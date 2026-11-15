use std::net::IpAddr;

use crate::{Action, PolicyInput};

/// Weekday and time-of-day window in local time. start_min > end_min means the window crosses
/// midnight.
#[derive(Debug, Clone, Copy)]
pub struct TimeWindow {
    /// Weekday bitmask, bit 0 is Sunday; 0 means every day.
    pub days: u8,
    /// Minutes since midnight.
    pub start_min: u16,
    /// Minutes since midnight.
    pub end_min: u16,
}

impl TimeWindow {
    /// In a window that crosses midnight, the part after midnight counts as the previous weekday;
    /// otherwise a Friday 22:00 to 02:00 window misses early Saturday. `minute_of_week` counts from
    /// Sunday 00:00, local time.
    fn contains(&self, minute_of_week: u32) -> bool {
        let weekday = ((minute_of_week / 1_440) % 7) as u8;
        let minute = (minute_of_week % 1_440) as u16;
        if self.start_min < self.end_min {
            (self.days == 0 || (self.days & (1 << weekday)) != 0)
                && minute >= self.start_min
                && minute < self.end_min
        } else {
            let previous_weekday = (weekday + 6) % 7;
            (minute >= self.start_min && (self.days == 0 || (self.days & (1 << weekday)) != 0))
                || (minute < self.end_min
                    && (self.days == 0 || (self.days & (1 << previous_weekday)) != 0))
        }
    }
}

/// Without a prefix it is a host route.
#[derive(Debug, Clone, Copy)]
struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// A prefix longer than the family allows is refused.
    fn parse(s: &str) -> Option<Cidr> {
        let (ip_s, pfx) = match s.split_once('/') {
            Some((a, b)) => (a, b.parse::<u8>().ok()?),
            None => (s, u8::MAX),
        };
        let base: IpAddr = ip_s.trim().parse().ok()?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let prefix = if pfx == u8::MAX { max } else { pfx };
        if prefix > max {
            return None;
        }
        Some(Cidr { base, prefix })
    }

    /// Always false across address families.
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(b), IpAddr::V4(x)) => mask_match(&b.octets(), &x.octets(), self.prefix),
            (IpAddr::V6(b), IpAddr::V6(x)) => mask_match(&b.octets(), &x.octets(), self.prefix),
            _ => false,
        }
    }
}

/// Whether the first `prefix` bits are equal.
fn mask_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// Matches only at label boundaries; a plain ends_with would make evil-example.com match a rule for
/// example.com.
fn suffix_match(qname: &str, suffix: &str) -> bool {
    let s = suffix.trim_matches('.');
    if s.is_empty() {
        return true;
    }
    qname == s
        || (qname.len() > s.len()
            && qname.ends_with(s)
            && qname.as_bytes()[qname.len() - s.len() - 1] == b'.')
}

/// All conditions must hold; within one condition, any value may match. An empty condition matches
/// anything.
#[derive(Debug, Clone)]
pub struct Rule {
    clients: Vec<Cidr>,
    suffixes: Vec<String>,
    qtypes: Vec<u16>,
    window: Option<TimeWindow>,
    action: Action,
}

impl Rule {
    /// A rule with no conditions, which matches every query.
    pub fn new(action: Action) -> Self {
        Rule {
            clients: vec![],
            suffixes: vec![],
            qtypes: vec![],
            window: None,
            action,
        }
    }
    /// Entries that do not parse are dropped silently, so a typo in one rule cannot stop the server
    /// from starting; config validation checks the format separately.
    pub fn with_clients(mut self, cidrs: &[String]) -> Self {
        self.clients = cidrs.iter().filter_map(|c| Cidr::parse(c)).collect();
        self
    }
    /// Stored lowercased.
    pub fn with_suffixes(mut self, suffixes: &[String]) -> Self {
        self.suffixes = suffixes
            .iter()
            .map(|s| s.trim().trim_matches('.').to_ascii_lowercase())
            .collect();
        self
    }
    pub fn with_qtypes(mut self, qtypes: &[u16]) -> Self {
        self.qtypes = qtypes.to_vec();
        self
    }
    pub fn with_window(mut self, w: TimeWindow) -> Self {
        self.window = Some(w);
        self
    }

    fn matches(&self, input: &PolicyInput) -> bool {
        if !self.clients.is_empty() && !self.clients.iter().any(|c| c.contains(input.client)) {
            return false;
        }
        if !self.suffixes.is_empty() && !self.suffixes.iter().any(|s| suffix_match(input.qname, s))
        {
            return false;
        }
        if !self.qtypes.is_empty() && !self.qtypes.contains(&input.qtype) {
            return false;
        }
        if let Some(w) = &self.window {
            if !w.contains(input.local_minute_of_week) {
                return false;
            }
        }
        true
    }
}

/// Rules in config order, which is their priority; the first match wins.
#[derive(Default)]
pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        RuleEngine { rules }
    }
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
    /// The first matching rule's action, or Continue if none matches.
    pub fn evaluate(&self, input: &PolicyInput) -> Action {
        for r in &self.rules {
            if r.matches(input) {
                return r.action;
            }
        }
        Action::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// `t` is minutes since Sunday 00:00.
    fn input<'a>(client: &str, qname: &'a str, qtype: u16, t: u32) -> PolicyInput<'a> {
        PolicyInput {
            client: client.parse().unwrap(),
            qname,
            qtype,
            unix_time: 0,
            local_minute_of_week: t,
            transport: crate::QueryTransport::Do53Udp,
            client_id: None,
            authenticated: false,
        }
    }

    #[test]
    fn cidr_match_v4() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains("192.168.1.50".parse().unwrap()));
        assert!(!c.contains("192.168.2.50".parse().unwrap()));
        let host = Cidr::parse("10.0.0.5").unwrap();
        assert!(host.contains("10.0.0.5".parse().unwrap()));
        assert!(!host.contains("10.0.0.6".parse().unwrap()));
    }

    #[test]
    fn suffix_is_label_bounded() {
        assert!(suffix_match("ads.example.com", "example.com"));
        assert!(suffix_match("example.com", "example.com"));
        assert!(!suffix_match("notexample.com", "example.com"));
        assert!(!suffix_match("example.com.evil.com", "example.com"));
    }

    #[test]
    fn rule_combines_client_and_suffix() {
        let r = Rule::new(Action::Block)
            .with_clients(&["192.168.1.0/24".into()])
            .with_suffixes(&["social.example".into()]);
        let eng = RuleEngine::new(vec![r]);

        assert_eq!(
            eng.evaluate(&input("192.168.1.10", "x.social.example", 1, 0)),
            Action::Block
        );

        assert_eq!(
            eng.evaluate(&input("10.0.0.1", "x.social.example", 1, 0)),
            Action::Continue
        );

        assert_eq!(
            eng.evaluate(&input("192.168.1.10", "work.example", 1, 0)),
            Action::Continue
        );
    }

    #[test]
    fn first_match_wins() {
        let allow = Rule::new(Action::Allow).with_suffixes(&["good.example".into()]);
        let block = Rule::new(Action::Block).with_suffixes(&["example".into()]);
        let eng = RuleEngine::new(vec![allow, block]);

        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "good.example", 1, 0)),
            Action::Allow
        );

        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "bad.example", 1, 0)),
            Action::Block
        );
    }

    #[test]
    fn qtype_filter() {
        let r = Rule::new(Action::Refuse).with_qtypes(&[28]);
        let eng = RuleEngine::new(vec![r]);
        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "a.com", 28, 0)),
            Action::Refuse
        );
        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "a.com", 1, 0)),
            Action::Continue
        );
    }

    #[test]
    fn time_window_weekday_and_minute() {
        let wed_midnight = 3 * 1_440u32;

        let w = TimeWindow {
            days: 1 << 3,
            start_min: 0,
            end_min: 60,
        };
        assert!(w.contains(wed_midnight));

        assert!(!w.contains(wed_midnight + 120));

        assert!(!w.contains(wed_midnight + 1_440));
        let r = Rule::new(Action::Block).with_window(w);
        let eng = RuleEngine::new(vec![r]);
        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "x", 1, wed_midnight)),
            Action::Block
        );
        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "x", 1, wed_midnight + 120)),
            Action::Continue
        );
    }

    #[test]
    fn time_window_across_midnight_uses_previous_weekday() {
        let w = TimeWindow {
            days: 1 << 5,
            start_min: 22 * 60,
            end_min: 2 * 60,
        };

        assert!(w.contains(5 * 1_440 + 23 * 60));

        assert!(w.contains(6 * 1_440 + 60));

        assert!(!w.contains(5 * 1_440 + 60));

        assert!(!w.contains(6 * 1_440 + 23 * 60));
    }

    #[test]
    fn rewrite_action_carries_ip() {
        let r = Rule::new(Action::Rewrite(Ipv4Addr::new(10, 0, 0, 1)))
            .with_suffixes(&["router.lan".into()]);
        let eng = RuleEngine::new(vec![r]);
        assert_eq!(
            eng.evaluate(&input("1.1.1.1", "router.lan", 1, 0)),
            Action::Rewrite(Ipv4Addr::new(10, 0, 0, 1))
        );
    }
}
