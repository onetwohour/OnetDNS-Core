use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;

/// Concurrent connections per client, limited per address and per IPv6 /64. One IPv6 host usually
/// holds a whole /64, so with only a per-address limit it could take every slot by changing
/// addresses. A /64 is held to half the capacity rather than to the per-address limit, since the
/// hosts of one LAN share a /64. An IPv4-mapped address counts as its IPv4 address.
pub struct ClientCounts {
    per_address: usize,
    per_prefix: usize,
    addresses: HashMap<IpAddr, usize>,
    prefixes: HashMap<u64, usize>,
}

impl ClientCounts {
    /// `capacity` is the total number of connections the owner admits.
    pub fn new(per_address: usize, capacity: usize) -> Self {
        Self {
            per_address,
            per_prefix: (capacity / 2).max(per_address),
            addresses: HashMap::new(),
            prefixes: HashMap::new(),
        }
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        self.addresses.get(&ip).copied().unwrap_or(0) < self.per_address
            && prefix64(ip).is_none_or(|prefix| {
                self.prefixes.get(&prefix).copied().unwrap_or(0) < self.per_prefix
            })
    }

    pub fn add(&mut self, ip: IpAddr) {
        let ip = canonical(ip);
        *self.addresses.entry(ip).or_default() += 1;
        if let Some(prefix) = prefix64(ip) {
            *self.prefixes.entry(prefix).or_default() += 1;
        }
    }

    /// Drops entries that reach 0, so the maps hold only clients with open connections.
    pub fn remove(&mut self, ip: IpAddr) {
        let ip = canonical(ip);
        decrement(&mut self.addresses, ip);
        if let Some(prefix) = prefix64(ip) {
            decrement(&mut self.prefixes, prefix);
        }
    }

    pub fn clear(&mut self) {
        self.addresses.clear();
        self.prefixes.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    pub fn shrink(&mut self) {
        shrink_if_sparse(&mut self.addresses);
        shrink_if_sparse(&mut self.prefixes);
    }
}

/// Returns bucket memory after a peak, shrinking only when sparse so it does not churn.
pub fn shrink_if_sparse<K: Eq + Hash, V>(map: &mut HashMap<K, V>) {
    if map.is_empty() {
        map.shrink_to_fit();
        return;
    }
    let target = map.len().saturating_mul(2).saturating_add(1);
    if map.capacity() > target.saturating_mul(2) {
        map.shrink_to(target);
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn prefix64(ip: IpAddr) -> Option<u64> {
    match ip {
        IpAddr::V6(v6) => Some((u128::from(v6) >> 64) as u64),
        IpAddr::V4(_) => None,
    }
}

fn decrement<K: Eq + Hash>(map: &mut HashMap<K, usize>, key: K) {
    if let Some(count) = map.get_mut(&key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            map.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn one_ipv6_prefix_cannot_take_more_than_half_by_changing_addresses() {
        let mut counts = ClientCounts::new(2, 8);
        for host in 1..=4 {
            let address = ip(&format!("2001:db8::{host}"));
            assert!(counts.allows(address));
            counts.add(address);
        }
        assert!(
            !counts.allows(ip("2001:db8::ffff:5")),
            "같은 /64 의 다른 주소로 절반을 넘겨 받으면 안 됩니다"
        );
        assert!(counts.allows(ip("2001:db8:0:1::1")));

        counts.remove(ip("2001:db8::4"));
        assert!(counts.allows(ip("2001:db8::ffff:5")));
    }

    #[test]
    fn each_address_keeps_its_own_limit() {
        let mut counts = ClientCounts::new(2, 8);
        counts.add(ip("2001:db8::1"));
        counts.add(ip("2001:db8::1"));
        assert!(!counts.allows(ip("2001:db8::1")));
        assert!(counts.allows(ip("2001:db8::2")), "같은 LAN 의 다른 호스트");

        counts.add(ip("192.0.2.1"));
        counts.add(ip("::ffff:192.0.2.1"));
        assert!(
            !counts.allows(ip("192.0.2.1")),
            "IPv4 사상 표기로 몫을 하나 더 얻으면 안 됩니다"
        );
    }

    #[test]
    fn removing_the_last_connection_forgets_the_client() {
        let mut counts = ClientCounts::new(2, 8);
        counts.add(ip("2001:db8::1"));
        counts.add(ip("192.0.2.1"));
        counts.remove(ip("2001:db8::1"));
        counts.remove(ip("192.0.2.1"));
        assert!(counts.is_empty() && counts.prefixes.is_empty());
    }

    #[test]
    fn sparse_maps_release_reserved_buckets() {
        let mut map = HashMap::new();
        for key in 0..1024 {
            map.insert(key, key);
        }
        let high_water = map.capacity();
        map.retain(|key, _| *key == 0);
        shrink_if_sparse(&mut map);
        assert_eq!(map.get(&0), Some(&0));
        assert!(map.capacity() < high_water);

        map.clear();
        shrink_if_sparse(&mut map);
        assert_eq!(map.capacity(), 0);
    }
}
