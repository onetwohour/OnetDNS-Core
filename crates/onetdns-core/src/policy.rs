//! Trait boundary between the data plane and policy implementations. The server knows only these
//! traits, not which filter, ACL, or rate limiter is plugged in, so replacing a policy
//! implementation does not change the query path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use onetdns_proto::{Name, RData, RecordType};

use crate::client::ClientInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    Allow,
    /// Rejects and sends a refusal.
    Deny,
    /// Rejects without any response, carrying the rule that dropped it.
    Drop(DropReason),
}

/// A drop tells the client nothing, so logs are all the operator sees. Unlisted drops take in the
/// internet's scanning traffic and would bury drop-list entries, so they are counted apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    DropList,
    /// Matched no rule, and such clients are configured to be dropped.
    Unlisted,
}

pub trait AccessControl: Send + Sync {
    /// Called per query; holding a lock long here throttles everything.
    fn check(&self, client: &ClientInfo) -> AclDecision;

    /// Whether this address is dropped without a response, and why. It depends only on the address,
    /// so transports can apply it before reading a query or completing a handshake. When it returns
    /// a reason, check must return Drop with that reason for any client ID from the address.
    fn drops(&self, ip: IpAddr) -> Option<DropReason>;

    /// True only when there are no rules; the wire fast path then skips the check. Returning true
    /// with any rule bypasses the ACL.
    fn is_trivially_allow(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    Permit,
    Throttle,
}

pub trait RateLimiter: Send + Sync {
    /// Also updates the counters.
    fn check(&self, client: &ClientInfo) -> RateDecision;

    /// Rate 0 is inactive. Config validation reads this too: Public mode requires an active
    /// limiter, since an open resolver without one is an amplification platform.
    fn is_active(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockResponse {
    /// Default; clients give up fastest.
    #[default]
    NxDomain,

    ZeroIp,
    /// Makes the block most visible.
    Refused,

    /// The name exists but has no record of that type.
    NoData,

    /// Operator-chosen addresses, for example a block page.
    Custom {
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum RewriteTarget {
    Records(Vec<RData>),

    /// Resolution continues normally from the target.
    Cname(Name),
}

impl RewriteTarget {
    /// A or AAAA by address family.
    pub fn ip(ip: std::net::IpAddr) -> Self {
        let rdata = match ip {
            std::net::IpAddr::V4(v4) => RData::A(v4),
            std::net::IpAddr::V6(v6) => RData::Aaaa(v6),
        };
        RewriteTarget::Records(vec![rdata])
    }
}

#[derive(Debug, Clone)]
pub enum FilterVerdict {
    /// The only verdict the wire fast path may store.
    Allow,
    Block(BlockResponse),

    Rewrite(RewriteTarget),

    /// No answer at all; only from rules where the operator chose NORESPONSE. Not a BlockResponse:
    /// there it could be picked as the default block response, and every place that builds a block
    /// response would have to handle one it cannot build.
    Drop,
}

/// Stage that decided the verdict. Declaration order is priority: the first stage to match wins.
/// Per-client policy beats global rules, important beats ordinary, and allow beats block within a
/// layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchStage {
    /// Filtering is turned off for this client.
    ClientPolicyDisable,

    ClientPolicyAllow,
    ClientPolicyBlock,

    RpzClientIp,

    ClientRuleAllow,
    ClientRuleBlock,

    /// Overrides ordinary blocks.
    ImportantAllow,

    /// Among global rules, only ImportantAllow beats it.
    NoResponse,

    /// Overrides ordinary allows.
    ImportantBlock,

    Refuse,

    NoData,

    Rewrite,

    Allow,
    RegexAllow,

    Block,
    RegexBlock,
    /// Blocks only specific record types.
    TypedBlock,

    DefaultAllow,
}

impl MatchStage {
    /// Stable; the dashboard reads it as is.
    pub fn as_str(self) -> &'static str {
        match self {
            MatchStage::ClientPolicyDisable => "client-policy:disable-filtering",
            MatchStage::ClientPolicyAllow => "client-policy:allow",
            MatchStage::ClientPolicyBlock => "client-policy:block",
            MatchStage::RpzClientIp => "rpz-client-ip",
            MatchStage::ClientRuleAllow => "client-rule:allow",
            MatchStage::ClientRuleBlock => "client-rule:block",
            MatchStage::ImportantAllow => "important:allow",
            MatchStage::NoResponse => "noresponse",
            MatchStage::ImportantBlock => "important:block",
            MatchStage::Refuse => "refuse",
            MatchStage::NoData => "nodata",
            MatchStage::Rewrite => "rewrite",
            MatchStage::Allow => "allow",
            MatchStage::RegexAllow => "regex:allow",
            MatchStage::Block => "block",
            MatchStage::RegexBlock => "regex:block",
            MatchStage::TypedBlock => "typed-block",
            MatchStage::DefaultAllow => "default-allow",
        }
    }
}

/// Verdict and its reason, for the query log and check diagnostics.
#[derive(Debug, Clone)]
pub struct FilterExplanation {
    pub verdict: FilterVerdict,
    pub stage: MatchStage,

    /// The rule text that matched, to trace which line of which list fired.
    pub matched: Option<String>,
    /// Name of the list holding the matched rule: a path for file lists, a URL for subscriptions.
    /// None for rules entered directly.
    pub source: Option<String>,
}

pub trait FilterEngine: Send + Sync {
    /// Called per query; implementations must not allocate.
    fn verdict(&self, name: &Name, qtype: RecordType, client: &ClientInfo) -> FilterVerdict;

    /// The default reconstructs from the verdict alone and cannot know the exact stage; engines
    /// that need precise diagnostics must override it.
    fn explain(&self, name: &Name, qtype: RecordType, client: &ClientInfo) -> FilterExplanation {
        let verdict = self.verdict(name, qtype, client);
        let stage = match &verdict {
            FilterVerdict::Allow => MatchStage::DefaultAllow,
            FilterVerdict::Block(_) => MatchStage::Block,
            FilterVerdict::Rewrite(_) => MatchStage::Rewrite,
            FilterVerdict::Drop => MatchStage::NoResponse,
        };
        FilterExplanation {
            verdict,
            stage,
            matched: None,
            source: None,
        }
    }
}
