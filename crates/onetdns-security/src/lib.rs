//! Admission control: ACL, rate limiting and DNS Cookies, all decided before resolution starts. A
//! refusal must not reach upstream or touch the cache, or refusing would itself become a way to
//! consume resources.

pub mod acl;
pub mod bucket;
pub mod cookie;
pub mod rate;
pub mod siphash;
pub mod subnet;

pub use acl::IpAcl;
pub use cookie::{CookieCheck, CookieKeeper};
pub use rate::KeyedRateLimiter;
pub use subnet::SubnetRateLimiter;
