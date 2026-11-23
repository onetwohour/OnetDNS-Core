//! Ad and tracker blocking engine. Lists are compiled into domain sets, and each query is judged
//! against them in a fixed priority order. Engines are swapped atomically, so the query path takes
//! no locks.
//!
//! Loading may be slow but verdicts must be fast, so loading freezes the sets into their compact
//! form.

mod cache;
mod compact;
mod table;

pub mod engine;
pub mod loader;
pub mod presets;
pub mod regex;
pub mod safesearch;
pub mod services;

pub use cache::{
    decode_engine_cache, decode_parsed_list, encode_engine_cache, write_engine_cache,
    write_parsed_list, CacheError, CacheWriteError, MAX_CACHE_BYTES,
};
pub use engine::{
    normalize_name, normalize_str, BlockEngine, ClientPolicy, DomainSet, EngineParts,
    FilterLoadReport, LocalZoneAction, LocalZoneSet, RewriteSet, RpzIpRule, RpzNameRule,
    SharedFilter, SourceStat, StaticAnswer, StaticZone,
};
pub use loader::{
    build_from_named, build_from_str, load_lists, load_lists_with, load_parts,
    load_parts_with_store, load_parts_with_subscriptions, parse_rpz_text, validate_rule,
    ParsedList, ParsedListStore, SubscriptionRules, SubscriptionSource,
};
