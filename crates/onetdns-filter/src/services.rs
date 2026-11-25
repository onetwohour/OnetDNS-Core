//! Blocking rules per service. Choosing one service blocks every domain it uses. The catalog built
//! into the binary is services.json; a newer revision fetched at run time replaces it.
//!
//! Every installed version reads the published file, so its format only grows: a field may be
//! added and is ignored by older versions, but no field changes meaning.

use std::sync::{Arc, Mutex, OnceLock};

use onetdns_core::json::{self, Json};
use onetdns_core::MutexExt;

pub const MAX_CATALOG_BYTES: usize = 1 << 20;

pub struct Service {
    /// The name written in config.
    pub id: String,
    pub name: String,
    pub group: String,
    /// Each one blocks the domain and its subdomains.
    pub domains: Vec<String>,
}

impl Service {
    pub fn rules(&self) -> impl Iterator<Item = String> + '_ {
        self.domains.iter().map(|domain| format!("||{domain}^"))
    }
}

pub struct Catalog {
    /// Raised on every change, so a newer copy replaces an older one.
    pub revision: u64,
    pub services: Vec<Service>,
}

impl Catalog {
    pub fn parse(text: &str) -> Result<Self, String> {
        let root = json::parse_with_limit(text, MAX_CATALOG_BYTES)
            .map_err(|error| format!("The service catalog is not valid JSON: {error}"))?;
        let revision = root
            .get("revision")
            .and_then(Json::as_u64)
            .filter(|revision| *revision > 0)
            .ok_or("The service catalog has no revision")?;
        let entries = root
            .get("services")
            .and_then(Json::as_array)
            .filter(|entries| !entries.is_empty())
            .ok_or("The service catalog lists no services")?;
        let mut services: Vec<Service> = Vec::with_capacity(entries.len());
        for entry in entries {
            let service = parse_service(entry)?;
            if services.iter().any(|seen| seen.id == service.id) {
                return Err(format!(
                    "The service catalog lists {} more than once",
                    service.id
                ));
            }
            services.push(service);
        }
        Ok(Self { revision, services })
    }

    pub fn get(&self, id: &str) -> Option<&Service> {
        self.services
            .iter()
            .find(|service| service.id.eq_ignore_ascii_case(id))
    }

    /// Whether `self` should replace `current`. Config may name any service, so a newer revision
    /// that drops one is an error rather than a replacement.
    pub fn replaces(&self, current: &Catalog) -> Result<bool, String> {
        if self.revision <= current.revision {
            return Ok(false);
        }
        match current
            .services
            .iter()
            .find(|service| self.get(&service.id).is_none())
        {
            Some(dropped) => Err(format!(
                "Service catalog revision {} drops the service {}",
                self.revision, dropped.id
            )),
            None => Ok(true),
        }
    }
}

fn parse_service(entry: &Json) -> Result<Service, String> {
    let text = |key: &str| entry.get(key).and_then(Json::as_str).unwrap_or_default();
    let id = text("id");
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(format!(
            "The service catalog has an invalid service id: {id:?}"
        ));
    }
    let name = text("name");
    let group = text("group");
    if name.is_empty() || name.len() > 100 {
        return Err(format!("The service {id} has no usable name"));
    }
    if group.is_empty() || !group.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
        return Err(format!("The service {id} has an invalid group: {group:?}"));
    }
    let domains = entry
        .get("domains")
        .and_then(Json::as_array)
        .filter(|domains| !domains.is_empty())
        .ok_or_else(|| format!("The service {id} lists no domains"))?
        .iter()
        .map(|domain| {
            domain
                .as_str()
                .filter(|domain| is_blockable_domain(domain))
                .map(str::to_string)
                .ok_or_else(|| format!("The service {id} has an invalid domain: {domain:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Service {
        id: id.to_string(),
        name: name.to_string(),
        group: group.to_string(),
        domains,
    })
}

/// Lowercase, with at least two labels, so a catalog cannot block a whole top-level domain.
fn is_blockable_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.split('.').count() >= 2
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn builtin() -> Arc<Catalog> {
    static BUILTIN: OnceLock<Arc<Catalog>> = OnceLock::new();
    BUILTIN
        .get_or_init(|| {
            Arc::new(
                Catalog::parse(include_str!("../services.json"))
                    .expect("the built-in service catalog is checked by a test"),
            )
        })
        .clone()
}

static ADOPTED: Mutex<Option<Arc<Catalog>>> = Mutex::new(None);

pub fn current() -> Arc<Catalog> {
    ADOPTED.lock_recover().clone().unwrap_or_else(builtin)
}

/// Makes `next` current when it replaces the current catalog. Ok(false) means it was not newer.
pub fn adopt(next: Catalog) -> Result<bool, String> {
    let mut adopted = ADOPTED.lock_recover();
    let now = adopted.clone().unwrap_or_else(builtin);
    if !next.replaces(&now)? {
        return Ok(false);
    }
    *adopted = Some(Arc::new(next));
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog(revision: u64, ids: &[&str]) -> Catalog {
        let services: Vec<String> = ids
            .iter()
            .map(|id| {
                format!("{{\"id\":\"{id}\",\"name\":\"{id}\",\"group\":\"other\",\"domains\":[\"{id}.example\"]}}")
            })
            .collect();
        Catalog::parse(&format!(
            "{{\"revision\":{revision},\"services\":[{}]}}",
            services.join(",")
        ))
        .expect("테스트 카탈로그")
    }

    #[test]
    fn builtin_catalog_is_valid() {
        let catalog = builtin();
        assert!(catalog.services.len() > 50);
        let youtube = catalog.get("YouTube").expect("대소문자를 가리지 않습니다");
        assert!(youtube.rules().any(|rule| rule == "||googlevideo.com^"));
    }

    #[test]
    fn catalogs_only_hold_blockable_domains() {
        let entry = |domains: &str| {
            Catalog::parse(&format!(
                "{{\"revision\":1,\"services\":[{{\"id\":\"x\",\"name\":\"X\",\"group\":\"other\",\"domains\":[{domains}]}}]}}"
            ))
        };
        assert!(entry("\"cdn.example.com\"").is_ok());
        for bad in [
            "\"com\"",
            "\"Example.com\"",
            "\"*.example.com\"",
            "\"-a.example\"",
            "\"a..example\"",
            "\"example.com^\"",
            "7",
            "",
        ] {
            assert!(entry(bad).is_err(), "{bad}");
        }
        let unknown_field = "{\"revision\":2,\"later\":true,\"services\":[{\"id\":\"x\",\"name\":\"X\",\"group\":\"other\",\"domains\":[\"x.example\"],\"later\":1}]}";
        assert!(
            Catalog::parse(unknown_field).is_ok(),
            "모르는 필드는 무시합니다"
        );
        for bad in [
            "{\"services\":[]}",
            "{\"revision\":0,\"services\":[]}",
            "{\"revision\":1,\"services\":[]}",
            "{\"revision\":1,\"services\":[{\"id\":\"Bad Id\",\"name\":\"X\",\"group\":\"other\",\"domains\":[\"x.example\"]}]}",
        ] {
            assert!(Catalog::parse(bad).is_err(), "{bad}");
        }
        assert!(Catalog::parse(&" ".repeat(MAX_CATALOG_BYTES + 1)).is_err());
    }

    #[test]
    fn only_a_newer_revision_that_keeps_every_service_replaces() {
        let current = catalog(3, &["a", "b"]);
        assert_eq!(catalog(4, &["a", "b", "c"]).replaces(&current), Ok(true));
        assert_eq!(catalog(3, &["a", "b", "c"]).replaces(&current), Ok(false));
        assert_eq!(catalog(2, &["a", "b", "c"]).replaces(&current), Ok(false));
        assert!(catalog(4, &["a"]).replaces(&current).is_err());
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let duplicate = "{\"revision\":1,\"services\":[{\"id\":\"a\",\"name\":\"A\",\"group\":\"other\",\"domains\":[\"a.example\"]},{\"id\":\"a\",\"name\":\"A\",\"group\":\"other\",\"domains\":[\"b.example\"]}]}";
        assert!(Catalog::parse(duplicate).is_err());
    }
}
