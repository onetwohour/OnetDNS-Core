//! Keeps the service catalog current from the public repository, so service rules change without a
//! release. A fetched catalog is saved in the blocklist cache and read again at startup.

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use onetdns_filter::services::{self, Catalog, MAX_CATALOG_BYTES};

use crate::http::{self, HostResolver};

const CATALOG_URL: &str =
    "https://raw.githubusercontent.com/onetwohour/OnetDNS-Core/main/crates/onetdns-filter/services.json";
const CACHE_FILE: &str = "services.json";
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
pub(crate) const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);
pub(crate) const TICK_SECS: u64 = 60;

/// Adopts the saved catalog when it is newer than the built-in one.
pub(crate) fn load_cache(cache_dir: Option<&Path>) {
    let Some(path) = cache_dir.map(|dir| dir.join(CACHE_FILE)) else {
        return;
    };
    let text = match std::fs::metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Ok(meta) if meta.len() > MAX_CATALOG_BYTES as u64 => {
            Err("the file is larger than a catalog can be".to_string())
        }
        _ => std::fs::read_to_string(&path).map_err(|error| error.to_string()),
    };
    if let Err(error) = text
        .and_then(|text| Catalog::parse(&text))
        .and_then(services::adopt)
    {
        onetdns_core::warn!(
            event = "filter.services_cache_invalid",
            path = %path.display(),
            %error,
            "Ignoring the saved service catalog"
        );
    }
}

/// Ok(true) when a newer catalog replaced the current one, so the filter needs a rebuild.
pub(crate) fn refresh(
    resolver: &HostResolver,
    cache_dir: Option<&Path>,
    stop: &Arc<AtomicBool>,
) -> Result<bool, String> {
    let response = http::get(CATALOG_URL)
        .timeout(FETCH_TIMEOUT)
        .max_response(2 * MAX_CATALOG_BYTES as u64)
        .resolver(resolver.clone())
        .deny_private_targets()
        .stop_on(stop.clone())
        .call()
        .map_err(|error| format!("Could not download the service catalog: {error}"))?;
    if response.status != 200 {
        return Err(format!(
            "The service catalog download answered with HTTP status {}",
            response.status
        ));
    }
    let text = String::from_utf8(response.body)
        .map_err(|_| "The service catalog is not UTF-8 text".to_string())?;
    let catalog = Catalog::parse(&text)?;
    let revision = catalog.revision;
    if !services::adopt(catalog)? {
        return Ok(false);
    }
    if let Some(dir) = cache_dir {
        if let Err(error) = std::fs::create_dir_all(dir)
            .and_then(|()| crate::atomic_file::atomic_write(&dir.join(CACHE_FILE), text.as_bytes()))
        {
            onetdns_core::warn!(
                event = "filter.services_cache_failed",
                %error,
                "Could not save the service catalog; the built-in one is used after a restart"
            );
        }
    }
    onetdns_core::info!(
        event = "filter.services_updated",
        revision,
        "Updated the service catalog"
    );
    Ok(true)
}
