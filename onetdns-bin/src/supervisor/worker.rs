//! The worker's side: joins the supervisor that started it, and asks it for a successor after an
//! update is swapped in.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use onetdns_core::MutexExt;

use super::channel::{self, Reply, Start};
use super::{sys, Joined};
use crate::error::BoxResult;
use crate::handoff::{wire, Link, Links};

/// The predecessor introduces itself as soon as it gets the link.
const INTRODUCTION_WAIT: Duration = Duration::from_secs(30);

/// Kept for the successor requests of the worker side.
static LINKS: OnceLock<Arc<Links>> = OnceLock::new();
/// Set from a successor request until the supervisor says this process serves on.
static HANDING_OVER: AtomicBool = AtomicBool::new(false);

/// Introduces this process to the supervisor that started it. A successor also takes the link to
/// its predecessor into `links`. On Linux it blocks dumps and restores the process name, so call it
/// before starting threads.
pub fn join(links: &Arc<Links>) -> BoxResult<Joined> {
    if std::env::var_os(channel::CHANNEL_ENV).is_none() {
        return Ok(Joined::default());
    }
    sys::prepare_worker()?;
    let _ = LINKS.set(links.clone());
    let Some(start) = channel::join()? else {
        return Ok(Joined::default());
    };
    let console = match start {
        Start::Fresh => None,
        Start::Successor(stream) => {
            let key =
                wire::introduced(&stream, Instant::now() + INTRODUCTION_WAIT).map_err(|error| {
                    crate::anyhow!(format!(
                        "The running version did not introduce itself: {error}"
                    ))
                })?;
            onetdns_control::adopt_credential_key(&key).map_err(|error| crate::anyhow!(error))?;
            let released = sys::until_released(&stream)?;
            *links.predecessor.lock_recover() = Some(Link::over(stream));
            Some(released)
        }
    };
    Ok(Joined {
        ready: Some(Box::new(|| {
            if let Err(error) = channel::ready() {
                crate::tui::leave();
                onetdns_core::error!(event = "supervisor.ready_signal_failed", %error, "Could not send the service ready signal; aborting startup");
                std::process::exit(1);
            }
        })),
        console,
    })
}

pub(crate) enum Requested {
    /// The new version is on trial, and the link to it waits in `Links::successor`.
    Linked,
    /// The new version failed and was put back.
    Cancelled,
    /// It cannot take over beside this process.
    Unavailable(String),
}

/// Whether the supervisor would start a successor beside this process now, as far as memory goes.
pub(crate) fn successor_fits() -> bool {
    super::room_for_successor(sys::own_memory()).is_ok()
}

/// Asks the supervisor to start the installed version beside this process.
pub(crate) fn request_successor() -> Requested {
    HANDING_OVER.store(true, Ordering::Release);
    let stream = match channel::request_successor() {
        Ok(Reply::Link(stream)) => stream,
        Ok(Reply::Cancelled) => {
            HANDING_OVER.store(false, Ordering::Release);
            return Requested::Cancelled;
        }
        Ok(Reply::Fallback(reason)) | Err(reason) => {
            HANDING_OVER.store(false, Ordering::Release);
            return Requested::Unavailable(reason);
        }
    };
    if let Err(error) = wire::introduce(&stream, &onetdns_control::credential_key()) {
        onetdns_core::warn!(event = "handoff.introduce_failed", %error, "Could not introduce this process to the new version");
    }
    if let Some(links) = LINKS.get() {
        *links.successor.lock_recover() = Some(Link::over(stream));
    }
    Requested::Linked
}

/// After a handoff, whether this process ends. `handed` is how the handoff went here; the
/// supervisor's verdict decides.
pub fn settle(handed: bool, abort: &dyn Fn() -> bool) -> bool {
    let ends = channel::settle(handed, abort);
    if !ends {
        HANDING_OVER.store(false, Ordering::Release);
    }
    ends
}

/// While true, a successor may already have read the configuration.
pub fn handing_over() -> bool {
    HANDING_OVER.load(Ordering::Acquire)
}
