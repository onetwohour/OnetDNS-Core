//! Temporary install directories for update tests.

use std::path::PathBuf;

use super::install::Install;

/// Removed however the test ends.
pub(super) struct Scratch(pub(super) PathBuf);

impl Scratch {
    pub(super) fn new(label: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("시계")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "onetdns-update-{label}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("임시 디렉터리");
        Self(dir)
    }

    /// No files are created.
    pub(super) fn install(&self) -> Install {
        let name = if cfg!(windows) {
            "OnetDNS.exe"
        } else {
            "OnetDNS"
        };
        Install::at(self.0.join(name)).expect("설치 경로")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
