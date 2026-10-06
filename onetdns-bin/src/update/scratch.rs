/*!
 * @brief 업데이트 테스트가 쓰는 임시 설치 디렉터리.
 */

use std::path::PathBuf;

use super::install::Install;

/** @brief 테스트마다 따로 쓰는 임시 디렉터리. 테스트가 어디서 끝나도 지운다. */
pub(super) struct Scratch(pub(super) PathBuf);

impl Scratch {
    /** @brief 새 디렉터리를 만든다. */
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

    /** @brief 이 디렉터리에 둔 설치 경로. 파일은 만들지 않는다. */
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
