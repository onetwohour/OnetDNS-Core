/*!
 * @brief 파일 전송을 지원하지 않는 플랫폼용 대체 구현.
 */

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use onetdns_core::IpNet;

/** @brief 아무것도 하지 않는다. 이 플랫폼에는 파일 전송이 없다. */
pub fn spawn_tftp(
    root: PathBuf,
    listen: SocketAddr,
    writable: bool,
    write_allow: Vec<IpNet>,
    allow_overwrite: bool,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let _ = (
        root,
        listen,
        writable,
        write_allow,
        allow_overwrite,
        shutdown,
    );
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "The TFTP server cannot start because this operating system does not support safe TFTP file access",
    ))
}
