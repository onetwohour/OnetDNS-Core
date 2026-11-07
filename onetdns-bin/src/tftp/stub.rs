//! TFTP for platforms without safe file access relative to a directory handle.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use onetdns_core::IpNet;

pub fn spawn_tftp(
    root: PathBuf,
    listen: SocketAddr,
    read_allow: Vec<IpNet>,
    writable: bool,
    write_allow: Vec<IpNet>,
    allow_overwrite: bool,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let _ = (
        root,
        listen,
        read_allow,
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
