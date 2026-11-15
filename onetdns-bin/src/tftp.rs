//! TFTP for PXE boot. Only Unix has a real implementation; other platforms get a stub that does
//! nothing.

#[cfg(unix)]
mod imp;
#[cfg(unix)]
pub use imp::spawn_tftp;

#[cfg(not(unix))]
mod stub;
#[cfg(not(unix))]
pub use stub::spawn_tftp;
