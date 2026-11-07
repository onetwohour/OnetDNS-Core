//! Creates files whose access is settled at creation: private files for secrets, query logs and
//! dnstap output, and replacements that keep the ACL of the file they replace.
//!
//! On Windows the ACL goes into the `CreateFileW` call itself. A file restricted after it is
//! created can be opened by another account in between, and that handle keeps reading whatever
//! is written later.

use std::fs::File;
use std::io;
use std::path::Path;

/// How [`open_private`] opens a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateOpen {
    /// Create a file that must not exist yet, for writing.
    CreateNew,
    /// Append, creating the file when it is missing. An existing file keeps its access rules.
    Append,
}

/// Opens a file that only its owner can read if this call creates it.
///
/// Unix uses mode 0600 and does not follow a symlink. Windows gives the file a protected ACL
/// for the owner, SYSTEM and Administrators.
pub fn open_private(path: &Path, how: PrivateOpen) -> io::Result<File> {
    #[cfg(windows)]
    {
        windows::create(path, how, Some(&windows::Descriptor::owner_only()?))
    }
    #[cfg(not(windows))]
    {
        let mut options = std::fs::OpenOptions::new();
        match how {
            PrivateOpen::CreateNew => options.write(true).create_new(true),
            PrivateOpen::Append => options.append(true).create(true),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        options.open(path)
    }
}

/// Creates `path` for writing with the ACL of `template`, so that renaming it over `template`
/// keeps who can read the file. Without this the replacement gets the folder's inherited ACL.
/// When `template` does not exist the new file inherits from the folder as usual.
#[cfg(windows)]
pub fn create_new_like(path: &Path, template: &Path) -> io::Result<File> {
    let descriptor = windows::Descriptor::of_file(template)?;
    let file = windows::create(path, PrivateOpen::CreateNew, descriptor.as_ref())?;
    // Creation drops the auto-inherited flag that later folder ACL changes rely on.
    if let Some(descriptor) = descriptor.as_ref().filter(|d| !d.is_protected()) {
        descriptor.apply_inheriting(path)?;
    }
    Ok(file)
}

/// Replaces the ACL of an existing file with the owner, SYSTEM and Administrators only.
#[cfg(windows)]
pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
    windows::Descriptor::owner_only()?.apply(path)
}

/// The file's ACL in SDDL. Tests use it to check that a file stayed private.
#[cfg(windows)]
pub fn access_rules(path: &Path) -> io::Result<String> {
    windows::Descriptor::of_file(path)?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
        .to_sddl()
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use super::PrivateOpen;

    /// Owner, SYSTEM and Administrators, with nothing inherited from the folder.
    const OWNER_ONLY: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x2000_0000;
    const SE_DACL_PROTECTED: u16 = 0x1000;
    const SE_FILE_OBJECT: u32 = 1;
    const SDDL_REVISION_1: u32 = 1;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    // FILE_GENERIC_WRITE without FILE_WRITE_DATA, so every write lands at the end.
    const FILE_APPEND_ONLY: u32 = 0x0012_0114;
    const FILE_SHARE_READ_WRITE_DELETE: u32 = 0x0000_0007;
    const CREATE_NEW: u32 = 1;
    const OPEN_ALWAYS: u32 = 4;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_INSUFFICIENT_BUFFER: i32 = 122;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        descriptor: *mut c_void,
        inherit_handle: i32,
    }

    #[link(name = "Advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor: *mut c_void,
            revision: u32,
            information: u32,
            sddl: *mut *mut u16,
            length: *mut u32,
        ) -> i32;
        fn GetFileSecurityW(
            file_name: *const u16,
            information: u32,
            descriptor: *mut c_void,
            length: u32,
            needed: *mut u32,
        ) -> i32;
        fn SetFileSecurityW(
            file_name: *const u16,
            information: u32,
            descriptor: *mut c_void,
        ) -> i32;
        fn GetSecurityDescriptorControl(
            descriptor: *mut c_void,
            control: *mut u16,
            revision: *mut u32,
        ) -> i32;
        fn GetSecurityDescriptorDacl(
            descriptor: *mut c_void,
            present: *mut i32,
            dacl: *mut *mut c_void,
            defaulted: *mut i32,
        ) -> i32;
        fn SetNamedSecurityInfoW(
            object_name: *const u16,
            object_type: u32,
            information: u32,
            owner: *mut c_void,
            group: *mut c_void,
            dacl: *mut c_void,
            sacl: *mut c_void,
        ) -> u32;
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            access: u32,
            share: u32,
            security: *const SecurityAttributes,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(once(0)).collect()
    }

    /// A self-relative security descriptor holding a DACL.
    pub(super) enum Descriptor {
        /// From `ConvertStringSecurityDescriptorToSecurityDescriptorW`; freed with `LocalFree`.
        Local(*mut c_void),
        /// From `GetFileSecurityW`. `u64` words keep the pointer alignment it needs.
        Owned(Vec<u64>),
    }

    impl Drop for Descriptor {
        fn drop(&mut self) {
            if let Descriptor::Local(memory) = *self {
                // SAFETY: the conversion call allocated this with LocalAlloc and nothing else frees it.
                unsafe { LocalFree(memory) };
            }
        }
    }

    impl Descriptor {
        pub(super) fn owner_only() -> io::Result<Self> {
            let sddl: Vec<u16> = OWNER_ONLY.encode_utf16().chain(once(0)).collect();
            let mut memory = null_mut();
            // SAFETY: `sddl` is NUL-terminated and `memory` receives a buffer that `Descriptor` frees.
            let converted = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut memory,
                    null_mut(),
                )
            };
            if converted == 0 || memory.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Descriptor::Local(memory))
        }

        /// The DACL of `path`, or `None` when the file does not exist.
        pub(super) fn of_file(path: &Path) -> io::Result<Option<Self>> {
            let name = wide(path);
            let mut needed = 0u32;
            // SAFETY: a zero-length request with a null buffer only reports the size needed.
            let sized = unsafe {
                GetFileSecurityW(
                    name.as_ptr(),
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    0,
                    &mut needed,
                )
            };
            if sized == 0 {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(ERROR_FILE_NOT_FOUND) => return Ok(None),
                    Some(ERROR_INSUFFICIENT_BUFFER) => {}
                    _ => return Err(error),
                }
            }
            let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
            // SAFETY: `buffer` holds at least `needed` writable bytes.
            let read = unsafe {
                GetFileSecurityW(
                    name.as_ptr(),
                    DACL_SECURITY_INFORMATION,
                    buffer.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            };
            if read == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Some(Descriptor::Owned(buffer)))
        }

        fn as_ptr(&self) -> *mut c_void {
            match self {
                Descriptor::Local(memory) => *memory,
                Descriptor::Owned(buffer) => buffer.as_ptr().cast_mut().cast(),
            }
        }

        pub(super) fn apply(&self, path: &Path) -> io::Result<()> {
            let name = wide(path);
            // SAFETY: `name` is NUL-terminated and the descriptor outlives the call, which only reads it.
            let applied = unsafe {
                SetFileSecurityW(name.as_ptr(), DACL_SECURITY_INFORMATION, self.as_ptr())
            };
            if applied == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub(super) fn is_protected(&self) -> bool {
            let mut control = 0u16;
            let mut revision = 0u32;
            // SAFETY: the descriptor is valid and both outputs are plain integers.
            let read =
                unsafe { GetSecurityDescriptorControl(self.as_ptr(), &mut control, &mut revision) };
            read != 0 && control & SE_DACL_PROTECTED != 0
        }

        /// Sets this DACL's explicit entries on `path` and inherits the rest from its folder.
        pub(super) fn apply_inheriting(&self, path: &Path) -> io::Result<()> {
            let mut present = 0i32;
            let mut dacl = null_mut();
            let mut defaulted = 0i32;
            // SAFETY: the descriptor is valid; `dacl` points into it and is used while it lives.
            let read = unsafe {
                GetSecurityDescriptorDacl(self.as_ptr(), &mut present, &mut dacl, &mut defaulted)
            };
            if read == 0 {
                return Err(io::Error::last_os_error());
            }
            if present == 0 {
                return Err(io::Error::other("The security descriptor has no DACL"));
            }
            let name = wide(path);
            // SAFETY: `name` is NUL-terminated and `dacl` stays valid for the call.
            let status = unsafe {
                SetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    dacl,
                    null_mut(),
                )
            };
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            Ok(())
        }

        pub(super) fn to_sddl(&self) -> io::Result<String> {
            let mut text = null_mut();
            let mut length = 0u32;
            // SAFETY: the descriptor is valid and `text` receives a LocalAlloc buffer freed below.
            let converted = unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    self.as_ptr(),
                    SDDL_REVISION_1,
                    DACL_SECURITY_INFORMATION,
                    &mut text,
                    &mut length,
                )
            };
            if converted == 0 || text.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the call wrote `length` UTF-16 units, counting the terminating NUL.
            let units = unsafe { std::slice::from_raw_parts(text, length as usize) };
            let sddl = String::from_utf16_lossy(units)
                .trim_end_matches('\0')
                .to_string();
            // SAFETY: `text` came from LocalAlloc in the conversion call.
            unsafe { LocalFree(text.cast()) };
            Ok(sddl)
        }
    }

    pub(super) fn create(
        path: &Path,
        how: PrivateOpen,
        descriptor: Option<&Descriptor>,
    ) -> io::Result<File> {
        let name = wide(path);
        let (access, disposition) = match how {
            PrivateOpen::CreateNew => (GENERIC_WRITE, CREATE_NEW),
            PrivateOpen::Append => (FILE_APPEND_ONLY, OPEN_ALWAYS),
        };
        let attributes = descriptor.map(|descriptor| SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor: descriptor.as_ptr(),
            inherit_handle: 0,
        });
        let security = attributes
            .as_ref()
            .map_or(null(), |attributes| attributes as *const SecurityAttributes);
        // SAFETY: `name` is NUL-terminated and `security`, when set, points at live attributes.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                FILE_SHARE_READ_WRITE_DELETE,
                security,
                disposition,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateFileW returned a valid handle that nothing else owns.
        Ok(unsafe { File::from_raw_handle(handle) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "onetdns-fs-{name}-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(crate::rng::random_array::<8>())
        ))
    }

    #[cfg(windows)]
    const OWNER_ONLY: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

    #[cfg(windows)]
    #[test]
    fn a_new_private_file_is_created_with_the_owner_only_acl() {
        for how in [PrivateOpen::CreateNew, PrivateOpen::Append] {
            let path = scratch("new");
            open_private(&path, how).unwrap().write_all(b"x").unwrap();
            assert_eq!(access_rules(&path).unwrap(), OWNER_ONLY, "{how:?}");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn appending_keeps_the_acl_of_an_existing_file() {
        let path = scratch("append");
        std::fs::write(&path, b"a").unwrap();
        let inherited = access_rules(&path).unwrap();
        assert_ne!(inherited, OWNER_ONLY);
        open_private(&path, PrivateOpen::Append)
            .unwrap()
            .write_all(b"b")
            .unwrap();
        assert_eq!(access_rules(&path).unwrap(), inherited);
        assert_eq!(std::fs::read(&path).unwrap(), b"ab");
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn a_replacement_starts_with_the_acl_of_the_file_it_replaces() {
        let private = scratch("private");
        std::fs::write(&private, b"secret").unwrap();
        restrict_to_owner(&private).unwrap();
        assert_eq!(access_rules(&private).unwrap(), OWNER_ONLY);

        let plain = scratch("plain");
        std::fs::write(&plain, b"public").unwrap();

        for template in [&private, &plain] {
            let replacement = scratch("replacement");
            drop(create_new_like(&replacement, template).unwrap());
            assert_eq!(
                access_rules(&replacement).unwrap(),
                access_rules(template).unwrap()
            );
            std::fs::remove_file(replacement).unwrap();
        }

        let missing = scratch("missing");
        let replacement = scratch("replacement");
        drop(create_new_like(&replacement, &missing).unwrap());
        assert_eq!(
            access_rules(&replacement).unwrap(),
            access_rules(&plain).unwrap()
        );
        for path in [private, plain, replacement] {
            std::fs::remove_file(path).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_new_private_file_is_mode_0600_and_appending_keeps_an_existing_mode() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;

        let path = scratch("new");
        drop(open_private(&path, PrivateOpen::CreateNew).unwrap());
        assert_eq!(mode(&path), 0o600);
        std::fs::remove_file(&path).unwrap();

        drop(open_private(&path, PrivateOpen::Append).unwrap());
        assert_eq!(mode(&path), 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        open_private(&path, PrivateOpen::Append)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert_eq!(mode(&path), 0o640);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn creating_a_private_file_refuses_an_existing_path() {
        let path = scratch("exists");
        std::fs::write(&path, b"keep").unwrap();
        let error = open_private(&path, PrivateOpen::CreateNew).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        std::fs::remove_file(path).unwrap();
    }
}
