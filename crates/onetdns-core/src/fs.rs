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
/// for the owner, the running account, SYSTEM and Administrators.
pub fn open_private(path: &Path, how: PrivateOpen) -> io::Result<File> {
    #[cfg(windows)]
    {
        windows::create(path, how, Some(&windows::Descriptor::private(path, None)?))
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

/// Creates a private file to rename over `target`. On Windows, whoever could use `target` keeps
/// access even when another account writes the replacement.
pub fn create_private_replacing(path: &Path, target: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        let descriptor = windows::Descriptor::private(path, Some(target))?;
        windows::create(path, PrivateOpen::CreateNew, Some(&descriptor))
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        open_private(path, PrivateOpen::CreateNew)
    }
}

/// Creates `path` for writing with the ACL of `template`, so that renaming it over `template`
/// keeps who can read the file. Without this the replacement gets the folder's inherited ACL.
/// When `template` does not exist the new file inherits from the folder as usual.
#[cfg(windows)]
pub fn create_new_like(path: &Path, template: &Path) -> io::Result<File> {
    let descriptor = windows::Descriptor::of_file(template)?
        .map(|descriptor| descriptor.keeping_access(path, template))
        .transpose()?;
    let file = windows::create(path, PrivateOpen::CreateNew, descriptor.as_ref())?;
    // Creation drops the auto-inherited flag that later folder ACL changes rely on. A DACL
    // without the flag is already copied as is; re-inheriting would add the folder's entries a
    // second time.
    if let Some(descriptor) = descriptor.as_ref().filter(|d| d.inherits_automatically()) {
        descriptor.apply_inheriting(path)?;
    }
    Ok(file)
}

/// Replaces the ACL of an existing file with a private one.
#[cfg(windows)]
pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
    windows::Descriptor::private(path, Some(path))?.apply(path)
}

/// The file's ACL in SDDL. Tests use it to check that a file stayed private.
#[cfg(windows)]
pub fn access_rules(path: &Path) -> io::Result<String> {
    windows::Descriptor::of_file(path)?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
        .to_sddl()
}

/// The ACL [`open_private`] gives a new file at `path`, in SDDL, for tests to compare with.
#[cfg(windows)]
pub fn private_rules(path: &Path) -> io::Result<String> {
    windows::Descriptor::private(path, None)?.to_sddl()
}

#[cfg(windows)]
mod windows {
    use std::collections::BTreeSet;
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use super::PrivateOpen;

    /// `OW` is whoever owns the file, which changes with the account that writes it.
    const PRIVATE_RULES: &str = "(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;
    const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x2000_0000;
    const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
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
        fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
        fn GetTokenInformation(
            token: *mut c_void,
            class: u32,
            information: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
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

    fn allow_rule(account: &str) -> String {
        format!("(A;;FA;;;{account})")
    }

    fn private_sddl(accounts: &BTreeSet<String>) -> String {
        let listed: String = accounts.iter().map(|account| allow_rule(account)).collect();
        format!("D:P{listed}{PRIVATE_RULES}")
    }

    /// Accounts a private file names besides `OW`. The owner alone is not enough: what an elevated
    /// process or a service writes is owned by Administrators or SYSTEM, which locks out the user
    /// who runs OnetDNS without elevation. Only account SIDs count; SDDL aliases such as `BA` and
    /// `WD` are groups or already listed.
    fn kept_accounts(
        current: &str,
        folder_owner: Option<&str>,
        file_owner: Option<&str>,
        protected_rules: Option<&str>,
    ) -> BTreeSet<String> {
        // A service has no user of its own, so the folder's owner stands in.
        let stand_in = folder_owner.filter(|_| current == "SY");
        let listed = protected_rules
            .into_iter()
            .flat_map(|rules| rules.split('('))
            .filter_map(|rule| rule.split(')').next()?.strip_prefix("A;;FA;;;"));
        [Some(current), stand_in, file_owner]
            .into_iter()
            .flatten()
            .chain(listed)
            .filter(|account| account.starts_with("S-"))
            .map(str::to_string)
            .collect()
    }

    /// Reads what [`kept_accounts`] needs. Anything unreadable only leaves the ACL narrower.
    fn accounts_for(file: &Path, replaced: Option<&Path>) -> io::Result<BTreeSet<String>> {
        let current = current_user()?;
        let folder = file
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let rules = replaced
            .and_then(|path| Descriptor::of_file(path).ok().flatten())
            .filter(Descriptor::is_protected)
            .and_then(|descriptor| descriptor.to_sddl().ok());
        Ok(kept_accounts(
            &current,
            owner_of(folder).as_deref(),
            replaced.and_then(owner_of).as_deref(),
            rules.as_deref(),
        ))
    }

    fn owner_of(path: &Path) -> Option<String> {
        Descriptor::read(path, OWNER_SECURITY_INFORMATION)
            .ok()??
            .owner()
            .ok()
    }

    /// This process's account in SDDL form, so that well-known accounts come back as aliases.
    fn current_user() -> io::Result<String> {
        let mut token = null_mut();
        // SAFETY: the pseudo handle needs no closing and `token` receives a handle closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // Holds TOKEN_USER and the longest SID. `u64` words keep its pointer aligned.
        let mut buffer = [0u64; 16];
        let mut returned = 0u32;
        // SAFETY: `token` is open and `buffer` has the length passed.
        let read = unsafe {
            GetTokenInformation(
                token,
                TOKEN_USER_CLASS,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                &mut returned,
            )
        };
        let read_error = (read == 0).then(io::Error::last_os_error);
        // SAFETY: closes the handle opened above, once.
        unsafe { CloseHandle(token) };
        if let Some(error) = read_error {
            return Err(error);
        }
        // SAFETY: TOKEN_USER starts with a pointer to the SID, which lies inside `buffer`.
        let sid = unsafe { *buffer.as_ptr().cast::<*mut c_void>() };
        let mut text = null_mut();
        // SAFETY: `sid` is valid and `text` receives a LocalAlloc buffer freed below.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut length = 0;
        // SAFETY: the call wrote a NUL-terminated string.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: `length` units were just read from `text`.
        let raw = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
        // SAFETY: `text` came from LocalAlloc in the conversion call.
        unsafe { LocalFree(text.cast()) };
        Descriptor::from_sddl(&format!("O:{raw}"))?.owner()
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
        /// A private ACL for `file`. `replaced` is the file it will replace, if any.
        pub(super) fn private(file: &Path, replaced: Option<&Path>) -> io::Result<Self> {
            Self::from_sddl(&private_sddl(&accounts_for(file, replaced)?))
        }

        /// This copy of `template`'s ACL, for `file` to replace it. A private ACL names the
        /// accounts that must keep access, since `OW` will mean the replacement's owner.
        pub(super) fn keeping_access(self, file: &Path, template: &Path) -> io::Result<Self> {
            let mut sddl = self.to_sddl()?;
            if !self.is_protected() || !sddl.contains(";;;OW)") {
                return Ok(self);
            }
            for account in accounts_for(file, Some(template))? {
                let rule = allow_rule(&account);
                if !sddl.contains(&rule) {
                    sddl.push_str(&rule);
                }
            }
            Self::from_sddl(&sddl)
        }

        pub(super) fn from_sddl(sddl: &str) -> io::Result<Self> {
            let sddl: Vec<u16> = sddl.encode_utf16().chain(once(0)).collect();
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
            Self::read(path, DACL_SECURITY_INFORMATION)
        }

        fn read(path: &Path, information: u32) -> io::Result<Option<Self>> {
            let name = wide(path);
            let mut needed = 0u32;
            // SAFETY: a zero-length request with a null buffer only reports the size needed.
            let sized =
                unsafe { GetFileSecurityW(name.as_ptr(), information, null_mut(), 0, &mut needed) };
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
                    information,
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

        fn control(&self) -> Option<u16> {
            let mut control = 0u16;
            let mut revision = 0u32;
            // SAFETY: the descriptor is valid and both outputs are plain integers.
            let read =
                unsafe { GetSecurityDescriptorControl(self.as_ptr(), &mut control, &mut revision) };
            (read != 0).then_some(control)
        }

        /// Whether the DACL takes entries from its folder through automatic inheritance.
        pub(super) fn inherits_automatically(&self) -> bool {
            self.control().is_some_and(|control| {
                control & SE_DACL_AUTO_INHERITED != 0 && control & SE_DACL_PROTECTED == 0
            })
        }

        fn is_protected(&self) -> bool {
            self.control()
                .is_some_and(|control| control & SE_DACL_PROTECTED != 0)
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
            self.sddl(DACL_SECURITY_INFORMATION)
        }

        /// The owner as a SID string or an SDDL alias.
        fn owner(&self) -> io::Result<String> {
            let sddl = self.sddl(OWNER_SECURITY_INFORMATION)?;
            sddl.strip_prefix("O:")
                .map(str::to_string)
                .ok_or_else(|| io::Error::other("The security descriptor has no owner"))
        }

        fn sddl(&self, information: u32) -> io::Result<String> {
            let mut text = null_mut();
            let mut length = 0u32;
            // SAFETY: the descriptor is valid and `text` receives a LocalAlloc buffer freed below.
            let converted = unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    self.as_ptr(),
                    SDDL_REVISION_1,
                    information,
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

    #[cfg(test)]
    mod tests {
        use super::*;

        const USER: &str = "S-1-5-21-1-2-3-1001";
        const OTHER: &str = "S-1-5-21-1-2-3-1002";

        fn accounts(list: &[&str]) -> BTreeSet<String> {
            list.iter().map(|account| account.to_string()).collect()
        }

        #[test]
        fn a_private_acl_names_the_accounts_before_the_fixed_rules() {
            assert_eq!(
                private_sddl(&accounts(&[USER])),
                format!("D:P(A;;FA;;;{USER})(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)")
            );
        }

        #[test]
        fn an_elevated_user_stays_listed_when_administrators_own_the_file() {
            assert_eq!(
                kept_accounts(USER, Some("BA"), Some("BA"), None),
                accounts(&[USER])
            );
        }

        #[test]
        fn a_service_keeps_the_previous_owner_and_the_folder_owner() {
            assert_eq!(
                kept_accounts("SY", Some(OTHER), Some(USER), None),
                accounts(&[USER, OTHER])
            );
        }

        #[test]
        fn only_a_service_lets_the_folder_owner_stand_in() {
            assert_eq!(
                kept_accounts(USER, Some(OTHER), None, None),
                accounts(&[USER])
            );
        }

        #[test]
        fn a_second_service_write_keeps_the_account_named_by_the_first() {
            let rules = format!("D:P(A;;FA;;;{USER})(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)");
            assert_eq!(
                kept_accounts("SY", None, Some("SY"), Some(&rules)),
                accounts(&[USER])
            );
        }

        #[test]
        fn groups_and_partial_rights_are_not_kept() {
            let rules = format!("D:P(A;;FA;;;WD)(A;;FR;;;{USER})(D;;FA;;;{OTHER})");
            assert!(kept_accounts("SY", None, Some("BU"), Some(&rules)).is_empty());
        }

        #[test]
        fn the_current_account_can_be_read() {
            let account = current_user().unwrap();
            assert!(
                !account.is_empty() && !account.starts_with("O:"),
                "{account}"
            );
        }
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
    #[test]
    fn a_new_private_file_is_created_with_the_private_acl() {
        for how in [PrivateOpen::CreateNew, PrivateOpen::Append] {
            let path = scratch("new");
            let expected = private_rules(&path).unwrap();
            open_private(&path, how).unwrap().write_all(b"x").unwrap();
            assert_eq!(access_rules(&path).unwrap(), expected, "{how:?}");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn appending_keeps_the_acl_of_an_existing_file() {
        let path = scratch("append");
        std::fs::write(&path, b"a").unwrap();
        let inherited = access_rules(&path).unwrap();
        assert_ne!(inherited, private_rules(&path).unwrap());
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
        assert_eq!(
            access_rules(&private).unwrap(),
            private_rules(&private).unwrap()
        );

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

    #[cfg(windows)]
    #[test]
    fn a_private_acl_from_before_accounts_were_named_gains_the_running_account() {
        let old = scratch("old");
        std::fs::write(&old, b"secret").unwrap();
        windows::Descriptor::from_sddl("D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)")
            .unwrap()
            .apply(&old)
            .unwrap();
        let replacement = scratch("replacement");
        drop(create_new_like(&replacement, &old).unwrap());
        let rules = access_rules(&replacement).unwrap();
        let expected = private_rules(&replacement).unwrap();
        for path in [old, replacement] {
            std::fs::remove_file(path).unwrap();
        }
        let sorted = |sddl: &str| {
            let mut rules: Vec<String> = sddl.split('(').map(str::to_string).collect();
            rules.sort();
            rules
        };
        assert_eq!(sorted(&rules), sorted(&expected));
    }

    #[cfg(windows)]
    #[test]
    fn a_replacement_copies_an_acl_that_does_not_inherit_automatically() {
        // SetFileSecurityW leaves out the auto-inherited flag, as on some CI runners' temp folders.
        let folder = scratch("legacy");
        std::fs::create_dir(&folder).unwrap();
        windows::Descriptor::from_sddl("D:(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)")
            .unwrap()
            .apply(&folder)
            .unwrap();
        let template = folder.join("template");
        std::fs::write(&template, b"x").unwrap();
        let replacement = folder.join("replacement");
        drop(create_new_like(&replacement, &template).unwrap());
        let rules = (
            access_rules(&template).unwrap(),
            access_rules(&replacement).unwrap(),
        );
        std::fs::remove_dir_all(folder).unwrap();
        assert_eq!(rules.1, rules.0);
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
