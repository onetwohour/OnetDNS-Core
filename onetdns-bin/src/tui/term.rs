//! Raw keyboard input and the alternate screen.

use std::io::Write;

use super::view::Key;

/// Alternate screen, cursor hidden, no wrap at the right margin.
const ENTER: &str = "\x1b[?1049h\x1b[?25l\x1b[?7l";
const LEAVE: &str = "\x1b[0m\x1b[?7h\x1b[?25h\x1b[?1049l";

pub(super) fn write(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}

/// Decodes the keys the console uses; other input is dropped.
#[cfg(any(unix, test))]
fn parse_keys(bytes: &[u8], keys: &mut Vec<Key>) {
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            0x1b => {
                let (key, used) = escape(&bytes[at..]);
                keys.extend(key);
                at += used;
            }
            0x03 => {
                keys.push(Key::Interrupt);
                at += 1;
            }
            byte @ 0x20..=0x7e => {
                keys.push(Key::Char(char::from(byte)));
                at += 1;
            }
            _ => at += 1,
        }
    }
}

/// `bytes` starts with Esc. Returns the key and the bytes the sequence used.
#[cfg(any(unix, test))]
fn escape(bytes: &[u8]) -> (Option<Key>, usize) {
    match bytes.get(1) {
        Some(b'[') => {
            let Some(end) = bytes[2..]
                .iter()
                .position(|byte| (0x40..=0x7e).contains(byte))
                .map(|offset| offset + 2)
            else {
                return (None, bytes.len());
            };
            let key = match (&bytes[2..end], bytes[end]) {
                (b"", b'A') => Some(Key::Up),
                (b"", b'B') => Some(Key::Down),
                (b"", b'H') | (b"1" | b"7", b'~') => Some(Key::Home),
                (b"", b'F') | (b"4" | b"8", b'~') => Some(Key::End),
                (b"5", b'~') => Some(Key::PageUp),
                (b"6", b'~') => Some(Key::PageDown),
                _ => None,
            };
            (key, end + 1)
        }
        Some(b'O') => match bytes.get(2) {
            Some(b'A') => (Some(Key::Up), 3),
            Some(b'B') => (Some(Key::Down), 3),
            Some(b'H') => (Some(Key::Home), 3),
            Some(b'F') => (Some(Key::End), 3),
            Some(_) => (None, 3),
            None => (None, 2),
        },
        _ => (None, 1),
    }
}

#[cfg(unix)]
pub(crate) use unix::Saved;
#[cfg(unix)]
pub(super) use unix::{enter, read_keys, size, usable};
#[cfg(windows)]
pub(crate) use windows::Saved;
#[cfg(windows)]
pub(super) use windows::{enter, read_keys, size, usable};

#[cfg(unix)]
mod unix {
    use super::{parse_keys, write, Key, ENTER, LEAVE};
    use std::time::Duration;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const VDISABLE: libc::cc_t = 0;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const VDISABLE: libc::cc_t = libc::_POSIX_VDISABLE;

    /// Terminal settings to put back.
    pub(crate) struct Saved(libc::termios);

    impl Saved {
        pub(crate) fn capture() -> Option<Self> {
            let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
            // SAFETY: tcgetattr fills the struct when it returns 0, and only then is it read.
            unsafe {
                (libc::tcgetattr(0, termios.as_mut_ptr()) == 0).then(|| Self(termios.assume_init()))
            }
        }

        pub(crate) fn restore(&self) {
            write(LEAVE);
            // SAFETY: the struct came from tcgetattr.
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, &self.0);
            }
        }

        #[cfg(target_os = "linux")]
        pub(crate) fn to_bytes(&self) -> Vec<u8> {
            // SAFETY: termios is plain data, read here as its own bytes.
            unsafe {
                std::slice::from_raw_parts(
                    (&raw const self.0).cast::<u8>(),
                    std::mem::size_of::<libc::termios>(),
                )
            }
            .to_vec()
        }

        /// Bytes `to_bytes` made in a process on the same system.
        #[cfg(target_os = "linux")]
        pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
            (bytes.len() == std::mem::size_of::<libc::termios>()).then(|| {
                // SAFETY: the length matches, and every bit pattern is a termios.
                Self(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::termios>()) })
            })
        }
    }

    /// In the background, reading the terminal would stop the process.
    pub(in crate::tui) fn usable() -> bool {
        let term = std::env::var("TERM").unwrap_or_default();
        // SAFETY: both calls only read process state.
        let foreground = unsafe { libc::tcgetpgrp(0) == libc::getpgrp() };
        !term.is_empty() && term != "dumb" && foreground
    }

    /// Keys arrive one by one without echo. Ctrl+C still raises SIGINT; Ctrl+Z and Ctrl+\ are off
    /// because stopping or killing the process would leave the terminal in this state.
    pub(in crate::tui) fn enter() -> Option<Saved> {
        let saved = Saved::capture()?;
        let mut raw = saved.0;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::IEXTEN);
        raw.c_iflag &= !libc::IXON;
        raw.c_cc[libc::VSUSP] = VDISABLE;
        raw.c_cc[libc::VQUIT] = VDISABLE;
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        // SAFETY: `raw` is a copy of a struct tcgetattr filled.
        if unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw) } != 0 {
            return None;
        }
        write(ENTER);
        Some(saved)
    }

    pub(in crate::tui) fn size() -> (usize, usize) {
        let mut size = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCGWINSZ writes one winsize.
        let ok = unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut size) } == 0;
        if ok && size.ws_col > 0 && size.ws_row > 0 {
            (usize::from(size.ws_col), usize::from(size.ws_row))
        } else {
            (80, 24)
        }
    }

    /// Waits up to `timeout` for input.
    pub(in crate::tui) fn read_keys(timeout: Duration, keys: &mut Vec<Key>) {
        let mut poll = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: one pollfd, as the count says.
        if unsafe { libc::poll(&mut poll, 1, millis) } <= 0 {
            return;
        }
        let mut buf = [0u8; 64];
        // SAFETY: reads at most the buffer's length into it.
        let read = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
        match usize::try_from(read) {
            Ok(read) if read > 0 => parse_keys(&buf[..read], keys),
            // A closed terminal stays readable; without the wait this would spin.
            _ => std::thread::sleep(timeout),
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::{write, Key, ENTER, LEAVE};
    use std::time::Duration;

    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
    const ENABLE_LINE_INPUT: u32 = 0x0002;
    const ENABLE_ECHO_INPUT: u32 = 0x0004;
    const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
    const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    const KEY_EVENT: u16 = 1;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x102;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    /// INPUT_RECORD read as a KEY_EVENT_RECORD; other events are skipped by type.
    struct InputRecord {
        event_type: u16,
        _padding: u16,
        key_down: i32,
        repeat: u16,
        virtual_key: u16,
        scan_code: u16,
        unicode: u16,
        control: u32,
    }

    const _: () = assert!(std::mem::size_of::<InputRecord>() == 20);

    #[repr(C)]
    #[derive(Default)]
    /// CONSOLE_SCREEN_BUFFER_INFO.
    struct ScreenBufferInfo {
        size: [i16; 2],
        cursor: [i16; 2],
        attributes: u16,
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
        max_size: [i16; 2],
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(which: u32) -> isize;
        fn GetConsoleMode(console: isize, mode: *mut u32) -> i32;
        fn SetConsoleMode(console: isize, mode: u32) -> i32;
        fn GetConsoleScreenBufferInfo(console: isize, info: *mut ScreenBufferInfo) -> i32;
        fn WaitForSingleObject(handle: isize, millis: u32) -> u32;
        fn ReadConsoleInputW(
            console: isize,
            records: *mut InputRecord,
            length: u32,
            read: *mut u32,
        ) -> i32;
    }

    /// Console modes to put back.
    pub(crate) struct Saved {
        input: isize,
        output: isize,
        input_mode: u32,
        output_mode: u32,
    }

    impl Saved {
        pub(crate) fn restore(&self) {
            write(LEAVE);
            // SAFETY: handles and modes came from the same console.
            unsafe {
                SetConsoleMode(self.input, self.input_mode);
                SetConsoleMode(self.output, self.output_mode);
            }
        }
    }

    fn handle(which: u32) -> isize {
        // SAFETY: GetStdHandle takes no pointers.
        unsafe { GetStdHandle(which) }
    }

    fn mode(console: isize) -> Option<u32> {
        let mut mode = 0;
        // SAFETY: writes one u32.
        (unsafe { GetConsoleMode(console, &mut mode) } != 0).then_some(mode)
    }

    /// A Git Bash or other pseudo-terminal passes the terminal check but is no console.
    pub(in crate::tui) fn usable() -> bool {
        mode(handle(STD_INPUT_HANDLE)).is_some() && mode(handle(STD_OUTPUT_HANDLE)).is_some()
    }

    /// Ctrl+C arrives as a key, so the console quits through the normal shutdown.
    pub(in crate::tui) fn enter() -> Option<Saved> {
        let input = handle(STD_INPUT_HANDLE);
        let output = handle(STD_OUTPUT_HANDLE);
        let saved = Saved {
            input,
            output,
            input_mode: mode(input)?,
            output_mode: mode(output)?,
        };
        let output_mode =
            saved.output_mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        let input_mode = saved.input_mode
            & !(ENABLE_PROCESSED_INPUT
                | ENABLE_LINE_INPUT
                | ENABLE_ECHO_INPUT
                | ENABLE_VIRTUAL_TERMINAL_INPUT);
        // SAFETY: the handles are this process's console.
        unsafe {
            if SetConsoleMode(output, output_mode) == 0 {
                return None;
            }
            if SetConsoleMode(input, input_mode) == 0 {
                SetConsoleMode(output, saved.output_mode);
                return None;
            }
        }
        write(ENTER);
        Some(saved)
    }

    pub(in crate::tui) fn size() -> (usize, usize) {
        let mut info = ScreenBufferInfo::default();
        // SAFETY: writes one CONSOLE_SCREEN_BUFFER_INFO.
        let ok = unsafe { GetConsoleScreenBufferInfo(handle(STD_OUTPUT_HANDLE), &mut info) } != 0;
        let cols = usize::try_from(i32::from(info.right) - i32::from(info.left) + 1).unwrap_or(0);
        let rows = usize::try_from(i32::from(info.bottom) - i32::from(info.top) + 1).unwrap_or(0);
        if ok && cols > 0 && rows > 0 {
            (cols, rows)
        } else {
            (80, 24)
        }
    }

    /// Waits up to `timeout` for input.
    pub(in crate::tui) fn read_keys(timeout: Duration, keys: &mut Vec<Key>) {
        let input = handle(STD_INPUT_HANDLE);
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: waits on this process's console input handle.
        match unsafe { WaitForSingleObject(input, millis) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => return,
            _ => {
                std::thread::sleep(timeout);
                return;
            }
        }
        let mut records = [InputRecord::default(); 16];
        let mut read = 0;
        // SAFETY: reads at most the array's length into it.
        if unsafe { ReadConsoleInputW(input, records.as_mut_ptr(), 16, &mut read) } == 0 {
            std::thread::sleep(timeout);
            return;
        }
        for record in records.iter().take(read as usize) {
            if record.event_type != KEY_EVENT || record.key_down == 0 {
                continue;
            }
            let key = match record.virtual_key {
                0x21 => Some(Key::PageUp),
                0x22 => Some(Key::PageDown),
                0x23 => Some(Key::End),
                0x24 => Some(Key::Home),
                0x26 => Some(Key::Up),
                0x28 => Some(Key::Down),
                _ => match record.unicode {
                    0x03 => Some(Key::Interrupt),
                    0x20..=0x7e => Some(Key::Char(char::from(record.unicode as u8))),
                    _ => None,
                },
            };
            if let Some(key) = key {
                for _ in 0..record.repeat.clamp(1, 8) {
                    keys.push(key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(bytes: &[u8]) -> Vec<Key> {
        let mut keys = Vec::new();
        parse_keys(bytes, &mut keys);
        keys
    }

    #[test]
    fn arrows_and_paging_decode_in_both_cursor_modes() {
        assert_eq!(
            keys(b"\x1b[A\x1bOB\x1b[5~\x1b[6~\x1b[H\x1b[4~q"),
            [
                Key::Up,
                Key::Down,
                Key::PageUp,
                Key::PageDown,
                Key::Home,
                Key::End,
                Key::Char('q')
            ]
        );
    }

    #[test]
    fn unknown_or_cut_sequences_drop_without_eating_keys() {
        assert_eq!(keys(b"\x1b[1;5Cp"), [Key::Char('p')]);
        assert_eq!(keys(b"\x1b"), []);
        assert_eq!(keys(b"\x1b[12"), []);
        assert_eq!(keys("é\x03".as_bytes()), [Key::Interrupt]);
    }
}
