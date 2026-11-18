//! One TLS connection read by one thread while another writes, over a socket handle both share.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::conn::TlsConnection;
use crate::record::RecordReader;
use crate::TlsError;

/// Clones share the connection. The record keys are locked only while a record is opened or
/// written, never while waiting for the peer, so a reader blocked on the socket does not hold up a
/// writer. A read that times out keeps the part of a record that arrived.
pub struct SharedTlsStream<S> {
    io: S,
    conn: Arc<Mutex<TlsConnection>>,
    received: Arc<Mutex<Received>>,
}

#[derive(Default)]
struct Received {
    records: RecordReader,
    plain: Vec<u8>,
    pos: usize,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn tls_io_error(error: TlsError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

impl<S: Clone> Clone for SharedTlsStream<S> {
    fn clone(&self) -> Self {
        Self {
            io: self.io.clone(),
            conn: self.conn.clone(),
            received: self.received.clone(),
        }
    }
}

impl<S> SharedTlsStream<S> {
    /// `pending` is ciphertext the handshake left unread.
    pub fn new(conn: TlsConnection, io: S, pending: &[u8]) -> Self {
        let mut records = RecordReader::new();
        records.feed(pending);
        Self {
            io,
            conn: Arc::new(Mutex::new(conn)),
            received: Arc::new(Mutex::new(Received {
                records,
                ..Received::default()
            })),
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }
}

impl<S: Write> SharedTlsStream<S> {
    /// RFC 8446 requires it before closing the write side, or the peer sees a truncation.
    pub fn send_close_notify(&mut self) -> std::io::Result<()> {
        lock(&self.conn)
            .send_close_notify(&mut self.io)
            .map_err(tls_io_error)
    }
}

impl<S: Read + Write> Read for SharedTlsStream<S> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut received = lock(&self.received);
        loop {
            if received.pos < received.plain.len() {
                let start = received.pos;
                let n = (received.plain.len() - start).min(out.len());
                out[..n].copy_from_slice(&received.plain[start..start + n]);
                received.pos += n;
                return Ok(n);
            }
            let record = match received.records.next_record() {
                Ok(record) => record,
                Err(error) => {
                    return Err(tls_io_error(
                        lock(&self.conn).fail_read(&mut self.io, error),
                    ))
                }
            };
            let Some(record) = record else {
                let mut chunk = [0u8; 8192];
                let n = self.io.read(&mut chunk)?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        TlsError::Eof.to_string(),
                    ));
                }
                received.records.feed(&chunk[..n]);
                continue;
            };
            match lock(&self.conn).open_app_record(record, &mut self.io) {
                Ok(Some(data)) => {
                    received.plain = data;
                    received.pos = 0;
                }
                Ok(None) => {}
                Err(TlsError::CloseNotify) => return Ok(0),
                Err(error) => return Err(tls_io_error(error)),
            }
        }
    }
}

impl<S: Write> Write for SharedTlsStream<S> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        lock(&self.conn)
            .write_app(&mut self.io, data)
            .map_err(|_| std::io::Error::other("Could not write TLS data"))?;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{client_handshake, server_handshake, ClientConfig, InsecureVerifier};
    use crate::ServerConfig;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    #[derive(Clone)]
    struct Socket(Arc<TcpStream>);

    impl Read for Socket {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            (&*self.0).read(buf)
        }
    }

    impl Write for Socket {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            (&*self.0).write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            (&*self.0).flush()
        }
    }

    /// A server stream and the client end with its TLS connection.
    fn connected() -> (SharedTlsStream<Socket>, TcpStream, TlsConnection) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let config = ServerConfig::from_pkcs8(
            ck.cert.der().as_ref().to_vec(),
            &ck.key_pair.serialize_der(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let conn = server_handshake(&mut socket, &config).expect("서버 핸드셰이크");
            SharedTlsStream::new(conn, Socket(Arc::new(socket)), &[])
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let config = ClientConfig {
            server_name: "localhost".to_string(),
            verify_name: true,
            roots: None,
            insecure_verifier: Some(
                InsecureVerifier::dangerously_disable_certificate_verification(),
            ),
            ..Default::default()
        };
        let conn = client_handshake(&mut client, &config).expect("클라이언트 핸드셰이크");
        (server.join().unwrap(), client, conn)
    }

    #[test]
    fn a_reader_waiting_for_the_peer_does_not_hold_up_the_writer() {
        let (server, mut client, mut conn) = connected();
        let mut reader = server.clone();
        let reading = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let n = reader.read(&mut buf).unwrap();
            buf[..n].to_vec()
        });
        std::thread::sleep(Duration::from_millis(100));
        let mut writer = server;
        // On its own thread: a writer stuck behind the reader then fails the read below instead of
        // hanging the test.
        std::thread::spawn(move || writer.write_all(b"from the server"));
        assert_eq!(
            conn.read_app(&mut client)
                .expect("읽는 쪽이 막혀 있어도 쓰기는 도착해야 합니다"),
            b"from the server"
        );
        conn.write_app(&mut client, b"from the client").unwrap();
        assert_eq!(reading.join().unwrap(), b"from the client");
    }

    #[test]
    fn a_read_timeout_keeps_the_part_of_a_record_that_arrived() {
        let (mut server, mut client, mut conn) = connected();
        server
            .get_ref()
            .0
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut sealed = Vec::new();
        conn.write_app(&mut sealed, b"split record").unwrap();
        client.write_all(&sealed[..7]).unwrap();
        let mut buf = [0u8; 64];
        let error = server
            .read(&mut buf)
            .expect_err("레코드가 다 오기 전에는 읽을 것이 없습니다");
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        client.write_all(&sealed[7..]).unwrap();
        let n = server.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"split record");
    }

    #[test]
    fn close_notify_reads_as_the_end_of_the_stream() {
        let (mut server, mut client, mut conn) = connected();
        conn.send_close_notify(&mut client).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(server.read(&mut buf).unwrap(), 0);
    }
}
