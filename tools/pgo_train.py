#!/usr/bin/env python3
"""Writes the PGO profile for a release build.

Runs an OnetDNS binary built with -Cprofile-generate on the workloads the profile should cover,
then merges what every instance wrote with the llvm-profdata of the rustc in use: blocked queries
and cache hits behind a filter over UDP and TCP, forwarding over each encrypted transport to a
second instance, a new TLS connection per query to that instance, and DNSSEC-validated recursion
and forwarding from a local root, over zones signed with ECDSA, Ed25519 and RSA.

Root hints carry no port, so the root listens on 127.0.0.1:53 and the zones below it on [::1]:53;
on Linux this needs net.ipv4.ip_unprivileged_port_start=0 or a network namespace.

usage: pgo_train.py [--emulator CMD] BINARY OUTPUT.profdata
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import random
import re
import shlex
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PORT = 15353
ZONE_PORT = 15853
# DoT and DoQ share the number, as do DoH and DoH3.
DOT_PORT = 15854
DOH_PORT = 15443
DNSCRYPT_PORT = 15855
RESOLVER_PORT = 15856
ROOT = "127.0.0.1"
ZONE = "::1"
TLS_NAME = "pgo.test"
PROVIDER = "2.dnscrypt-cert.pgo.test"
ZONE_OWNERS = 20000
ED25519_OWNERS = 5000
# Each one is signed in Python here.
RSA_OWNERS = 500
RULES = 100000
REGEX_RULES = 100
BLOCKED_QUERIES = 20000
LOAD_SECONDS = 15
SHORT_SECONDS = 5
# Emulated targets load the blocklist many times slower.
READY_SECONDS = 300
STOP_SECONDS = 120
NXDOMAIN = 3
NOERROR = 0
A = 1
NS = 2
SOA = 6
DNSKEY = 48
RSASHA256 = 8
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
CLIENT_COOKIE = bytes(range(1, 9))


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def name_wire(name: str) -> bytes:
    labels = [label for label in name.lower().split(".") if label]
    return b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\0"


def query(name: str, edns: bool, qtype: int = A, ad: bool = False, cookie: bool = False) -> bytes:
    flags = 0x0100 | (0x0020 if ad else 0)
    header = struct.pack("!HHHHHH", 0, flags, 1, 0, 0, 1 if edns else 0)
    packet = header + name_wire(name) + struct.pack("!HH", qtype, 1)
    if edns:
        option = struct.pack("!HH", 10, len(CLIENT_COOKIE)) + CLIENT_COOKIE if cookie else b""
        packet += b"\0" + struct.pack("!HHIH", 41, 1232, 0, len(option)) + option
    return packet


def ask(host: str, port: int, packet: bytes) -> bytes:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.0)
        for _ in range(10):
            try:
                sock.sendto(packet, (host, port))
                return sock.recv(65535)
            except OSError:
                time.sleep(0.5)
    fail(f"no answer from {host} port {port}")


def answers(reply: bytes, rtype: int) -> list[bytes]:
    """The rdata of the answer records of type `rtype`."""

    def skip_name(pos: int) -> int:
        while reply[pos] and reply[pos] & 0xC0 != 0xC0:
            pos += reply[pos] + 1
        return pos + (2 if reply[pos] else 1)

    qdcount, ancount = struct.unpack_from("!HH", reply, 4)
    pos = 12
    for _ in range(qdcount):
        pos = skip_name(pos) + 4
    out = []
    for _ in range(ancount):
        pos = skip_name(pos)
        rr_type, _, _, length = struct.unpack_from("!HHIH", reply, pos)
        pos += 10
        if rr_type == rtype:
            out.append(reply[pos : pos + length])
        pos += length
    return out


def key_signing_key(host: str, port: int, zone: str) -> bytes:
    """The DNSKEY rdata with the SEP flag that the server at `host` publishes for `zone`."""
    keys = [key for key in answers(ask(host, port, query(zone, True, DNSKEY)), DNSKEY) if key[1] & 1]
    if not keys:
        fail(f"{host} port {port} published no key-signing DNSKEY for {zone}")
    return keys[0]


def key_tag(rdata: bytes) -> int:
    """RFC 4034, appendix B."""
    total = sum(byte if i & 1 else byte << 8 for i, byte in enumerate(rdata))
    return (total + (total >> 16)) & 0xFFFF


def ds_record(owner: str, rdata: bytes) -> str:
    digest = hashlib.sha256(name_wire(owner) + rdata).hexdigest().upper()
    return f"{owner} IN DS {key_tag(rdata)} {rdata[3]} 2 {digest}"


def write_anchor(path: Path, rdata: bytes) -> None:
    """A root trust anchor in the state format dnssec_anchor_file reads."""
    flags = struct.unpack_from("!H", rdata)[0]
    key = base64.b64encode(rdata[4:]).decode()
    path.write_text(
        f"ONETDNS-ANCHOR\nzone .\nhold_down 2592000\nkey valid 0 {flags} {rdata[3]} 0 {key}\n",
        encoding="utf-8",
    )


def dnscrypt_stamp(log: Path) -> str:
    """The stamp of the DNSCrypt listener, from the provider key the server logged."""
    match = re.search(r"provider_pubkey=\"?([0-9A-F]{64})", log.read_text(encoding="utf-8", errors="replace"))
    if not match:
        fail(f"{log} does not show the DNSCrypt provider key")

    def lp(data: bytes) -> bytes:
        return bytes([len(data)]) + data

    raw = b"\x01" + bytes(8) + lp(f"127.0.0.1:{DNSCRYPT_PORT}".encode())
    raw += lp(bytes.fromhex(match[1])) + lp(PROVIDER.encode())
    return "sdns://" + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def write_fixtures(work: Path) -> tuple[list[str], list[str]]:
    """Writes the zone below the root and the blocklist; returns allowed and blocked names."""
    allowed = [f"h{i:06d}.bench.test" for i in range(ZONE_OWNERS)]
    zone = [
        "$TTL 3600",
        "@ IN SOA ns.test. hostmaster.test. 1 3600 600 86400 300",
        "@ IN NS ns.test.",
        f"ns IN AAAA {ZONE}",
    ]
    zone += [f"h{i:06d}.bench IN A 192.0.2.{i % 254 + 1}" for i in range(ZONE_OWNERS)]
    (work / "db.test").write_text("\n".join(zone) + "\n", encoding="utf-8")

    # Same shape as benchmarks/dns-filter/gen-realistic-fixture.sh: varied registered domains
    # under a small set of repeated tracker labels.
    rng = random.Random(11)
    tlds = "com net org io ru cn info biz top xyz".split()
    subs = ("ads ad track tracker analytics stat stats metrics pixel beacon cdn img static log "
            "event collect sync rtb bid px t a").split()
    domains = []
    for _ in range(RULES // 4):
        label = "".join(chr(97 + rng.randrange(26)) for _ in range(5 + rng.randrange(9)))
        domains.append(f"{label}.{rng.choice(tlds)}")
    names: set[str] = set()
    while len(names) < RULES:
        domain = rng.choice(domains)
        roll = rng.random()
        if roll < 0.25:
            names.add(domain)
        elif roll < 0.85:
            names.add(f"{rng.choice(subs)}.{domain}")
        else:
            names.add(f"{rng.choice(subs)}.{rng.choice(subs)}.{domain}")
    blocked = sorted(names)
    # Lists in use mix hosts files, exceptions and a few regular expressions in with these rules.
    hosts = blocked[::5]
    adblock = [name for i, name in enumerate(blocked) if i % 5]
    excepted = [f"allow.{name}" for name in rng.sample(adblock, RULES // 100)]
    regex_domains = rng.sample(domains, REGEX_RULES)
    rules = "".join(f"||{name}^\n" for name in adblock)
    rules += "".join(f"@@||{name}^\n" for name in excepted)
    for domain in regex_domains:
        labels = "|".join(rng.sample(subs, 3))
        escaped = domain.replace(".", "\\.")
        rules += f"/^({labels})[0-9]{{1,3}}\\.{escaped}$/\n"
    (work / "blocklist.txt").write_text(rules, encoding="utf-8")
    (work / "hosts.txt").write_text("".join(f"0.0.0.0 {name}\n" for name in hosts), encoding="utf-8")

    queries = [rng.choice(blocked) for _ in range(BLOCKED_QUERIES)]
    for i in range(5, BLOCKED_QUERIES, 10):
        queries[i] = f"{rng.choice(subs)}{rng.randrange(1000)}.{rng.choice(regex_domains)}"
    for i in range(7, BLOCKED_QUERIES, 50):
        queries[i] = rng.choice(excepted)
    return allowed, queries


def write_ed25519_zone(work: Path) -> list[str]:
    zone = [
        "$TTL 3600",
        "@ IN SOA ns.test. hostmaster.test. 1 3600 600 86400 300",
        "@ IN NS ns.test.",
    ]
    zone += [f"h{i:06d} IN A 192.0.2.{i % 254 + 1}" for i in range(ED25519_OWNERS)]
    (work / "db.ed25519").write_text("\n".join(zone) + "\n", encoding="utf-8")
    return [f"h{i:06d}.ed25519" for i in range(ED25519_OWNERS)]


def probable_prime(n: int, rng: random.Random) -> bool:
    """Miller-Rabin."""
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(20):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rsa_prime(rng: random.Random, small_primes: list[int]) -> int:
    """A 1024-bit prime p with p - 1 coprime to the public exponent 65537."""
    while True:
        p = rng.getrandbits(1024) | (3 << 1022) | 1
        if p % 65537 != 1 and all(p % q for q in small_primes) and probable_prime(p, rng):
            return p


def write_rsa_zone(work: Path) -> list[str]:
    """Writes the `rsa.` zone signed with RSA/SHA-256, which zone signing does not offer. The key
    comes from a fixed seed: it is a fixture, not a secret."""
    rng = random.Random(RSASHA256)
    small_primes = [n for n in range(3, 2000, 2) if all(n % d for d in range(3, int(n**0.5) + 1, 2))]
    p, q = rsa_prime(rng, small_primes), rsa_prime(rng, small_primes)
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))
    dp, dq, qinv = d % (p - 1), d % (q - 1), pow(q, -1, p)
    dnskey = struct.pack("!HBBB", 257, 3, RSASHA256, 3) + e.to_bytes(3, "big") + (p * q).to_bytes(256, "big")
    tag = key_tag(dnskey)
    ttl = 3600
    now = int(time.time())
    inception, expiration = now - 3600, now + 7 * 86400

    def sign(data: bytes) -> bytes:
        """PKCS #1 v1.5 with the private key in CRT form."""
        digest = SHA256_DIGEST_INFO + hashlib.sha256(data).digest()
        m = int.from_bytes(b"\0\1" + b"\xff" * (253 - len(digest)) + b"\0" + digest, "big")
        m1, m2 = pow(m, dp, p), pow(m, dq, q)
        return (m2 + qinv * (m1 - m2) % p * q).to_bytes(256, "big")

    lines = []

    def rrset(owner: str, rtype: int, mnemonic: str, text: str, rdata: bytes) -> None:
        """One record and its RRSIG (RFC 4034)."""
        labels = owner.count(".")
        rrsig = struct.pack("!HBBIIIH", rtype, RSASHA256, labels, ttl, expiration, inception, tag)
        rrsig += name_wire("rsa.")
        record = name_wire(owner) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
        signature = base64.b64encode(sign(rrsig + record)).decode()
        lines.append(f"{owner} {ttl} IN {mnemonic} {text}")
        lines.append(
            f"{owner} {ttl} IN RRSIG {mnemonic} {RSASHA256} {labels} {ttl} {expiration} {inception} "
            f"{tag} rsa. {signature}"
        )

    soa = name_wire("ns.test.") + name_wire("hostmaster.test.") + struct.pack("!5I", 1, 3600, 600, 86400, 300)
    rrset("rsa.", SOA, "SOA", "ns.test. hostmaster.test. 1 3600 600 86400 300", soa)
    rrset("rsa.", NS, "NS", "ns.test.", name_wire("ns.test."))
    rrset("rsa.", DNSKEY, "DNSKEY", f"257 3 {RSASHA256} {base64.b64encode(dnskey[4:]).decode()}", dnskey)
    for i in range(RSA_OWNERS):
        address = bytes([192, 0, 2, i % 254 + 1])
        rrset(f"h{i:06d}.rsa.", A, "A", socket.inet_ntoa(address), address)
    (work / "db.rsa").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return [f"h{i:06d}.rsa" for i in range(RSA_OWNERS)]


def write_root_zone(work: Path, keys: dict[str, bytes]) -> None:
    """The root, with each zone below it delegated to ns.test. and secured by a DS of `keys`."""
    zone = [
        "$TTL 86400",
        "@ IN SOA ns.root. hostmaster.root. 1 1800 900 604800 86400",
        "@ IN NS ns.root.",
        f"ns.root. IN A {ROOT}",
        f"ns.test. IN AAAA {ZONE}",
    ]
    for owner, key in keys.items():
        zone += [f"{owner} IN NS ns.test.", ds_record(owner, key)]
    (work / "db.root").write_text("\n".join(zone) + "\n", encoding="utf-8")


def write_config(path: Path, listen: list[str], extra: str) -> None:
    addresses = ", ".join(f'"{address}"' for address in listen)
    # Without the dashboard, statistics and the query log are kept only for a file.
    path.write_text(
        f"""mode = "personal"
listen = [{addresses}]
workers = 1
do_udp = true
do_tcp = true
prefetch = false
querylog_file = "{path.with_suffix(".querylog").as_posix()}"
{extra}""",
        encoding="utf-8",
    )


class Server:
    def __init__(
        self,
        command: list[str],
        config: Path,
        profile: str,
        env: dict | None = None,
        low_ports: bool = False,
    ) -> None:
        self.log_path = config.with_suffix(".log")
        self.log = self.log_path.open("wb")
        env = dict(os.environ, LLVM_PROFILE_FILE=profile, **(env or {}))
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        argv = [*command, "run", "--config", str(config), "--no-web", "--no-supervisor"]
        if low_ports and sys.platform == "darwin":
            # macOS lets only root bind a port below 1024 to a specific address. sudo drops the
            # environment, so the profile path goes on the command line.
            argv = ["sudo", "-n", "env", f"LLVM_PROFILE_FILE={profile}", *argv]
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            env=env,
            creationflags=flags,
        )

    def fail(self, message: str) -> None:
        self.kill()
        tail = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-20:]
        fail(message + "\n" + "\n".join(tail))

    def wait_ready(self, host: str, port: int, name: str, rcode: int, ad: bool = False) -> None:
        """Until `name` gets `rcode`, and with `ad` also the AD bit of a validated answer."""
        packet = query(name, edns=False, ad=ad)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        deadline = time.monotonic() + READY_SECONDS
        try:
            while time.monotonic() < deadline:
                if self.proc.poll() is not None:
                    self.fail(f"server exited with {self.proc.returncode} before answering")
                try:
                    sock.sendto(packet, (host, port))
                    reply = sock.recv(4096)
                    if reply[3] & 0x0F == rcode and (not ad or reply[3] & 0x20):
                        return
                except OSError:
                    pass
                time.sleep(0.25)
        finally:
            sock.close()
        wanted = f"rcode {rcode}" + (" with AD" if ad else "")
        self.fail(f"{name} did not get {wanted} on {host} port {port} within {READY_SECONDS} s")

    def stop(self) -> None:
        # Only a normal exit writes the profile: Ctrl+Break on Windows, SIGTERM elsewhere.
        self.proc.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
        try:
            code = self.proc.wait(timeout=STOP_SECONDS)
        except subprocess.TimeoutExpired:
            self.fail(f"server did not exit within {STOP_SECONDS} s of the stop signal")
        self.log.close()
        if code != 0:
            self.fail(f"server exited with {code} after the stop signal")

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


def drive(port: int, names: list[str], seconds: float, window: int = 64) -> tuple[int, int]:
    """Keeps `window` queries in flight over UDP for `seconds`; returns queries sent and answered."""
    packets = [query(name, edns=i % 2 == 1, cookie=i % 4 == 3) for i, name in enumerate(names)]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("127.0.0.1", port))
    sock.settimeout(1.0)
    sent = answered = 0

    def send() -> None:
        nonlocal sent
        packet = packets[sent % len(packets)]
        sock.send(struct.pack("!H", sent & 0xFFFF) + packet[2:])
        sent += 1

    for _ in range(window):
        send()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            sock.recv(4096)
            answered += 1
            send()
        except socket.timeout:
            for _ in range(window):
                send()
    sock.close()
    return sent, answered


def drive_tcp(port: int, names: list[str], seconds: float, window: int = 16) -> tuple[int, int]:
    """Pipelines `window` queries on a TCP connection for `seconds`, reconnecting when it closes."""
    packets = [query(name, edns=True) for name in names]
    sent = answered = 0
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            pending = b""

            def send() -> None:
                nonlocal sent
                packet = struct.pack("!H", sent & 0xFFFF) + packets[sent % len(packets)][2:]
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                sent += 1

            try:
                for _ in range(window):
                    send()
                while time.monotonic() < deadline:
                    data = sock.recv(65535)
                    if not data:
                        break
                    pending += data
                    while len(pending) >= 2 and len(pending) >= 2 + struct.unpack_from("!H", pending)[0]:
                        pending = pending[2 + struct.unpack_from("!H", pending)[0] :]
                        answered += 1
                        send()
            except OSError:
                pass
    return sent, answered


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed early")
        data += chunk
    return data


def exchange_dot(sock: socket.socket, packet: bytes) -> bool:
    sock.sendall(struct.pack("!H", len(packet)) + packet)
    return len(recv_exact(sock, struct.unpack("!H", recv_exact(sock, 2))[0])) > 12


def exchange_doh(sock: socket.socket, packet: bytes, get: bool) -> bool:
    """One DoH request over HTTP/1.1."""
    head = f"Host: {TLS_NAME}\r\nAccept: application/dns-message\r\n"
    if get:
        encoded = base64.urlsafe_b64encode(packet).decode().rstrip("=")
        request = f"GET /dns-query?dns={encoded} HTTP/1.1\r\n{head}\r\n".encode()
    else:
        head += f"Content-Type: application/dns-message\r\nContent-Length: {len(packet)}\r\n"
        request = f"POST /dns-query HTTP/1.1\r\n{head}\r\n".encode() + packet
    sock.sendall(request)
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            return False
        response += chunk
    header, body = response.split(b"\r\n\r\n", 1)
    length = re.search(rb"(?i)\r\ncontent-length:\s*(\d+)", header)
    if not header.startswith(b"HTTP/1.1 200") or not length:
        return False
    return len(body + recv_exact(sock, int(length[1]) - len(body))) > 12


def drive_tls(names: list[str], seconds: float) -> tuple[int, int, int]:
    """Opens a new connection per query to the DoT and DoH listeners of the zone instance, so its
    server side runs a handshake each time: TLS 1.3 in full and resumed, and TLS 1.2. Returns
    connections opened, answered, and resumed."""

    def context(alpn: str, tls12: bool) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Only the server's work is trained; the client need not check its certificate.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if tls12:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols([alpn])
        return ctx

    variants = [
        (DOT_PORT, context("dot", False), False, exchange_dot),
        (DOT_PORT, context("dot", False), True, exchange_dot),
        (DOT_PORT, context("dot", True), False, exchange_dot),
        (DOH_PORT, context("http/1.1", False), False, lambda s, p: exchange_doh(s, p, False)),
        (DOH_PORT, context("http/1.1", False), True, lambda s, p: exchange_doh(s, p, True)),
        (DOH_PORT, context("http/1.1", True), False, lambda s, p: exchange_doh(s, p, False)),
    ]
    sessions: dict[int, ssl.SSLSession] = {}
    opened = answered = resumed = 0
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        index = opened % len(variants)
        port, ctx, resume, exchange = variants[index]
        packet = query(names[opened % len(names)], edns=True)
        opened += 1
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5.0) as raw:
                session = sessions.get(index) if resume else None
                with ctx.wrap_socket(raw, server_hostname=TLS_NAME, session=session) as sock:
                    if exchange(sock, packet):
                        answered += 1
                    resumed += sock.session_reused
                    sessions[index] = sock.session
        except OSError:
            pass
    return opened, answered, resumed


def llvm_profdata() -> Path:
    sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip()
    info = subprocess.check_output(["rustc", "-vV"], text=True)
    host = next(line.split()[1] for line in info.splitlines() if line.startswith("host:"))
    name = "llvm-profdata.exe" if os.name == "nt" else "llvm-profdata"
    tool = Path(sysroot, "lib", "rustlib", host, "bin", name)
    if not tool.is_file():
        fail(f"{tool} not found; install it with: rustup component add llvm-tools")
    return tool


def train(
    command: list[str],
    work: Path,
    phase: str,
    extra: str,
    names: list[str],
    rcode: int = NOERROR,
    seconds: float = LOAD_SECONDS,
    tcp_seconds: float = 0,
    ad: bool = False,
    env: dict | None = None,
    probes: list[tuple[str, int]] | None = None,
) -> None:
    """Runs one instance under load. It is ready once each of `probes`, by default the first of
    `names`, gets its rcode."""
    config = work / f"{phase}.toml"
    write_config(config, [f"127.0.0.1:{PORT}"], extra)
    server = Server(command, config, str(work / f"train-{phase}-%p.profraw"), env)
    try:
        for name, code in probes or [(names[0], rcode)]:
            server.wait_ready("127.0.0.1", PORT, name, code, ad)
        sent, answered = drive(PORT, names, seconds)
        print(f"{phase}: {answered} of {sent} UDP queries answered in {seconds} s")
        if answered == 0:
            server.fail("no query was answered")
        if tcp_seconds:
            sent, answered = drive_tcp(PORT, names, tcp_seconds)
            print(f"{phase}: {answered} of {sent} TCP queries answered in {tcp_seconds} s")
            if answered == 0:
                server.fail("no TCP query was answered")
        server.stop()
    except BaseException:
        server.kill()
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--emulator", default="", help="command that runs BINARY, e.g. qemu-aarch64")
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    profdata = llvm_profdata()
    if os.name == "nt":
        # Ctrl+Break reaches only processes on the sender's console; a job started without
        # one gets one here, and an existing console makes this a no-op.
        import ctypes

        ctypes.windll.kernel32.AllocConsole()

    command = [*shlex.split(args.emulator), str(args.binary.resolve())]
    with tempfile.TemporaryDirectory(prefix="onetdns-pgo-", ignore_cleanup_errors=True) as tmp:
        work = Path(tmp)
        allowed, blocked = write_fixtures(work)
        ed25519_names = write_ed25519_zone(work)
        rsa_names = write_rsa_zone(work)
        missing = [f"x{i:06d}.bench.test" for i in range(ZONE_OWNERS)]
        # Answers from each signing algorithm, and denials proved by NSEC.
        pools = [allowed, ed25519_names, allowed, rsa_names, missing]
        signed_names = [pools[i % 5][i // 5 % len(pools[i % 5])] for i in range(ZONE_OWNERS)]
        signed_probes = [(allowed[0], NOERROR), (ed25519_names[0], NOERROR), (rsa_names[0], NOERROR)]
        cert, key = work / "pgo.crt", work / "pgo.key"
        subprocess.run(
            [*command, "--cli", "cert", "--host", TLS_NAME, "--cert-out", str(cert), "--key-out", str(key)],
            check=True,
            stdout=subprocess.DEVNULL,
            env=dict(os.environ, LLVM_PROFILE_FILE=str(work / "cert-%p.profraw")),
        )
        tls = f'tls_cert = "{cert.as_posix()}"\ntls_key = "{key.as_posix()}"\n'
        signed = "dnssec_sign = true"
        zones = ", ".join(
            [
                f'{{ origin = "test", file = "{(work / "db.test").as_posix()}", {signed} }}',
                f'{{ origin = "ed25519", file = "{(work / "db.ed25519").as_posix()}", {signed}, '
                'dnssec_algorithm = "ed25519" }',
                f'{{ origin = "rsa", file = "{(work / "db.rsa").as_posix()}" }}',
            ]
        )

        write_config(
            work / "zone.toml",
            [f"127.0.0.1:{ZONE_PORT}", f"[{ZONE}]:53"],
            tls
            + "cache_enabled = false\n"
            + f'listen_dot = ["127.0.0.1:{DOT_PORT}", "[{ZONE}]:853"]\n'
            + f'listen_doq = ["127.0.0.1:{DOT_PORT}", "[{ZONE}]:853"]\n'
            + f'listen_doh = ["127.0.0.1:{DOH_PORT}"]\nlisten_doh3 = ["127.0.0.1:{DOH_PORT}"]\n'
            + f'listen_dnscrypt = ["127.0.0.1:{DNSCRYPT_PORT}"]\ndnscrypt_provider_name = "{PROVIDER}"\n'
            + f"zones = [{zones}]\n",
        )
        servers = []
        try:
            zone = Server(command, work / "zone.toml", str(work / "train-zone-%p.profraw"), low_ports=True)
            servers.append(zone)
            zone.wait_ready("127.0.0.1", ZONE_PORT, allowed[0], NOERROR)
            write_root_zone(work, {owner: key_signing_key(ZONE, 53, owner) for owner in ("test.", "ed25519.", "rsa.")})
            write_config(
                work / "root.toml",
                [f"{ROOT}:53"],
                tls
                + "cache_enabled = false\n"
                + f'listen_dot = ["{ROOT}:853"]\nlisten_doq = ["{ROOT}:853"]\n'
                + f'zones = [{{ origin = ".", file = "{(work / "db.root").as_posix()}", {signed} }}]\n',
            )
            root = Server(command, work / "root.toml", str(work / "train-root-%p.profraw"), low_ports=True)
            servers.append(root)
            root.wait_ready(ROOT, 53, "ns.root", NOERROR)
            write_anchor(work / "root.anchor", key_signing_key(ROOT, 53, "."))

            forward = 'backend = "forward"\ndnssec = false\n'
            lists = [(work / name).as_posix() for name in ("blocklist.txt", "hosts.txt")]
            filters = f'blocklists = ["{lists[0]}", "{lists[1]}"]\n'
            plain = f'upstreams = []\nupstream_urls = ["udp://127.0.0.1:{ZONE_PORT}"]\n'
            cache = "cache_enabled = true\ncache_size = 40000\nsharded_cache = false\n"
            no_cache = "cache_enabled = false\n"
            train(command, work, "filter", forward + no_cache + filters + plain, blocked, NXDOMAIN)
            train(command, work, "cache", forward + cache + filters + plain, allowed, tcp_seconds=SHORT_SECONDS)

            encrypted = {
                "dot": f"tls://127.0.0.1:{DOT_PORT}#{TLS_NAME}",
                "doq": f"quic://127.0.0.1:{DOT_PORT}#{TLS_NAME}",
                "doh": f"https://127.0.0.1:{DOH_PORT}/dns-query#{TLS_NAME}",
                "doh3": f"h3://127.0.0.1:{DOH_PORT}/dns-query#{TLS_NAME}",
                "dnscrypt": dnscrypt_stamp(zone.log_path),
            }
            for phase, url in encrypted.items():
                upstream = f'upstreams = []\nupstream_urls = ["{url}"]\n'
                train(
                    command,
                    work,
                    phase,
                    forward + no_cache + upstream,
                    allowed,
                    seconds=SHORT_SECONDS,
                    env={"SSL_CERT_FILE": str(cert)},
                )

            opened, answered, resumed = drive_tls(allowed, SHORT_SECONDS)
            print(f"tls: {answered} of {opened} new connections answered, {resumed} resumed, in {SHORT_SECONDS} s")
            if answered == 0 or resumed == 0:
                zone.fail("the TLS listeners answered no new connection or resumed no session")

            anchor = f'dnssec_anchor_file = "{(work / "root.anchor").as_posix()}"\n'
            recurse = (
                f'backend = "recurse"\nroot_hints = ["{ROOT}"]\ndnssec = true\n'
                f'recurse_allow_server = ["{ROOT}/32", "{ZONE}/128"]\n'
                + anchor
                + "recurse_opportunistic_encryption = true\n"
            )
            recurse_probes = [*signed_probes, (missing[0], NXDOMAIN)]
            train(command, work, "recurse", recurse + no_cache, signed_names, ad=True, probes=recurse_probes)

            # Forwarding validates what a recursive resolver answers. It does not check denial
            # proofs, so a missing name gets no AD there.
            write_config(work / "resolver.toml", [f"127.0.0.1:{RESOLVER_PORT}"], recurse)
            resolver = Server(command, work / "resolver.toml", str(work / "train-resolver-%p.profraw"))
            servers.append(resolver)
            resolver.wait_ready("127.0.0.1", RESOLVER_PORT, allowed[0], NOERROR, ad=True)
            validate = (
                'backend = "forward"\ndnssec = true\n'
                + anchor
                + f'upstreams = []\nupstream_urls = ["udp://127.0.0.1:{RESOLVER_PORT}"]\n'
            )
            train(command, work, "validate", validate + no_cache, signed_names, ad=True, probes=signed_probes)

            for server in reversed(servers):
                server.stop()
            servers.clear()
        finally:
            for server in servers:
                server.kill()

        profiles = sorted(work.glob("train-*.profraw"))
        sizes = [(p.name, p.stat().st_size) for p in profiles]
        expected = 3 + 2 + len(encrypted) + 2
        if len(profiles) != expected or any(size == 0 for _, size in sizes):
            fail(f"expected {expected} non-empty profiles, found {sizes}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        merge = [str(profdata), "merge", "-o", str(args.output), *map(str, profiles)]
        subprocess.run(merge, check=True)
    print(f"wrote {args.output} ({args.output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
