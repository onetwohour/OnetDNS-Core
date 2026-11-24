#!/usr/bin/env python3
"""Writes the PGO profile for a release build.

Runs an OnetDNS binary built with -Cprofile-generate on the workloads the profile should cover,
then merges what every instance wrote with the llvm-profdata of the rustc in use: blocked queries
and cache hits behind a filter over UDP and TCP, forwarding over each encrypted transport to a
second instance, and DNSSEC-validated recursion from a local root.

Root hints carry no port, so the root listens on 127.0.0.1:53 and the zone below it on [::1]:53;
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
ROOT = "127.0.0.1"
ZONE = "::1"
TLS_NAME = "pgo.test"
PROVIDER = "2.dnscrypt-cert.pgo.test"
ZONE_OWNERS = 20000
RULES = 100000
BLOCKED_QUERIES = 20000
LOAD_SECONDS = 15
SHORT_SECONDS = 5
# Emulated targets load the blocklist many times slower.
READY_SECONDS = 300
STOP_SECONDS = 120
NXDOMAIN = 3
NOERROR = 0
A = 1
DNSKEY = 48


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def name_wire(name: str) -> bytes:
    labels = [label for label in name.lower().split(".") if label]
    return b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\0"


def query(name: str, edns: bool, qtype: int = A, ad: bool = False) -> bytes:
    flags = 0x0100 | (0x0020 if ad else 0)
    header = struct.pack("!HHHHHH", 0, flags, 1, 0, 0, 1 if edns else 0)
    packet = header + name_wire(name) + struct.pack("!HH", qtype, 1)
    if edns:
        packet += b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
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
    rules = "".join(f"||{name}^\n" for name in blocked)
    (work / "blocklist.txt").write_text(rules, encoding="utf-8")
    return allowed, [rng.choice(blocked) for _ in range(BLOCKED_QUERIES)]


def write_root_zone(work: Path, test_key: bytes) -> None:
    zone = [
        "$TTL 86400",
        "@ IN SOA ns.root. hostmaster.root. 1 1800 900 604800 86400",
        "@ IN NS ns.root.",
        f"ns.root. IN A {ROOT}",
        "test. IN NS ns.test.",
        f"ns.test. IN AAAA {ZONE}",
        ds_record("test.", test_key),
    ]
    (work / "db.root").write_text("\n".join(zone) + "\n", encoding="utf-8")


def write_config(path: Path, listen: list[str], extra: str) -> None:
    addresses = ", ".join(f'"{address}"' for address in listen)
    path.write_text(
        f"""mode = "personal"
listen = [{addresses}]
workers = 1
do_udp = true
do_tcp = true
prefetch = false
querylog = false
{extra}""",
        encoding="utf-8",
    )


class Server:
    def __init__(self, command: list[str], config: Path, profile: str, env: dict | None = None) -> None:
        self.log_path = config.with_suffix(".log")
        self.log = self.log_path.open("wb")
        env = dict(os.environ, LLVM_PROFILE_FILE=profile, **(env or {}))
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        self.proc = subprocess.Popen(
            [*command, "run", "--config", str(config), "--no-web", "--no-supervisor"],
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
    packets = [query(name, edns=i % 2 == 1) for i, name in enumerate(names)]
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
) -> None:
    config = work / f"{phase}.toml"
    write_config(config, [f"127.0.0.1:{PORT}"], extra)
    server = Server(command, config, str(work / f"train-{phase}-%p.profraw"), env)
    try:
        server.wait_ready("127.0.0.1", PORT, names[0], rcode, ad)
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
        cert, key = work / "pgo.crt", work / "pgo.key"
        subprocess.run(
            [*command, "--cli", "cert", "--host", TLS_NAME, "--cert-out", str(cert), "--key-out", str(key)],
            check=True,
            stdout=subprocess.DEVNULL,
            env=dict(os.environ, LLVM_PROFILE_FILE=str(work / "cert-%p.profraw")),
        )
        tls = f'tls_cert = "{cert.as_posix()}"\ntls_key = "{key.as_posix()}"\n'
        signed = "dnssec_sign = true"

        write_config(
            work / "zone.toml",
            [f"127.0.0.1:{ZONE_PORT}", f"[{ZONE}]:53"],
            tls
            + "cache_enabled = false\n"
            + f'listen_dot = ["127.0.0.1:{DOT_PORT}", "[{ZONE}]:853"]\n'
            + f'listen_doq = ["127.0.0.1:{DOT_PORT}", "[{ZONE}]:853"]\n'
            + f'listen_doh = ["127.0.0.1:{DOH_PORT}"]\nlisten_doh3 = ["127.0.0.1:{DOH_PORT}"]\n'
            + f'listen_dnscrypt = ["127.0.0.1:{DNSCRYPT_PORT}"]\ndnscrypt_provider_name = "{PROVIDER}"\n'
            + f'zones = [{{ origin = "test", file = "{(work / "db.test").as_posix()}", {signed} }}]\n',
        )
        servers = []
        try:
            zone = Server(command, work / "zone.toml", str(work / "train-zone-%p.profraw"))
            servers.append(zone)
            zone.wait_ready("127.0.0.1", ZONE_PORT, allowed[0], NOERROR)
            write_root_zone(work, key_signing_key(ZONE, 53, "test."))
            write_config(
                work / "root.toml",
                [f"{ROOT}:53"],
                tls
                + "cache_enabled = false\n"
                + f'listen_dot = ["{ROOT}:853"]\nlisten_doq = ["{ROOT}:853"]\n'
                + f'zones = [{{ origin = ".", file = "{(work / "db.root").as_posix()}", {signed} }}]\n',
            )
            root = Server(command, work / "root.toml", str(work / "train-root-%p.profraw"))
            servers.append(root)
            root.wait_ready(ROOT, 53, "ns.root", NOERROR)
            write_anchor(work / "root.anchor", key_signing_key(ROOT, 53, "."))

            forward = 'backend = "forward"\ndnssec = false\n'
            filters = f'blocklists = ["{(work / "blocklist.txt").as_posix()}"]\n'
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

            recurse = (
                f'backend = "recurse"\nroot_hints = ["{ROOT}"]\ndnssec = true\n'
                f'recurse_allow_server = ["{ROOT}/32", "{ZONE}/128"]\n'
                f'dnssec_anchor_file = "{(work / "root.anchor").as_posix()}"\n'
                "recurse_opportunistic_encryption = true\n"
            )
            train(command, work, "recurse", recurse + no_cache, allowed, ad=True)

            for server in reversed(servers):
                server.stop()
            servers.clear()
        finally:
            for server in servers:
                server.kill()

        profiles = sorted(work.glob("train-*.profraw"))
        sizes = [(p.name, p.stat().st_size) for p in profiles]
        expected = 2 + 2 + len(encrypted) + 1
        if len(profiles) != expected or any(size == 0 for _, size in sizes):
            fail(f"expected {expected} non-empty profiles, found {sizes}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        merge = [str(profdata), "merge", "-o", str(args.output), *map(str, profiles)]
        subprocess.run(merge, check=True)
    print(f"wrote {args.output} ({args.output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
