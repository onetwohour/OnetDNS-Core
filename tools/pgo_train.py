#!/usr/bin/env python3
"""Writes the PGO profile for a release build.

Runs an OnetDNS binary built with -Cprofile-generate on the workloads the profile should favour,
blocked queries and cache hits behind a filter, then merges what it wrote with the llvm-profdata
of the rustc in use.

usage: pgo_train.py [--emulator CMD] BINARY OUTPUT.profdata
"""
from __future__ import annotations

import argparse
import os
import random
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
UPSTREAM_PORT = 15853
ZONE_OWNERS = 20000
RULES = 100000
BLOCKED_QUERIES = 20000
LOAD_SECONDS = 15
# Emulated targets load the blocklist many times slower.
READY_SECONDS = 300
STOP_SECONDS = 120
NXDOMAIN = 3
NOERROR = 0


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def query(name: str, edns: bool) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0x0100, 1, 0, 0, 1 if edns else 0)
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    packet = header + qname + struct.pack("!HH", 1, 1)
    if edns:
        packet += b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
    return packet


def write_fixtures(work: Path) -> tuple[list[str], list[str]]:
    """Writes the zone the upstream serves and the blocklist; returns allowed and blocked names."""
    allowed = [f"h{i:06d}.bench.test" for i in range(ZONE_OWNERS)]
    zone = [
        "$TTL 3600",
        "@ IN SOA ns1.bench.test. hostmaster.bench.test. 1 3600 600 86400 300",
        "@ IN NS ns1.bench.test.",
        "ns1 IN A 127.0.0.1",
    ]
    zone += [f"h{i:06d} IN A 192.0.2.{i % 254 + 1}" for i in range(ZONE_OWNERS)]
    (work / "db.bench.test").write_text("\n".join(zone) + "\n", encoding="utf-8")

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


def write_config(path: Path, port: int, extra: str) -> None:
    path.write_text(
        f"""mode = "personal"
backend = "forward"
listen = ["127.0.0.1:{port}"]
workers = 1
do_udp = true
do_tcp = false
dnssec = false
prefetch = false
querylog = false
{extra}""",
        encoding="utf-8",
    )


class Server:
    def __init__(self, command: list[str], config: Path, log: Path, profile: str) -> None:
        self.log_path = log
        self.log = log.open("wb")
        env = dict(os.environ, LLVM_PROFILE_FILE=profile)
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

    def wait_ready(self, port: int, name: str, rcode: int) -> None:
        packet = query(name, edns=False)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        deadline = time.monotonic() + READY_SECONDS
        try:
            while time.monotonic() < deadline:
                if self.proc.poll() is not None:
                    self.fail(f"server exited with {self.proc.returncode} before answering")
                try:
                    sock.sendto(packet, ("127.0.0.1", port))
                    reply = sock.recv(4096)
                    if reply[3] & 0x0F == rcode:
                        return
                except OSError:
                    pass
                time.sleep(0.25)
        finally:
            sock.close()
        self.fail(f"{name} did not get rcode {rcode} on port {port} within {READY_SECONDS} s")

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
    """Keeps `window` queries in flight for `seconds`; returns queries sent and answered."""
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


def llvm_profdata() -> Path:
    sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip()
    info = subprocess.check_output(["rustc", "-vV"], text=True)
    host = next(line.split()[1] for line in info.splitlines() if line.startswith("host:"))
    name = "llvm-profdata.exe" if os.name == "nt" else "llvm-profdata"
    tool = Path(sysroot, "lib", "rustlib", host, "bin", name)
    if not tool.is_file():
        fail(f"{tool} not found; install it with: rustup component add llvm-tools")
    return tool


def train(command: list[str], work: Path, config: str, names: list[str], rcode: int) -> None:
    profile = str(work / "train-%p.profraw")
    server = Server(command, work / config, work / f"{config}.log", profile)
    try:
        server.wait_ready(PORT, names[0], rcode)
        sent, answered = drive(PORT, names, LOAD_SECONDS)
        print(f"{config}: {answered} of {sent} queries answered in {LOAD_SECONDS} s")
        if answered == 0:
            server.fail("no query was answered")
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
        zone_file = (work / "db.bench.test").as_posix()
        zone = f'zones = [{{ origin = "bench.test", file = "{zone_file}" }}]\n'
        filters = (
            f'blocklists = ["{(work / "blocklist.txt").as_posix()}"]\n'
            f'upstreams = []\nupstream_urls = ["udp://127.0.0.1:{UPSTREAM_PORT}"]\n'
        )
        cache = "cache_enabled = true\ncache_size = 40000\nsharded_cache = false\n"
        write_config(work / "upstream.toml", UPSTREAM_PORT, "cache_enabled = false\n" + zone)
        write_config(work / "filter.toml", PORT, "cache_enabled = false\n" + filters)
        write_config(work / "cache.toml", PORT, cache + filters)

        # The upstream only answers cache misses; its profile is not merged.
        upstream_profile = str(work / "upstream-%p.profraw")
        upstream = Server(command, work / "upstream.toml", work / "upstream.log", upstream_profile)
        try:
            upstream.wait_ready(UPSTREAM_PORT, allowed[0], NOERROR)
            train(command, work, "filter.toml", blocked, NXDOMAIN)
            train(command, work, "cache.toml", allowed, NOERROR)
        finally:
            upstream.kill()

        profiles = sorted(work.glob("train-*.profraw"))
        sizes = [(p.name, p.stat().st_size) for p in profiles]
        if len(profiles) != 2 or any(size == 0 for _, size in sizes):
            fail(f"expected two non-empty profiles, found {sizes}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        merge = [str(profdata), "merge", "-o", str(args.output), *map(str, profiles)]
        subprocess.run(merge, check=True)
    print(f"wrote {args.output} ({args.output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
