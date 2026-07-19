#!/usr/bin/env python3
"""Long-running paired comparison of classic AMT and AMTQ.

The sender emits the same sequence through two multicast groups. The receiver
records both paths, and the report command compares paired samples so a stable
clock offset between the source and receiver cancels out.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import os
import re
import selectors
import signal
import socket
import sqlite3
import statistics
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import zlib
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


MAGIC = b"AMTQAB01"
VERSION = 1
HEADER = struct.Struct("!8s16sQBBHQ")
CRC = struct.Struct("!I")
MIN_PROBE_SIZE = HEADER.size + CRC.size
MAX_UDP_PAYLOAD = 65_507

PATH_CODES = {"classic": 0, "amtq": 1}
CODE_PATHS = {value: key for key, value in PATH_CODES.items()}

SOURCE_FIELDS = [
    "run_id",
    "path",
    "sequence",
    "send_ns",
    "payload_bytes",
    "send_ok",
    "error",
]
RECEIVE_FIELDS = [
    "run_id",
    "path",
    "sequence",
    "send_ns",
    "recv_ns",
    "payload_bytes",
    "valid",
    "crc_ok",
    "expected_path",
    "source_ip",
    "source_port",
]
RESOURCE_FIELDS = [
    "sample_ns",
    "name",
    "pid",
    "alive",
    "cpu_percent",
    "cpu_seconds",
    "rss_kib",
    "vsz_kib",
]

STOP = False


def request_stop(_signum: int, _frame: object) -> None:
    global STOP
    STOP = True


def install_signal_handlers() -> None:
    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)


def duration_seconds(value: str) -> float:
    suffixes = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}
    value = value.strip().lower()
    if re.fullmatch(r"\d+(?:\.\d+)?", value):
        seconds = float(value)
    else:
        parts = re.findall(r"(\d+(?:\.\d+)?)([smhd])", value)
        if not parts or "".join(number + suffix for number, suffix in parts) != value:
            raise argparse.ArgumentTypeError(
                "expected a duration such as 30s, 10m, 6h, or 6h10m"
            )
        seconds = sum(float(number) * suffixes[suffix] for number, suffix in parts)
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("duration must be positive and finite")
    return seconds


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a number") from error
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive and finite")
    return parsed


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected an integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def udp_port(value: str) -> int:
    parsed = positive_int(value)
    if parsed > 65_535:
        raise argparse.ArgumentTypeError("UDP port must not exceed 65535")
    return parsed


def udp_payload_size(value: str) -> int:
    parsed = positive_int(value)
    if parsed > MAX_UDP_PAYLOAD:
        raise argparse.ArgumentTypeError(
            f"UDP payload must not exceed {MAX_UDP_PAYLOAD} bytes"
        )
    return parsed


def multicast_ttl(value: str) -> int:
    parsed = positive_int(value)
    if parsed > 255:
        raise argparse.ArgumentTypeError("multicast TTL must not exceed 255")
    return parsed


def probe_sizes(value: str) -> list[int]:
    try:
        sizes = [int(part.strip()) for part in value.split(",") if part.strip()]
    except ValueError as error:
        raise argparse.ArgumentTypeError("probe sizes must be comma-separated integers") from error
    if not sizes:
        raise argparse.ArgumentTypeError("at least one probe size is required")
    for size in sizes:
        if not MIN_PROBE_SIZE <= size <= MAX_UDP_PAYLOAD:
            raise argparse.ArgumentTypeError(
                f"probe size must be between {MIN_PROBE_SIZE} and {MAX_UDP_PAYLOAD} bytes"
            )
    return sizes


def multicast_v4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected an IPv4 multicast address") from error
    if address.version != 4 or not address.is_multicast:
        raise argparse.ArgumentTypeError("expected an IPv4 multicast address")
    return value


def ipv4_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected an IPv4 address") from error
    if address.version != 4:
        raise argparse.ArgumentTypeError("expected an IPv4 address")
    return value


def output_file(path: str, fields: list[str]) -> tuple[Any, csv.DictWriter]:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    handle = output.open("w", newline="", encoding="utf-8")
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    return handle, writer


def build_probe(
    run_id: uuid.UUID,
    sequence: int,
    path: str,
    payload_size: int,
) -> tuple[bytes, int]:
    packet = bytearray(payload_size)
    send_ns = time.time_ns()
    HEADER.pack_into(
        packet,
        0,
        MAGIC,
        run_id.bytes,
        sequence,
        PATH_CODES[path],
        VERSION,
        payload_size,
        send_ns,
    )
    CRC.pack_into(packet, payload_size - CRC.size, zlib.crc32(packet[:-CRC.size]) & 0xFFFFFFFF)
    return bytes(packet), send_ns


def decode_probe(packet: bytes) -> tuple[dict[str, Any] | None, str | None]:
    if len(packet) < MIN_PROBE_SIZE:
        return None, "short packet"
    (
        magic,
        run_bytes,
        sequence,
        path_code,
        version,
        declared_size,
        send_ns,
    ) = HEADER.unpack_from(packet)
    if magic != MAGIC:
        return None, "foreign packet"
    path = CODE_PATHS.get(path_code)
    if path is None:
        return None, "unknown path"
    expected_crc = CRC.unpack_from(packet, len(packet) - CRC.size)[0]
    actual_crc = zlib.crc32(packet[:-CRC.size]) & 0xFFFFFFFF
    valid = version == VERSION and declared_size == len(packet)
    return (
        {
            "run_id": str(uuid.UUID(bytes=run_bytes)),
            "path": path,
            "sequence": sequence,
            "send_ns": send_ns,
            "payload_bytes": len(packet),
            "valid": valid,
            "crc_ok": expected_crc == actual_crc,
        },
        None,
    )


def sender_socket(interface: str, ttl: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface))
    # BSD multicast socket options use one-byte values; Linux accepts these too.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", ttl))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, struct.pack("B", 1))
    return sock


def run_send(args: argparse.Namespace) -> int:
    install_signal_handlers()
    run_id = uuid.UUID(args.run_id) if args.run_id else uuid.uuid4()
    destinations = {
        "classic": (args.classic_group, args.classic_port),
        "amtq": (args.amtq_group, args.amtq_port),
    }
    sock = sender_socket(args.interface, args.ttl)
    handle, writer = output_file(args.output, SOURCE_FIELDS)
    interval = 1.0 / args.pps
    started = time.monotonic()
    deadline = started + args.duration
    next_pair = started
    next_report = started + args.progress_interval
    sequence = 0
    sent = defaultdict(int)
    failed = defaultdict(int)

    print(
        json.dumps(
            {
                "role": "send",
                "run_id": str(run_id),
                "duration_seconds": args.duration,
                "pairs_per_second": args.pps,
                "probe_sizes": args.sizes,
                "interface": args.interface,
                "destinations": destinations,
                "output": args.output,
            },
            sort_keys=True,
        ),
        flush=True,
    )

    try:
        while not STOP:
            now = time.monotonic()
            if now >= deadline:
                break
            if now < next_pair:
                time.sleep(min(next_pair - now, 0.05))
                continue
            if now - next_pair > interval:
                next_pair = now

            size = args.sizes[sequence % len(args.sizes)]
            paths = ("classic", "amtq") if sequence % 2 == 0 else ("amtq", "classic")
            for path in paths:
                packet, send_ns = build_probe(run_id, sequence, path, size)
                error_text = ""
                try:
                    sock.sendto(packet, destinations[path])
                    ok = True
                    sent[path] += 1
                except OSError as error:
                    ok = False
                    error_text = str(error)
                    failed[path] += 1
                writer.writerow(
                    {
                        "run_id": str(run_id),
                        "path": path,
                        "sequence": sequence,
                        "send_ns": send_ns,
                        "payload_bytes": size,
                        "send_ok": int(ok),
                        "error": error_text,
                    }
                )

            sequence += 1
            next_pair += interval
            now = time.monotonic()
            if now >= next_report:
                handle.flush()
                elapsed = now - started
                print(
                    f"sender elapsed={elapsed:.0f}s pairs={sequence} "
                    f"classic_sent={sent['classic']} amtq_sent={sent['amtq']} "
                    f"failures={failed['classic'] + failed['amtq']}",
                    flush=True,
                )
                next_report = now + args.progress_interval
    finally:
        handle.flush()
        handle.close()
        sock.close()

    elapsed = time.monotonic() - started
    print(
        f"sender stopped run_id={run_id} elapsed={elapsed:.1f}s pairs={sequence} "
        f"classic_sent={sent['classic']} amtq_sent={sent['amtq']} "
        f"failures={failed['classic'] + failed['amtq']}",
        flush=True,
    )
    return 0 if failed["classic"] + failed["amtq"] == 0 else 1


def run_blast(args: argparse.Namespace) -> int:
    install_signal_handlers()
    destinations = {
        "classic": (args.classic_group, args.classic_port),
        "amtq": (args.amtq_group, args.amtq_port),
    }
    sock = sender_socket(args.interface, args.ttl)
    payload = bytes(args.size)
    started = time.monotonic()
    deadline = started + args.duration
    next_report = started + args.progress_interval
    sequence = 0
    sent = defaultdict(int)
    failed = defaultdict(int)

    print(
        json.dumps(
            {
                "role": "blast",
                "duration_seconds": args.duration,
                "pairs_per_second": args.pps,
                "payload_bytes": args.size,
                "interface": args.interface,
                "destinations": destinations,
            },
            sort_keys=True,
        ),
        flush=True,
    )

    try:
        while not STOP:
            now = time.monotonic()
            if now >= deadline:
                break
            due = math.floor((now - started) * args.pps) + 1
            if sequence >= due:
                time.sleep(min((sequence - due + 1) / args.pps, 0.001))
                continue

            while sequence < due:
                paths = ("classic", "amtq") if sequence % 2 == 0 else ("amtq", "classic")
                for path in paths:
                    try:
                        sock.sendto(payload, destinations[path])
                        sent[path] += 1
                    except OSError:
                        failed[path] += 1
                sequence += 1

            now = time.monotonic()
            if now >= next_report:
                elapsed = now - started
                print(
                    f"blast elapsed={elapsed:.0f}s pairs={sequence} "
                    f"achieved_pps={sequence / elapsed:.1f} "
                    f"failures={failed['classic'] + failed['amtq']}",
                    flush=True,
                )
                next_report = now + args.progress_interval
    finally:
        sock.close()

    elapsed = time.monotonic() - started
    print(
        f"blast stopped elapsed={elapsed:.1f}s pairs={sequence} "
        f"achieved_pps={sequence / elapsed:.1f} "
        f"classic_sent={sent['classic']} amtq_sent={sent['amtq']} "
        f"failures={failed['classic'] + failed['amtq']}",
        flush=True,
    )
    return 0 if failed["classic"] + failed["amtq"] == 0 else 1


def receiver_socket(group: str, port: int, interface: str, receive_buffer: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
    sock.bind(("0.0.0.0", port))
    membership = struct.pack("=4s4s", socket.inet_aton(group), socket.inet_aton(interface))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    sock.setblocking(False)
    return sock


def run_receive(args: argparse.Namespace) -> int:
    install_signal_handlers()
    expected_run = str(uuid.UUID(args.run_id)) if args.run_id else None
    endpoints = {
        "classic": (args.classic_group, args.classic_port),
        "amtq": (args.amtq_group, args.amtq_port),
    }
    selector = selectors.DefaultSelector()
    sockets: list[socket.socket] = []
    for path, (group, port) in endpoints.items():
        sock = receiver_socket(group, port, args.interface, args.receive_buffer)
        sockets.append(sock)
        selector.register(sock, selectors.EVENT_READ, path)

    handle, writer = output_file(args.output, RECEIVE_FIELDS)
    process_started = time.monotonic()
    startup_deadline = process_started + args.startup_timeout
    capture_started: float | None = None
    capture_deadline: float | None = None
    next_report = process_started + args.progress_interval
    received = defaultdict(int)
    invalid = 0
    foreign = 0
    startup_timed_out = False

    print(
        json.dumps(
            {
                "role": "receive",
                "run_id": expected_run or "any",
                "duration_seconds": args.duration,
                "startup_timeout_seconds": args.startup_timeout,
                "interface": args.interface,
                "endpoints": endpoints,
                "output": args.output,
            },
            sort_keys=True,
        ),
        flush=True,
    )

    try:
        while not STOP:
            now = time.monotonic()
            active_deadline = capture_deadline or startup_deadline
            if now >= active_deadline:
                startup_timed_out = capture_started is None
                break
            events = selector.select(min(1.0, active_deadline - now))
            for key, _mask in events:
                sock = key.fileobj
                expected_path = key.data
                while True:
                    try:
                        packet, source = sock.recvfrom(65_535)
                    except BlockingIOError:
                        break
                    recv_ns = time.time_ns()
                    decoded, reason = decode_probe(packet)
                    if decoded is None:
                        if reason == "foreign packet":
                            foreign += 1
                        else:
                            invalid += 1
                        continue
                    if expected_run is not None and decoded["run_id"] != expected_run:
                        foreign += 1
                        continue
                    path_matches = decoded["path"] == expected_path
                    if not decoded["valid"] or not decoded["crc_ok"] or not path_matches:
                        invalid += 1
                    elif capture_started is None:
                        capture_started = time.monotonic()
                        capture_deadline = capture_started + args.duration
                        print(
                            f"receiver capture started run_id={decoded['run_id']} "
                            f"duration={args.duration:.1f}s",
                            flush=True,
                        )
                    received[expected_path] += 1
                    writer.writerow(
                        {
                            **decoded,
                            "recv_ns": recv_ns,
                            "expected_path": int(path_matches),
                            "source_ip": source[0],
                            "source_port": source[1],
                        }
                    )

            now = time.monotonic()
            if now >= next_report:
                handle.flush()
                if capture_started is None:
                    print(
                        f"receiver waiting elapsed={now - process_started:.0f}s "
                        f"invalid={invalid} foreign={foreign}",
                        flush=True,
                    )
                else:
                    print(
                        f"receiver elapsed={now - capture_started:.0f}s "
                        f"classic={received['classic']} amtq={received['amtq']} "
                        f"invalid={invalid} foreign={foreign}",
                        flush=True,
                    )
                next_report = now + args.progress_interval
    finally:
        handle.flush()
        handle.close()
        for sock in sockets:
            selector.unregister(sock)
            sock.close()
        selector.close()

    stopped = time.monotonic()
    capture_elapsed = (
        stopped - capture_started if capture_started is not None else 0.0
    )
    if startup_timed_out:
        print(
            f"receiver startup timed out after {args.startup_timeout:.1f}s "
            "without a valid probe",
            file=sys.stderr,
            flush=True,
        )
    print(
        f"receiver stopped elapsed={capture_elapsed:.1f}s classic={received['classic']} "
        f"amtq={received['amtq']} invalid={invalid} foreign={foreign}",
        flush=True,
    )
    return 2 if startup_timed_out else 0


def process_spec(value: str) -> tuple[str, int]:
    try:
        name, raw_pid = value.rsplit("=", 1)
        pid = int(raw_pid)
    except (ValueError, TypeError) as error:
        raise argparse.ArgumentTypeError("expected NAME=PID") from error
    if not name or pid <= 0:
        raise argparse.ArgumentTypeError("expected a non-empty NAME and positive PID")
    return name, pid


def parse_cpu_duration(value: str) -> float:
    value = value.strip()
    days = 0
    if "-" in value:
        raw_days, value = value.split("-", 1)
        days = int(raw_days)
    parts = value.split(":")
    if len(parts) == 2:
        hours = 0
        minutes, seconds = parts
    elif len(parts) == 3:
        hours, minutes, seconds = parts
    else:
        raise ValueError("invalid process CPU duration")
    total = (
        days * 86_400
        + int(hours) * 3_600
        + int(minutes) * 60
        + float(seconds)
    )
    if not math.isfinite(total) or total < 0:
        raise ValueError("invalid process CPU duration")
    return total


def linux_process_cpu_seconds(pid: int) -> float | None:
    if not sys.platform.startswith("linux"):
        return None
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        fields = raw[raw.rfind(")") + 2 :].split()
        ticks = int(fields[11]) + int(fields[12])
        return ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError):
        return None


def read_process(
    pid: int,
) -> tuple[bool, float | None, float | None, int | None, int | None]:
    result = subprocess.run(
        [
            "ps",
            "-p",
            str(pid),
            "-o",
            "pid=",
            "-o",
            "%cpu=",
            "-o",
            "rss=",
            "-o",
            "vsz=",
            "-o",
            "time=",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    fields = result.stdout.split()
    if result.returncode != 0 or len(fields) < 5:
        return False, None, None, None, None
    try:
        cpu_seconds = linux_process_cpu_seconds(pid)
        if cpu_seconds is None:
            cpu_seconds = parse_cpu_duration(fields[4])
        return True, float(fields[1]), cpu_seconds, int(fields[2]), int(fields[3])
    except ValueError:
        return False, None, None, None, None


def run_sample(args: argparse.Namespace) -> int:
    install_signal_handlers()
    handle, writer = output_file(args.output, RESOURCE_FIELDS)
    started = time.monotonic()
    deadline = started + args.duration
    next_sample = started
    samples = 0

    try:
        while not STOP:
            now = time.monotonic()
            if now >= deadline:
                break
            if now < next_sample:
                time.sleep(min(next_sample - now, 0.1))
                continue
            sample_ns = time.time_ns()
            for name, pid in args.process:
                alive, cpu, cpu_seconds, rss, vsz = read_process(pid)
                writer.writerow(
                    {
                        "sample_ns": sample_ns,
                        "name": name,
                        "pid": pid,
                        "alive": int(alive),
                        "cpu_percent": "" if cpu is None else cpu,
                        "cpu_seconds": "" if cpu_seconds is None else cpu_seconds,
                        "rss_kib": "" if rss is None else rss,
                        "vsz_kib": "" if vsz is None else vsz,
                    }
                )
            samples += 1
            if samples % 30 == 0:
                handle.flush()
                print(f"resource sampler samples={samples}", flush=True)
            next_sample += args.interval
    finally:
        handle.flush()
        handle.close()

    print(f"resource sampler stopped samples={samples} output={args.output}", flush=True)
    return 0


def as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes"}


def percentile(values: Iterable[float], fraction: float) -> float | None:
    ordered = sorted(values)
    return percentile_sorted(ordered, fraction)


def percentile_sorted(ordered: list[float], fraction: float) -> float | None:
    if not ordered:
        return None
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def metric(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def mean(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


def iter_csv(path: str) -> Iterable[dict[str, str]]:
    with Path(path).open(newline="", encoding="utf-8") as handle:
        yield from csv.DictReader(handle)


def select_run_id(
    source_path: str,
    receive_path: str,
    requested: str | None,
) -> str:
    if requested:
        return str(uuid.UUID(requested))
    source_ids = {row["run_id"] for row in iter_csv(source_path)}
    receive_ids = {row["run_id"] for row in iter_csv(receive_path)}
    common = source_ids & receive_ids
    if len(common) != 1:
        raise ValueError(
            "logs do not contain exactly one common run ID; pass --run-id explicitly"
        )
    return common.pop()


def summarize_resources(paths: list[str]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "cpu": [],
            "rss": [],
            "samples": 0,
            "cpu_seconds": 0.0,
            "has_cpu_delta": False,
        }
    )
    previous_cpu: dict[tuple[str, str], tuple[int, float]] = {}
    for path in paths:
        for row in iter_csv(path):
            if as_bool(row["alive"]):
                name = row["name"]
                values = grouped[name]
                values["samples"] += 1
                if row["rss_kib"]:
                    values["rss"].append(float(row["rss_kib"]))
                cpu_seconds = row.get("cpu_seconds", "")
                if cpu_seconds:
                    current = (int(row["sample_ns"]), float(cpu_seconds))
                    key = (name, row["pid"])
                    previous = previous_cpu.get(key)
                    if (
                        previous is not None
                        and current[0] > previous[0]
                        and current[1] >= previous[1]
                    ):
                        elapsed = (current[0] - previous[0]) / 1_000_000_000.0
                        consumed = current[1] - previous[1]
                        values["cpu"].append(100.0 * consumed / elapsed)
                        values["cpu_seconds"] += consumed
                        values["has_cpu_delta"] = True
                    previous_cpu[key] = current
                elif row["cpu_percent"]:
                    values["cpu"].append(float(row["cpu_percent"]))
    summary: dict[str, dict[str, Any]] = {}
    for name, values in grouped.items():
        cpu = values["cpu"]
        rss = values["rss"]
        summary[name] = {
            "samples": values["samples"],
            "cpu_mean_percent": mean(cpu),
            "cpu_p95_percent": percentile(cpu, 0.95),
            "cpu_seconds": (
                values["cpu_seconds"] if values["has_cpu_delta"] else None
            ),
            "rss_max_mib": max(rss) / 1024.0 if rss else None,
            "rss_growth_mib": (rss[-1] - rss[0]) / 1024.0 if len(rss) >= 2 else None,
        }
    return summary


def initialize_report_database(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        PRAGMA journal_mode = OFF;
        PRAGMA synchronous = OFF;
        PRAGMA temp_store = FILE;
        PRAGMA locking_mode = EXCLUSIVE;

        CREATE TABLE sent (
            path TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            send_ns INTEGER NOT NULL,
            PRIMARY KEY (path, sequence)
        ) WITHOUT ROWID;

        CREATE TABLE received (
            path TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            recv_ns INTEGER NOT NULL,
            copies INTEGER NOT NULL,
            PRIMARY KEY (path, sequence)
        ) WITHOUT ROWID;
        """
    )


def load_report_database(
    connection: sqlite3.Connection,
    source_path: str,
    receive_path: str,
    run_id: str,
) -> dict[str, int]:
    batch_size = 10_000
    sent_batch: list[tuple[str, int, int]] = []
    for row in iter_csv(source_path):
        if (
            row["run_id"] != run_id
            or row["path"] not in PATH_CODES
            or not as_bool(row["send_ok"])
        ):
            continue
        sent_batch.append((row["path"], int(row["sequence"]), int(row["send_ns"])))
        if len(sent_batch) >= batch_size:
            connection.executemany(
                "INSERT OR IGNORE INTO sent(path, sequence, send_ns) VALUES (?, ?, ?)",
                sent_batch,
            )
            sent_batch.clear()
    if sent_batch:
        connection.executemany(
            "INSERT OR IGNORE INTO sent(path, sequence, send_ns) VALUES (?, ?, ?)",
            sent_batch,
        )
    connection.commit()

    invalid = defaultdict(int)
    receive_batch: list[tuple[str, int, int]] = []
    upsert = """
        INSERT INTO received(path, sequence, recv_ns, copies)
        VALUES (?, ?, ?, 1)
        ON CONFLICT(path, sequence) DO UPDATE SET
            recv_ns = MIN(received.recv_ns, excluded.recv_ns),
            copies = received.copies + 1
    """
    for row in iter_csv(receive_path):
        if row["run_id"] != run_id or row["path"] not in PATH_CODES:
            continue
        path = row["path"]
        if not (
            as_bool(row["valid"])
            and as_bool(row["crc_ok"])
            and as_bool(row["expected_path"])
        ):
            invalid[path] += 1
            continue
        receive_batch.append((path, int(row["sequence"]), int(row["recv_ns"])))
        if len(receive_batch) >= batch_size:
            connection.executemany(upsert, receive_batch)
            receive_batch.clear()
    if receive_batch:
        connection.executemany(upsert, receive_batch)
    connection.commit()
    return dict(invalid)


def scalar(connection: sqlite3.Connection, query: str, parameters: tuple[Any, ...]) -> int:
    row = connection.execute(query, parameters).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def path_summary(
    path: str,
    connection: sqlite3.Connection,
    invalid: int,
) -> dict[str, Any]:
    sent = scalar(connection, "SELECT COUNT(*) FROM sent WHERE path = ?", (path,))
    received = scalar(
        connection,
        """
        SELECT COUNT(*)
        FROM sent AS s
        JOIN received AS r USING (path, sequence)
        WHERE s.path = ?
        """,
        (path,),
    )
    duplicates = scalar(
        connection,
        """
        SELECT COALESCE(SUM(r.copies - 1), 0)
        FROM sent AS s
        JOIN received AS r USING (path, sequence)
        WHERE s.path = ?
        """,
        (path,),
    )

    high_water = -1
    reordered = 0
    arrival_cursor = connection.execute(
        """
        SELECT r.sequence, r.recv_ns
        FROM received AS r
        JOIN sent AS s USING (path, sequence)
        WHERE r.path = ?
        ORDER BY r.recv_ns, r.sequence
        """,
        (path,),
    )
    previous_arrival_ns = None
    max_arrival_gap_ms = None
    for sequence, recv_ns in arrival_cursor:
        if sequence < high_water:
            reordered += 1
        high_water = max(high_water, sequence)
        if previous_arrival_ns is not None:
            gap_ms = (recv_ns - previous_arrival_ns) / 1_000_000.0
            max_arrival_gap_ms = (
                gap_ms
                if max_arrival_gap_ms is None
                else max(max_arrival_gap_ms, gap_ms)
            )
        previous_arrival_ns = recv_ns

    latency_ms: list[float] = []
    jitter_ms: list[float] = []
    previous_sequence = None
    previous_latency = None
    for sequence, send_ns, recv_ns in connection.execute(
        """
        SELECT s.sequence, s.send_ns, r.recv_ns
        FROM sent AS s
        JOIN received AS r USING (path, sequence)
        WHERE s.path = ?
        ORDER BY s.sequence
        """,
        (path,),
    ):
        latency = (recv_ns - send_ns) / 1_000_000.0
        latency_ms.append(latency)
        if previous_sequence is not None and sequence == previous_sequence + 1:
            jitter_ms.append(abs(latency - previous_latency))
        previous_sequence = sequence
        previous_latency = latency

    longest_burst = 0
    current_burst = 0
    previous_sequence = None
    for sequence, was_received in connection.execute(
        """
        SELECT s.sequence, r.sequence IS NOT NULL
        FROM sent AS s
        LEFT JOIN received AS r USING (path, sequence)
        WHERE s.path = ?
        ORDER BY s.sequence
        """,
        (path,),
    ):
        if previous_sequence is not None and sequence != previous_sequence + 1:
            current_burst = 0
        if was_received:
            current_burst = 0
        else:
            current_burst += 1
            longest_burst = max(longest_burst, current_burst)
        previous_sequence = sequence

    lost = sent - received
    ordered_latency = sorted(latency_ms)
    ordered_jitter = sorted(jitter_ms)
    return {
        "sent": sent,
        "received": received,
        "lost": lost,
        "loss_percent": (100.0 * lost / sent) if sent else None,
        "duplicates": duplicates,
        "corrupt_or_misrouted": invalid,
        "reordered": reordered,
        "longest_loss_burst": longest_burst,
        "latency_mean_ms": mean(latency_ms),
        "latency_p50_ms": percentile_sorted(ordered_latency, 0.50),
        "latency_p95_ms": percentile_sorted(ordered_latency, 0.95),
        "latency_p99_ms": percentile_sorted(ordered_latency, 0.99),
        "jitter_p95_ms": percentile_sorted(ordered_jitter, 0.95),
        "max_arrival_gap_ms": max_arrival_gap_ms,
    }


def paired_summary(connection: sqlite3.Connection) -> dict[str, Any]:
    paired_delta_ms = [
        (amtq_recv - amtq_send - classic_recv + classic_send) / 1_000_000.0
        for classic_send, classic_recv, amtq_send, amtq_recv in connection.execute(
            """
            SELECT sc.send_ns, rc.recv_ns, sa.send_ns, ra.recv_ns
            FROM sent AS sc
            JOIN sent AS sa
              ON sa.path = 'amtq' AND sa.sequence = sc.sequence
            JOIN received AS rc
              ON rc.path = 'classic' AND rc.sequence = sc.sequence
            JOIN received AS ra
              ON ra.path = 'amtq' AND ra.sequence = sc.sequence
            WHERE sc.path = 'classic'
            ORDER BY sc.sequence
            """
        )
    ]
    delivery_counts = connection.execute(
        """
        SELECT
          COALESCE(SUM(CASE WHEN rc.sequence IS NOT NULL
                            AND ra.sequence IS NULL THEN 1 ELSE 0 END), 0),
          COALESCE(SUM(CASE WHEN ra.sequence IS NOT NULL
                            AND rc.sequence IS NULL THEN 1 ELSE 0 END), 0),
          COALESCE(SUM(CASE WHEN rc.sequence IS NULL
                            AND ra.sequence IS NULL THEN 1 ELSE 0 END), 0)
        FROM sent AS sc
        JOIN sent AS sa
          ON sa.path = 'amtq' AND sa.sequence = sc.sequence
        LEFT JOIN received AS rc
          ON rc.path = 'classic' AND rc.sequence = sc.sequence
        LEFT JOIN received AS ra
          ON ra.path = 'amtq' AND ra.sequence = sc.sequence
        WHERE sc.path = 'classic'
        """
    ).fetchone()
    ordered_delta = sorted(paired_delta_ms)

    return {
        "samples": len(paired_delta_ms),
        "amtq_minus_classic_mean_ms": mean(paired_delta_ms),
        "amtq_minus_classic_p50_ms": percentile_sorted(ordered_delta, 0.50),
        "amtq_minus_classic_p95_ms": percentile_sorted(ordered_delta, 0.95),
        "amtq_minus_classic_p99_ms": percentile_sorted(ordered_delta, 0.99),
        "amtq_earlier_percent": (
            100.0 * sum(value < 0 for value in paired_delta_ms) / len(paired_delta_ms)
            if paired_delta_ms
            else None
        ),
        "classic_only_received": int(delivery_counts[0]),
        "amtq_only_received": int(delivery_counts[1]),
        "both_lost": int(delivery_counts[2]),
    }


def run_report(args: argparse.Namespace) -> int:
    try:
        run_id = select_run_id(args.source, args.receive, args.run_id)
    except ValueError as error:
        print(f"report error: {error}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="amtq-ab-report-", dir=args.work_dir) as temporary:
        connection = sqlite3.connect(str(Path(temporary) / "samples.sqlite3"))
        try:
            initialize_report_database(connection)
            invalid = load_report_database(
                connection,
                args.source,
                args.receive,
                run_id,
            )
            summaries = {
                path: path_summary(path, connection, invalid.get(path, 0))
                for path in ("classic", "amtq")
            }
            paired = paired_summary(connection)
        finally:
            connection.close()

    resources = summarize_resources(args.resource_log)

    report = {
        "run_id": run_id,
        "paths": summaries,
        "paired": paired,
        "resources": resources,
    }
    if args.json_out:
        output = Path(args.json_out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("# AMT versus AMTQ long-run report")
    print()
    print(f"Run ID: `{run_id}`")
    print()
    print("## Delivery")
    print()
    print(
        "| Path | Sent | Received | Loss | Longest loss burst | "
        "Duplicates | Reordered | Invalid |"
    )
    print("|---|---:|---:|---:|---:|---:|---:|---:|")
    for path in ("classic", "amtq"):
        item = summaries[path]
        loss = metric(item["loss_percent"])
        print(
            f"| {path} | {item['sent']} | {item['received']} | {loss}% | "
            f"{item['longest_loss_burst']} | {item['duplicates']} | {item['reordered']} | "
            f"{item['corrupt_or_misrouted']} |"
        )

    print()
    print("## Timing")
    print()
    print(
        "Apparent one-way latency requires synchronized source and receiver clocks. "
        "Jitter and the paired AMTQ-minus-AMT result do not require zero clock offset."
    )
    print()
    print("| Path | Mean | P50 | P95 | P99 | Jitter P95 | Maximum arrival gap |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for path in ("classic", "amtq"):
        item = summaries[path]
        print(
            f"| {path} | {metric(item['latency_mean_ms'])} ms | "
            f"{metric(item['latency_p50_ms'])} ms | {metric(item['latency_p95_ms'])} ms | "
            f"{metric(item['latency_p99_ms'])} ms | {metric(item['jitter_p95_ms'])} ms | "
            f"{metric(item['max_arrival_gap_ms'])} ms |"
        )

    print()
    print("## Paired Result")
    print()
    print(
        "Each value is `(AMTQ receive - AMTQ send) - (AMT receive - AMT send)` "
        "for the same sequence. Negative values favor AMTQ."
    )
    print()
    print("| Samples | Mean | P50 | P95 | P99 | AMTQ earlier |")
    print("|---:|---:|---:|---:|---:|---:|")
    print(
        f"| {paired['samples']} | "
        f"{metric(paired['amtq_minus_classic_mean_ms'])} ms | "
        f"{metric(paired['amtq_minus_classic_p50_ms'])} ms | "
        f"{metric(paired['amtq_minus_classic_p95_ms'])} ms | "
        f"{metric(paired['amtq_minus_classic_p99_ms'])} ms | "
        f"{metric(paired['amtq_earlier_percent'])}% |"
    )
    print()
    print(
        f"Classic-only deliveries: {paired['classic_only_received']}; "
        f"AMTQ-only deliveries: {paired['amtq_only_received']}; "
        f"lost on both paths: {paired['both_lost']}."
    )

    if resources:
        print()
        print("## Resources")
        print()
        print(
            "| Process | Samples | CPU time | Mean CPU | P95 CPU | Peak RSS | RSS change |"
        )
        print("|---|---:|---:|---:|---:|---:|---:|")
        for name, item in sorted(resources.items()):
            print(
                f"| {name} | {item['samples']} | {metric(item['cpu_seconds'])} s | "
                f"{metric(item['cpu_mean_percent'])}% | "
                f"{metric(item['cpu_p95_percent'])}% | {metric(item['rss_max_mib'])} MiB | "
                f"{metric(item['rss_growth_mib'])} MiB |"
            )
    return 0


def run_self_test(_args: argparse.Namespace) -> int:
    assert duration_seconds("1m") == 60.0
    assert probe_sizes("64,1200") == [64, 1200]
    assert parse_cpu_duration("0:37.81") == 37.81
    assert parse_cpu_duration("01:02:03") == 3_723.0
    assert parse_cpu_duration("2-01:02:03") == 176_523.0
    run_id = uuid.uuid4()
    packet, send_ns = build_probe(run_id, 7, "amtq", 1200)
    decoded, error = decode_probe(packet)
    assert error is None and decoded is not None
    assert decoded["run_id"] == str(run_id)
    assert decoded["path"] == "amtq"
    assert decoded["sequence"] == 7
    assert decoded["send_ns"] == send_ns
    assert decoded["valid"] and decoded["crc_ok"]
    corrupted = bytearray(packet)
    corrupted[-5] ^= 1
    decoded, error = decode_probe(corrupted)
    assert error is None and decoded is not None and not decoded["crc_ok"]

    connection = sqlite3.connect(":memory:")
    initialize_report_database(connection)
    connection.executemany(
        "INSERT INTO sent(path, sequence, send_ns) VALUES (?, ?, ?)",
        [
            ("classic", 0, 0),
            ("amtq", 0, 1_000_000),
            ("classic", 1, 100_000_000),
            ("amtq", 1, 101_000_000),
            ("classic", 2, 200_000_000),
            ("amtq", 2, 201_000_000),
        ],
    )
    connection.executemany(
        "INSERT INTO received(path, sequence, recv_ns, copies) VALUES (?, ?, ?, ?)",
        [
            ("classic", 0, 10_000_000, 1),
            ("amtq", 0, 10_000_000, 1),
            ("classic", 1, 110_000_000, 2),
            ("amtq", 1, 110_000_000, 1),
            ("amtq", 2, 210_000_000, 1),
        ],
    )
    classic = path_summary("classic", connection, 0)
    amtq = path_summary("amtq", connection, 0)
    paired = paired_summary(connection)
    connection.close()
    assert classic["lost"] == 1 and classic["duplicates"] == 1
    assert amtq["lost"] == 0
    assert paired["samples"] == 2
    assert paired["amtq_minus_classic_mean_ms"] == -1.0
    assert paired["amtq_only_received"] == 1
    print("self-test passed")
    return 0


def common_probe_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--classic-group", type=multicast_v4, default="239.250.10.1")
    parser.add_argument("--classic-port", type=udp_port, default=5501)
    parser.add_argument("--amtq-group", type=multicast_v4, default="239.250.10.2")
    parser.add_argument("--amtq-port", type=udp_port, default=5502)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Long-running paired comparison of classic AMT and AMTQ",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    send = subcommands.add_parser("send", help="send paired multicast probes")
    common_probe_options(send)
    send.add_argument("--interface", type=ipv4_address, required=True)
    send.add_argument("--duration", type=duration_seconds, default=duration_seconds("6h"))
    send.add_argument("--pps", type=positive_float, default=50.0, help="probe pairs per second")
    send.add_argument("--sizes", type=probe_sizes, default=[1200])
    send.add_argument("--ttl", type=multicast_ttl, default=16)
    send.add_argument("--run-id", help="optional UUID; generated by default")
    send.add_argument("--output", default="amtq-ab-source.csv")
    send.add_argument("--progress-interval", type=positive_float, default=30.0)
    send.set_defaults(handler=run_send)

    blast = subcommands.add_parser(
        "blast",
        help="send paired multicast traffic without per-packet logging",
    )
    common_probe_options(blast)
    blast.add_argument("--interface", type=ipv4_address, required=True)
    blast.add_argument("--duration", type=duration_seconds, default=duration_seconds("30s"))
    blast.add_argument("--pps", type=positive_float, default=1_000.0, help="pairs per second")
    blast.add_argument("--size", type=udp_payload_size, default=1_200)
    blast.add_argument("--ttl", type=multicast_ttl, default=16)
    blast.add_argument("--progress-interval", type=positive_float, default=5.0)
    blast.set_defaults(handler=run_blast)

    receive = subcommands.add_parser("receive", help="receive both multicast probe paths")
    common_probe_options(receive)
    receive.add_argument("--interface", type=ipv4_address, required=True)
    receive.add_argument("--duration", type=duration_seconds, default=duration_seconds("6h10m"))
    receive.add_argument(
        "--startup-timeout",
        type=duration_seconds,
        default=duration_seconds("10m"),
        help="maximum wait for the first valid probe",
    )
    receive.add_argument("--run-id", help="optional UUID filter")
    receive.add_argument("--output", default="amtq-ab-receiver.csv")
    receive.add_argument("--receive-buffer", type=positive_int, default=4 * 1024 * 1024)
    receive.add_argument("--progress-interval", type=positive_float, default=30.0)
    receive.set_defaults(handler=run_receive)

    sample = subcommands.add_parser("sample", help="sample CPU and RSS for named PIDs")
    sample.add_argument("--process", type=process_spec, action="append", required=True)
    sample.add_argument("--duration", type=duration_seconds, default=duration_seconds("6h"))
    sample.add_argument("--interval", type=positive_float, default=1.0)
    sample.add_argument("--output", default="amtq-ab-resources.csv")
    sample.set_defaults(handler=run_sample)

    report = subcommands.add_parser("report", help="summarize sender and receiver logs")
    report.add_argument("--source", required=True)
    report.add_argument("--receive", required=True)
    report.add_argument("--run-id")
    report.add_argument("--resource-log", action="append", default=[])
    report.add_argument("--json-out")
    report.add_argument(
        "--work-dir",
        help="directory for the temporary disk-backed report database",
    )
    report.set_defaults(handler=run_report)

    self_test = subcommands.add_parser("self-test", help="run local codec checks")
    self_test.set_defaults(handler=run_self_test)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
