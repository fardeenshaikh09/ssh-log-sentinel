#!/usr/bin/env python3
"""
SSH Log Sentinel
================
A small, dependency-free defensive tool that analyses Linux SSH authentication
logs (e.g. /var/log/auth.log) and flags:

  * brute-force attacks      - many failed logins from one IP in a short window
  * username spraying        - one IP trying many different usernames
  * possible compromise      - a SUCCESSFUL login from an IP that was already
                               hammering the server with failures

The tool only READS logs. It never touches firewall rules; block commands are
printed as suggestions for a human to review.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Iterable, Iterator, Optional

__version__ = "1.0.0"

# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
_PREFIX = (
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd(?:\[\d+\])?:\s+"
)

FAILED_RE = re.compile(
    _PREFIX
    + r"Failed (?:password|publickey) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
ACCEPTED_RE = re.compile(
    _PREFIX
    + r"Accepted (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>\S+) port \d+"
)


@dataclass(frozen=True)
class Event:
    time: datetime
    kind: str  # "failed" or "accepted"
    user: str
    ip: str
    invalid_user: bool = False


def parse_line(line: str, year: int) -> Optional[Event]:
    """Turn one syslog line into an Event, or None if it is not relevant."""
    for kind, pattern in (("failed", FAILED_RE), ("accepted", ACCEPTED_RE)):
        match = pattern.match(line)
        if not match:
            continue
        try:
            when = datetime.strptime(f"{year} {match['ts']}", "%Y %b %d %H:%M:%S")
        except ValueError:  # e.g. Feb 29 in a non-leap year
            return None
        invalid = bool(match.groupdict().get("invalid"))
        return Event(when, kind, match["user"], match["ip"], invalid)
    return None


def parse_log(lines: Iterable[str], year: int) -> Iterator[Event]:
    for line in lines:
        event = parse_line(line, year)
        if event:
            yield event


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}


@dataclass
class Alert:
    ip: str
    severity: str
    total_failures: int
    peak_failures_in_window: int
    first_seen: str
    last_seen: str
    usernames_tried: list[str]
    invalid_user_attempts: int
    compromised_user: Optional[str] = None
    reasons: list[str] = field(default_factory=list)


def peak_in_window(times: list[datetime], window_seconds: int) -> int:
    """Largest number of events inside any sliding window (two-pointer scan)."""
    times = sorted(times)
    left = best = 0
    for right, current in enumerate(times):
        while (current - times[left]).total_seconds() > window_seconds:
            left += 1
        best = max(best, right - left + 1)
    return best


def analyze(
    events: Iterable[Event],
    threshold: int = 5,
    window: int = 60,
    spray_users: int = 5,
) -> list[Alert]:
    failures: dict[str, list[Event]] = defaultdict(list)
    successes: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        (failures if ev.kind == "failed" else successes)[ev.ip].append(ev)

    alerts: list[Alert] = []
    for ip, fails in failures.items():
        fails.sort(key=lambda e: e.time)
        times = [e.time for e in fails]
        peak = peak_in_window(times, window)
        users = sorted({e.user for e in fails})

        reasons: list[str] = []
        if peak >= threshold:
            reasons.append(f"brute-force: {peak} failures within {window}s")
        if len(users) >= spray_users:
            reasons.append(f"username spraying: {len(users)} distinct usernames")
        if not reasons:
            continue

        # Did this address eventually get in?
        breach = next((s for s in sorted(successes.get(ip, []), key=lambda e: e.time)
                       if s.time >= times[0]), None)
        if breach:
            severity = "CRITICAL"
            reasons.append(f"successful login as '{breach.user}' after failures")
        elif peak >= threshold * 3:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        alerts.append(
            Alert(
                ip=ip,
                severity=severity,
                total_failures=len(fails),
                peak_failures_in_window=peak,
                first_seen=times[0].isoformat(sep=" "),
                last_seen=times[-1].isoformat(sep=" "),
                usernames_tried=users,
                invalid_user_attempts=sum(e.invalid_user for e in fails),
                compromised_user=breach.user if breach else None,
                reasons=reasons,
            )
        )

    alerts.sort(key=lambda a: (SEVERITY_RANK[a.severity], -a.total_failures))
    return alerts


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def csv_safe(value: object) -> str:
    """Neutralise spreadsheet formula injection (=, +, -, @) in CSV cells."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def render_table(alerts: list[Alert]) -> str:
    if not alerts:
        return "No suspicious activity detected."
    header = f"{'SEVERITY':<9} {'IP ADDRESS':<18} {'FAILS':>5} {'PEAK':>5} {'USERS':>5}  FIRST SEEN           REASONS"
    rows = [header, "-" * len(header)]
    for a in alerts:
        rows.append(
            f"{a.severity:<9} {a.ip:<18} {a.total_failures:>5} "
            f"{a.peak_failures_in_window:>5} {len(a.usernames_tried):>5}  "
            f"{a.first_seen:<19}  {'; '.join(a.reasons)}"
        )
    return "\n".join(rows)


def write_json(alerts: list[Alert], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(a) for a in alerts], fh, indent=2)


def write_csv(alerts: list[Alert], path: str) -> None:
    columns = [
        "severity", "ip", "total_failures", "peak_failures_in_window",
        "first_seen", "last_seen", "usernames_tried", "compromised_user", "reasons",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(columns)
        for a in alerts:
            row = asdict(a)
            row["usernames_tried"] = ", ".join(a.usernames_tried)
            row["reasons"] = "; ".join(a.reasons)
            writer.writerow([csv_safe(row[c] if row[c] is not None else "") for c in columns])


def block_suggestions(alerts: list[Alert]) -> list[str]:
    """Firewall commands for a human to review. Only valid IPs are emitted,
    so a malicious log line can never smuggle shell syntax into a command."""
    lines = ["# Review before running - these are suggestions only."]
    for a in alerts:
        try:
            ip = str(ipaddress.ip_address(a.ip))
        except ValueError:
            lines.append(f"# skipped {a.ip!r}: not a valid IP address")
            continue
        lines.append(f"sudo ufw deny from {ip} to any port 22    # {a.severity}")
    return lines


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Detect SSH brute-force attacks in Linux auth logs.",
    )
    p.add_argument("logfile", help="path to auth.log (use '-' to read stdin)")
    p.add_argument("--threshold", type=int, default=5,
                   help="failed logins inside the window that trigger an alert (default 5)")
    p.add_argument("--window", type=int, default=60,
                   help="sliding window in seconds (default 60)")
    p.add_argument("--spray-users", type=int, default=5,
                   help="distinct usernames from one IP that count as spraying (default 5)")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="year of the log (syslog timestamps omit it; default: current year)")
    p.add_argument("--json", metavar="FILE", help="also write alerts to a JSON file")
    p.add_argument("--csv", metavar="FILE", help="also write alerts to a CSV file")
    p.add_argument("--suggest-blocks", action="store_true",
                   help="print (never run) firewall commands for flagged IPs")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if min(args.threshold, args.window, args.spray_users) < 1:
        print("error: --threshold, --window and --spray-users must be >= 1", file=sys.stderr)
        return 2

    try:
        if args.logfile == "-":
            events = list(parse_log(sys.stdin, args.year))
        else:
            with open(args.logfile, encoding="utf-8", errors="replace") as fh:
                events = list(parse_log(fh, args.year))
    except OSError as exc:
        print(f"error: cannot read log file: {exc}", file=sys.stderr)
        return 2

    failed = sum(e.kind == "failed" for e in events)
    print(f"Parsed {len(events)} SSH events ({failed} failed, {len(events) - failed} accepted) "
          f"from {len({e.ip for e in events})} unique IPs\n")

    alerts = analyze(events, args.threshold, args.window, args.spray_users)
    print(render_table(alerts))

    if args.json:
        write_json(alerts, args.json)
    if args.csv:
        write_csv(alerts, args.csv)
    if args.suggest_blocks and alerts:
        print("\n" + "\n".join(block_suggestions(alerts)))

    return 1 if alerts else 0  # non-zero exit lets CI / cron jobs react


if __name__ == "__main__":
    sys.exit(main())
