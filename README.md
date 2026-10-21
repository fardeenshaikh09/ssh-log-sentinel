# 🛡️ SSH Log Sentinel

A small, dependency-free **blue-team** tool that reads Linux SSH authentication logs and flags brute-force attacks, username spraying, and — most importantly — **successful logins that follow a burst of failures** (a likely compromise).

Pure Python 3.9+ standard library. No installs. Read-only: it never changes your firewall.

## Why this exists

Tools like Hydra make it trivial to hammer an SSH server. This project is the defender's side of that coin: given `/var/log/auth.log`, which IPs are attacking, which usernames are they guessing, and did anyone actually get in?

## Features

| Detection | What it means |
|---|---|
| **Brute-force** | ≥ N failed logins from one IP inside a sliding time window |
| **Username spraying** | One IP trying many different usernames, even slowly |
| **Possible compromise** | A successful login from an IP *after* it started failing → `CRITICAL` |

- Severity ranking: `CRITICAL` → `HIGH` → `MEDIUM`
- Exports to **JSON** and **CSV** (CSV is hardened against spreadsheet formula injection)
- Prints **suggested** `ufw` block commands — only for validated IP addresses, so a crafted log line can't inject shell syntax
- Exit code `1` when alerts exist, so it works in cron jobs and CI

## Quick start

```bash
git clone https://github.com/<fardeenshaikh09>/ssh-log-sentinel.git
cd ssh-log-sentinel

python3 sentinel.py samples/auth_sample.log --year 2026
```

On a real server:

```bash
sudo python3 sentinel.py /var/log/auth.log --threshold 5 --window 60 --json report.json --suggest-blocks
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--threshold` | 5 | Failures inside the window that trigger an alert |
| `--window` | 60 | Sliding window in seconds |
| `--spray-users` | 5 | Distinct usernames from one IP that count as spraying |
| `--year` | current | Syslog timestamps have no year — set it for old logs |
| `--json FILE` / `--csv FILE` | – | Write the alerts to a file |
| `--suggest-blocks` | off | Print firewall commands (never executes them) |

## Sample output

```text
Parsed 36 SSH events (34 failed, 2 accepted) from 4 unique IPs

SEVERITY  IP ADDRESS         FAILS  PEAK USERS  FIRST SEEN           REASONS
----------------------------------------------------------------------------
CRITICAL  198.51.100.23          8     8     1  2026-10-20 03:41:10  brute-force: 8 failures within 60s; successful login as 'deploy' after failures
HIGH      203.0.113.45          18    18    10  2026-10-20 02:14:00  brute-force: 18 failures within 60s; username spraying: 10 distinct usernames
MEDIUM    203.0.113.99           6     1     6  2026-10-20 11:00:00  username spraying: 6 distinct usernames
```

Notice what it *doesn't* flag: `192.0.2.10` mistyped a password twice and then logged in. That's a normal user, not an attacker.

The sample log uses reserved documentation IP ranges (RFC 5737), so nothing in this repo points at a real host.

## How it works

1. **Parse** — regexes pull `Failed password/publickey` and `Accepted ...` events out of `sshd` lines.
2. **Group** — events are bucketed per source IP.
3. **Detect** — a two-pointer sliding-window scan finds the busiest `--window` seconds per IP in O(n); distinct usernames are counted for spraying.
4. **Correlate** — a successful login at or after an IP's first failure escalates the alert to `CRITICAL`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

17 tests cover parsing edge cases, sliding-window logic, severity rules, false-positive avoidance, CSV injection, and IP validation.

## Ideas to extend it

- Live mode that follows the log (`tail -f` style)
- GeoIP / ASN enrichment for flagged addresses
- Support for `journalctl -u ssh` output and other services (FTP, RDP)
- Email / Slack alerting
- Mapping alerts to MITRE ATT&CK **T1110** (Brute Force)

## Ethical use

This tool is **defensive** and only analyses logs you are authorised to read. Only run it on systems you own or administer.

## Author

**Fardeen Shaikh** — [LinkedIn](https://www.linkedin.com/in/fardeen-shaikh-cyber/)

Released under the [MIT License](LICENSE).
