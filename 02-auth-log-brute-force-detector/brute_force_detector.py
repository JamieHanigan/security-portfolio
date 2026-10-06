#!/usr/bin/env python3
"""
Brute-Force Login Detector
--------------------------
Parses a Linux auth log (/var/log/auth.log or a sample copy) and
identifies brute-force login attempts:
  - Failed password attempts grouped by source IP
  - Invalid-user attempts (account enumeration)
  - Accounts targeted across many IPs (password spraying)
  - Successful logins that followed heavy failures (possible compromise)

Usage:
    python brute_force_detector.py samples/auth.log
    python brute_force_detector.py /var/log/auth.log --threshold 10

Note: sample log uses TEST-NET documentation IPs (203.0.113.0/24,
198.51.100.0/24) so the demo data is safe to publish.
"""

import argparse
import re
from collections import Counter, defaultdict

FAILED_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*?"
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*?"
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_log(path):
    fails = defaultdict(list)      # ip -> [(timestamp, user)]
    invalid_users = Counter()      # user -> count
    targets = defaultdict(set)     # user -> set of ips
    successes = []                 # (timestamp, user, ip)
    with open(path, errors="ignore") as fh:
        for line in fh:
            m = FAILED_RE.search(line)
            if m:
                ts = f"{m.group('month')} {m.group('day')} {m.group('time')}"
                fails[m.group("ip")].append((ts, m.group("user")))
                targets[m.group("user")].add(m.group("ip"))
                if "invalid user" in line:
                    invalid_users[m.group("user")] += 1
                continue
            m = ACCEPTED_RE.search(line)
            if m:
                ts = f"{m.group('month')} {m.group('day')} {m.group('time')}"
                successes.append((ts, m.group("user"), m.group("ip")))
    return fails, invalid_users, targets, successes


def report(path, threshold):
    fails, invalid_users, targets, successes = parse_log(path)
    total_fails = sum(len(v) for v in fails.values())

    lines = [
        "=" * 64,
        "BRUTE-FORCE LOGIN ANALYSIS",
        "=" * 64,
        f"Log file:            {path}",
        f"Total failed logins: {total_fails}",
        f"Brute-force cutoff:  {threshold}+ failures from one IP",
        "-" * 64,
        "",
        "TOP SOURCE IPs (failed logins)",
    ]
    for ip, count in Counter({ip: len(v) for ip, v in fails.items()}).most_common(10):
        flag = "  <-- BRUTE FORCE" if count >= threshold else ""
        lines.append(f"  {ip:<18} {count:>4} attempts{flag}")

    brute_ips = {ip for ip, v in fails.items() if len(v) >= threshold}
    lines += ["", "BRUTE-FORCE SOURCES (action recommended)"]
    if brute_ips:
        for ip in sorted(brute_ips):
            attempts = fails[ip]
            first, last = attempts[0][0], attempts[-1][0]
            users = sorted({u for _, u in attempts})
            lines.append(f"  {ip}")
            lines.append(f"    attempts : {len(attempts)}  ({first} -> {last})")
            lines.append(f"    targeting: {', '.join(users[:8])}"
                         + (" ..." if len(users) > 8 else ""))
    else:
        lines.append("  None detected at this threshold.")

    lines += ["", "TOP TARGETED ACCOUNTS (password-spraying check)"]
    for user, ips in sorted(targets.items(), key=lambda kv: len(kv[1]), reverse=True)[:10]:
        note = "  <-- hit from many IPs" if len(ips) >= 3 else ""
        lines.append(f"  {user:<18} targeted from {len(ips)} IP(s){note}")

    if invalid_users:
        lines += ["", "MOST-PROBED INVALID USERNAMES (enumeration)"]
        for user, count in invalid_users.most_common(5):
            lines.append(f"  {user:<18} {count} attempts")

    lines += ["", "POSSIBLE COMPROMISES (success after heavy failures)"]
    compromised = [
        (ts, user, ip) for ts, user, ip in successes
        if ip in brute_ips
    ]
    if compromised:
        for ts, user, ip in compromised:
            lines.append(f"  !! {ts} - '{user}' logged in from {ip} (flagged brute-force source)")
    else:
        lines.append("  None - no successful logins came from flagged brute-force IPs.")

    lines += [
        "",
        "-" * 64,
        "RECOMMENDED ACTIONS",
        "-" * 64,
        "  1. Block brute-force IPs at the firewall: "
        "iptables -A INPUT -s <IP> -j DROP",
        "  2. Enforce key-based SSH auth; disable PasswordAuthentication",
        "     and root login (PermitRootLogin no).",
        "  3. Deploy fail2ban or equivalent to auto-block repeat offenders.",
        "  4. Require MFA for any account that logged in from a flagged IP.",
        "  5. Review the 'possible compromise' list above and force password",
        "     resets where a success followed heavy failures.",
        "=" * 64,
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Detect brute-force SSH logins in an auth log.")
    parser.add_argument("log_file", help="Path to auth.log (or a sample copy)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failures from one IP that counts as brute force (default: 5)")
    args = parser.parse_args()
    print(report(args.log_file, args.threshold))


if __name__ == "__main__":
    main()
