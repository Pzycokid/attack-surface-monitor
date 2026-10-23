"""
Passive attack surface monitor.

For each in-scope domain it:
  1. Collects subdomains from public Certificate Transparency logs (crt.sh).
  2. Resolves each subdomain to its current IP addresses.
  3. Compares the result with the previous snapshot and reports what changed.

Everything here is passive (public CT logs + normal DNS lookups). Only run it against
domains you own or are authorised to monitor; the scope file enforces that list.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
USER_AGENT = "attack-surface-monitor/0.1 (+https://github.com/Pzycokid/attack-surface-monitor)"


# ---------- data collection ----------

def fetch_ct_entries(domain: str, timeout: int = 30) -> list[dict]:
    """Download Certificate Transparency entries for *.domain from crt.sh."""
    req = urllib.request.Request(CRT_SH_URL.format(domain=domain), headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_subdomains(ct_entries: list[dict], domain: str) -> set[str]:
    """Pull clean, in-scope hostnames out of crt.sh name_value fields."""
    domain = domain.lower().strip(".")
    found: set[str] = set()
    for entry in ct_entries:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.").strip(".")
            if name == domain or name.endswith("." + domain):
                found.add(name)
    return found


def resolve(hostname: str) -> list[str]:
    """Return the sorted IPv4/IPv6 addresses for a hostname, or [] if it does not resolve."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


# ---------- snapshots and diffing ----------

def build_snapshot(domain: str, subdomains: set[str], resolver=resolve) -> dict:
    return {
        "domain": domain,
        "taken_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hosts": {host: resolver(host) for host in sorted(subdomains)},
    }


def diff_snapshots(old: dict | None, new: dict) -> dict:
    """Return new hosts, removed hosts, and hosts whose IPs changed."""
    old_hosts = (old or {}).get("hosts", {})
    new_hosts = new["hosts"]
    added = sorted(set(new_hosts) - set(old_hosts))
    removed = sorted(set(old_hosts) - set(new_hosts))
    changed = {
        h: {"before": old_hosts[h], "after": new_hosts[h]}
        for h in sorted(set(old_hosts) & set(new_hosts))
        if old_hosts[h] != new_hosts[h]
    }
    newly_live = sorted(h for h in added if new_hosts[h])
    return {"added": added, "newly_live": newly_live, "removed": removed, "ip_changed": changed}


def format_report(domain: str, snapshot: dict, diff: dict, first_run: bool) -> str:
    hosts = snapshot["hosts"]
    live = sum(1 for ips in hosts.values() if ips)
    lines = [
        f"# Attack surface report: {domain}",
        f"Taken at {snapshot['taken_at']}",
        "",
        f"- Hostnames seen in CT logs: **{len(hosts)}**",
        f"- Currently resolving (live): **{live}**",
        "",
    ]
    if first_run:
        lines.append("_First run: baseline saved. Future runs will report changes._")
        return "\n".join(lines) + "\n"

    def section(title, items):
        lines.append(f"## {title} ({len(items)})")
        lines.extend(f"- `{i}`" for i in items) if items else lines.append("_none_")
        lines.append("")

    section("New hostnames", diff["added"])
    section("New hostnames that are live (review first)", diff["newly_live"])
    section("Hostnames no longer in CT results", diff["removed"])
    lines.append(f"## IP address changes ({len(diff['ip_changed'])})")
    if diff["ip_changed"]:
        for host, c in diff["ip_changed"].items():
            lines.append(f"- `{host}`: {c['before'] or 'unresolved'} → {c['after'] or 'unresolved'}")
    else:
        lines.append("_none_")
    return "\n".join(lines) + "\n"


# ---------- scope and CLI ----------

def load_scope(path: Path) -> list[str]:
    """Scope file: one domain per line, '#' for comments."""
    domains = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            domains.append(line)
    if not domains:
        raise SystemExit(f"Scope file {path} lists no domains.")
    return domains


def run(scope_file: Path, data_dir: Path) -> int:
    data_dir.mkdir(parents=True, exist_ok=True)
    total_new_live = 0
    for domain in load_scope(scope_file):
        print(f"[*] {domain}: querying Certificate Transparency logs...", file=sys.stderr)
        subdomains = extract_subdomains(fetch_ct_entries(domain), domain)
        snapshot = build_snapshot(domain, subdomains)

        snap_path = data_dir / f"{domain}.json"
        old = json.loads(snap_path.read_text()) if snap_path.exists() else None
        diff = diff_snapshots(old, snapshot)
        report = format_report(domain, snapshot, diff, first_run=old is None)

        (data_dir / f"{domain}-report.md").write_text(report, encoding="utf-8")
        snap_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        print(report)
        total_new_live += len(diff["newly_live"])
    # Non-zero exit when new live hosts appear, so cron / CI can alert on it.
    return 2 if total_new_live else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Passive attack surface monitor for domains you own.")
    parser.add_argument("--scope", type=Path, default=Path("scope.txt"), help="file listing in-scope domains")
    parser.add_argument("--data", type=Path, default=Path("data"), help="where snapshots and reports are kept")
    args = parser.parse_args(argv)
    return run(args.scope, args.data)


if __name__ == "__main__":
    sys.exit(main())
