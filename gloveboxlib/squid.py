# glovebox: hardened, network-contained KVM sandboxes for AI agents.
# Copyright (C) 2026 MiCRoPhoBIC
# Licensed under the GNU GPL v3 or later; see LICENSE.
# SPDX-License-Identifier: GPL-3.0-or-later

import time
from urllib.parse import urlsplit

from .config import config
from .common import capture, die, log


def parse_access_line(line):
    # Squid's default "squid" logformat:
    #   time elapsed client result/status size method URL user hier/peer type
    # Returns (time, client, result/status, method, host, port), or None for a
    # line in another format.
    f = line.split()
    if len(f) < 7 or "/" not in f[3]:
        return None
    try:
        ts = float(f[0])
    except ValueError:
        return None
    method, url = f[5], f[6]
    if method == "CONNECT":
        host, _, port = url.rpartition(":")
    else:
        try:
            u = urlsplit(url)
            host = u.hostname or ""
            port = str(u.port or (443 if u.scheme == "https" else 80))
        except ValueError:
            return None
    if not host:
        return None
    return ts, f[2], f[3], method, host.strip("[]"), port


def is_refused(result):
    # TCP_DENIED/403: not in an allowlist (http_access); /409: Host doesn't
    # match the TLS name or the destination (host_verify_strict).
    tag, _, status = result.partition("/")
    return "DENIED" in tag or status == "409"


def cmd_squid_denied(a):
    if not config.proxy_access_log:
        die("proxy_access_log is empty in the config.")
    r = capture(["sudo", "cat", config.proxy_access_log])
    if r.returncode != 0:
        die(f"Could not read proxy_access_log '{config.proxy_access_log}': "
            f"{r.stderr.strip()}", code=2)

    parsed = 0
    refused = {}  # (host, port) -> [count, last time, set of results]
    for line in r.stdout.splitlines():
        entry = parse_access_line(line)
        if entry is None:
            continue
        parsed += 1
        ts, client, result, _method, host, port = entry
        if client != a.ip or not is_refused(result):
            continue
        e = refused.setdefault((host, port), [0, 0.0, set()])
        e[0] += 1
        e[1] = max(e[1], ts)
        e[2].add(result)

    if not parsed and r.stdout.strip():
        die(f"No line of {config.proxy_access_log} is in Squid's default "
            f"\"squid\" logformat, which squid-denied needs.", code=2)
    log(f"Requests from {a.name} ({a.ip}) that Squid refused, per "
        f"{config.proxy_access_log} (rotated logs not included):")
    if not refused:
        print("  none")
        return
    rows = sorted(refused.items(), key=lambda kv: kv[1][1], reverse=True)
    width = max(len(f"{h}:{p}") for (h, p), _ in rows)
    for (host, port), (count, last, results) in rows:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last))
        print(f"  {host + ':' + port:<{width}}  {count:>5}x  last {when}  "
              f"{', '.join(sorted(results))}")
    print()
    print(f"To allow one, add the host to {config.proxy_allowed_domains} (for "
          f"good) or {config.proxy_provision_domains} (for provisioning), then "
          f"`sudo squid -k reconfigure`. /409 means a Host/TLS-name mismatch "
          f"(e.g. domain fronting), which no allowlist entry fixes. Non-443 "
          f"CONNECT ports stay refused by design.")
