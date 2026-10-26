# glovebox: hardened, network-contained KVM sandboxes for AI agents.
# Copyright (C) 2026 MiCRoPhoBIC
# Licensed under the GNU GPL v3 or later; see LICENSE.
# SPDX-License-Identifier: GPL-3.0-or-later

"""host-check: is the host set up as glovebox expects, now and after a
reboot, and does anything else on it get in the way?

Read-only, except --probe: that attaches a temporary network namespace to
the bridge, sends test traffic from an address of each egress mode through
the host's real firewalls (glovebox's and any other), and removes it again.

Other firewalls can't open what glovebox's tables drop (in netfilter a
packet must pass every base chain of a hook, and a drop anywhere wins), so
while our tables are loaded containment holds. What other rules can do is
block what we allow; they're listed here, and --probe shows whether they
actually do.
"""

import datetime
import ipaddress
import json
import os
import signal
import sys

from . import journal
from .config import config
from .common import (capture, die, is_private_address, log, nft_set_contains,
                     nft_set_json, parse_n, private_allow_rules, read_root,
                     resolve_ip, resolve_subnet, root_exists)
from .hostsetup import (CA_CRT, GUARD_DEST, GUARD_TABLE, NFT_DEST, NFT_TABLES,
                        NFT_UNIT, PARTS, PLANNERS, Plan, forward_filters,
                        host_tool, ip_forward_on, other_interfaces,
                        package_manager, proxy_endpoint)


class Report:
    def __init__(self):
        self.sections = []  # (title, rows)
        self.failed = False

    def section(self, title):
        rows = []
        self.sections.append((title, rows))
        log(title)
        return rows

    def add(self, rows, status, what):
        rows.append((status, what))
        if status == "FAIL":
            self.failed = True
        print(f"    [{status:>4}] {what}", flush=True)


# --- 1. what host-setup would still do --------------------------------------------

def check_setup(report, pm):
    rows = report.section("host-setup: what it would still change")
    for part in PARTS:
        if part == "squid" and not config.proxy:
            report.add(rows, "info", "squid: proxy is off in the config, "
                                     "not checked")
            continue
        plan = Plan([part])
        try:
            PLANNERS[part](plan, pm)
        except SystemExit:
            report.add(rows, "FAIL", f"{part}: can't be checked (see the "
                                     f"error above)")
            continue
        steps = [s for s in plan.steps() if not s.check]
        for s in steps:
            report.add(rows, "FAIL", f"{part}: not set up: {s.what}")
        if not steps:
            report.add(rows, "ok", f"{part}: as host-setup sets it up")
        for _, _, notes in plan.sections:
            for note in notes:
                if not note.endswith(("is up to date.", "Nothing to do.")):
                    report.add(rows, "info", f"{part}: {note.splitlines()[0]}")


# --- 2. the live state ------------------------------------------------------------

def nft_normalized(prefix):
    """glovebox's tables (forward_guard's too) as `nft -j` shows them,
    without handles; None for a table that isn't loaded."""
    out = {}
    for t in NFT_TABLES + (GUARD_TABLE,):
        r = capture(prefix + ["nft", "-j", "list", "table", *t])
        if r.returncode != 0:
            out[t] = None
            continue
        objs = []
        for item in json.loads(r.stdout).get("nftables", []):
            (kind, body), = item.items()
            if kind == "metainfo":
                continue
            objs.append((kind, {k: v for k, v in body.items() if k != "handle"}))
        out[t] = objs
    return out


TABLE_ROLE = {
    "inet": "nothing filters the bridge, so the VMs can reach the host and "
            "the LAN",
    "ip": "no NAT, so the sandboxes have no internet",
    "bridge": "the VMs aren't isolated from each other",
}


def obj_label(kind, body):
    if kind == "rule":
        return f"rule in chain {body.get('chain')}: {body.get('comment', '')}".rstrip(": ")
    return f"{kind} {body.get('name')}"


def check_nft_loaded(report, rows):
    if not root_exists(NFT_DEST):
        report.add(rows, "FAIL", f"{NFT_DEST} is missing, so the loaded rules "
                                 f"can't be compared with it")
        return
    ns = f"gbnftcmp{os.getpid()}"
    try:
        if capture(["sudo", "ip", "netns", "add", ns]).returncode != 0:
            report.add(rows, "warn", "could not create a scratch network "
                                     "namespace to compare the rules in")
            return
        r = capture(["sudo", "ip", "netns", "exec", ns, "nft", "-f", NFT_DEST])
        if r.returncode != 0:
            report.add(rows, "FAIL", f"{NFT_DEST} doesn't load: "
                                     f"{r.stderr.strip()}")
            return
        want = nft_normalized(["sudo", "ip", "netns", "exec", ns])
    finally:
        capture(["sudo", "ip", "netns", "del", ns])
    have = nft_normalized(["sudo"])
    for t in NFT_TABLES:
        name = " ".join(t)
        if have[t] is None:
            report.add(rows, "FAIL", f"table {name} is not loaded: "
                                     f"{TABLE_ROLE[t[0]]} (sudo systemctl "
                                     f"restart {NFT_UNIT})")
        elif have[t] != want[t]:
            gone = {obj_label(*o) for o in want[t] if o not in have[t]}
            new = {obj_label(*o) for o in have[t] if o not in want[t]}
            diffs = ([f"changed: {x}" for x in sorted(gone & new)]
                     + [f"missing: {x}" for x in sorted(gone - new)]
                     + [f"extra: {x}" for x in sorted(new - gone)])
            report.add(rows, "FAIL", f"table {name} differs from {NFT_DEST} "
                       f"(changed by hand?): " + "; ".join(diffs[:5])
                       + f". Reload: sudo systemctl restart {NFT_UNIT}")
        else:
            report.add(rows, "ok", f"table {name} is loaded as in {NFT_DEST}")
    # forward_guard: optional, so loaded exactly when its file is there.
    name = " ".join(GUARD_TABLE)
    if have[GUARD_TABLE] == want[GUARD_TABLE]:
        if want[GUARD_TABLE] is not None:
            report.add(rows, "ok", f"table {name} (forward_guard) is loaded "
                                   f"as in {GUARD_DEST}")
    elif want[GUARD_TABLE] is None:
        report.add(rows, "FAIL", f"table {name} (forward_guard) is loaded, "
                                 f"but {GUARD_DEST} isn't there. Reload: "
                                 f"sudo systemctl restart {NFT_UNIT}")
    else:
        report.add(rows, "FAIL", f"table {name} (forward_guard) is "
                                 + ("not loaded" if have[GUARD_TABLE] is None
                                    else "changed by hand")
                                 + f", though {GUARD_DEST} is there. Reload: "
                                   f"sudo systemctl restart {NFT_UNIT}")


def check_live(report):
    rows = report.section("Live state")
    with open("/proc/sys/net/ipv4/ip_forward") as f:
        fwd = f.read().strip()
    report.add(rows, "ok" if fwd == "1" else "FAIL",
               f"net.ipv4.ip_forward = {fwd}"
               + ("" if fwd == "1" else ": the sandboxes have no internet"))

    r = capture(["ip", "-j", "-4", "addr", "show", "dev", config.bridge])
    addrs = []
    if r.returncode == 0:
        for link in json.loads(r.stdout or "[]"):
            addrs += [f"{a['local']}/{a['prefixlen']}" for a in link.get("addr_info", [])]
    want = str(ipaddress.ip_interface(config.host_address))
    report.add(rows, "ok" if want in addrs else "FAIL",
               f"bridge {config.bridge} has {want}" if want in addrs else
               f"bridge {config.bridge} is down or lacks {want} "
               f"(has: {', '.join(addrs) or 'nothing'})")

    check_nft_loaded(report, rows)

    if not config.proxy:
        return
    addr, port = proxy_endpoint()
    ss = capture(["ss", "-ltnH", f"sport = :{port}"]).stdout
    listening = any(f"{addr}:{port}" in ln for ln in ss.splitlines())
    report.add(rows, "ok" if listening else "FAIL",
               f"Squid listens on {addr}:{port}" if listening else
               f"nothing listens on {addr}:{port}: the proxy-only sandboxes "
               f"have no internet")
    if host_tool("squid"):
        r = capture(["sudo", "squid", "-k", "parse"])
        report.add(rows, "ok" if r.returncode == 0 else "FAIL",
                   "squid -k parse: the config is valid" if r.returncode == 0
                   else f"squid -k parse fails: {r.stderr.strip().splitlines()[-1:]}")
    r = capture(["sudo", "openssl", "x509", "-enddate", "-noout", "-in", CA_CRT])
    if r.returncode != 0:
        report.add(rows, "FAIL", f"the CA certificate {CA_CRT} is unreadable")
        return
    end = datetime.datetime.strptime(
        r.stdout.strip().split("=", 1)[1], "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=datetime.timezone.utc)
    days = (end - datetime.datetime.now(datetime.timezone.utc)).days
    report.add(rows, "FAIL" if days < 0 else "warn" if days < 30 else "ok",
               f"the CA expires in {days} days ({end:%Y-%m-%d})" if days >= 0
               else f"the CA expired on {end:%Y-%m-%d}: renew it and recreate "
                    f"the proxy-only VMs")


# --- 3. after a reboot, and the distro's own nftables.service ---------------------

def unit_prop(unit, prop):
    return capture(["systemctl", "show", "-p", prop, "--value",
                    unit]).stdout.strip()


def check_reboot(report):
    rows = report.section("After a reboot, and the distro's nftables.service")
    if unit_prop("nftables.service", "LoadState") != "loaded":
        report.add(rows, "ok", "no nftables.service that could flush "
                               "glovebox's tables")
    else:
        conf = read_root("/etc/nftables.conf") or ""
        flushes = any(ln.strip().startswith("flush ruleset")
                      for ln in conf.splitlines())
        ours = {p: unit_prop(NFT_UNIT, p).split()
                for p in ("PartOf", "ReloadPropagatedFrom", "WantedBy")}
        missing = [p for p, units in ours.items()
                   if "nftables.service" not in units]
        if missing:
            report.add(rows, "FAIL" if flushes else "warn",
                       f"{NFT_UNIT} doesn't follow nftables.service "
                       f"({', '.join(missing)} missing): restarting or "
                       f"reloading it may wipe glovebox's tables and leave "
                       f"the bridge unfiltered. Run ./glovebox host-setup "
                       f"nftables")
        else:
            report.add(rows, "ok", f"{NFT_UNIT} reloads glovebox's tables "
                                   f"whenever nftables.service starts, "
                                   f"restarts or reloads"
                                   + (" (/etc/nftables.conf flushes the "
                                      "ruleset)" if flushes else ""))
        if "flush" in unit_prop("nftables.service", "ExecStop"):
            report.add(rows, "info",
                       "`systemctl stop nftables.service` flushes the whole "
                       "ruleset, glovebox's tables included: running "
                       "sandboxes are unfiltered until it starts again "
                       "(libvirt's hook refuses to start new ones)")
    report.add(rows, "info", "units, autostart, the sysctl file and the "
                             "libvirt hook are covered by the host-setup "
                             "section above")


# --- 4. other firewalls -----------------------------------------------------------

def check_other_firewalls(report):
    rows = report.section("Other firewalls (they can block, not open)")
    if capture(["systemctl", "is-active", "firewalld"]).stdout.strip() == "active":
        report.add(rows, "warn", f"firewalld is active; glovebox doesn't "
                                 f"configure it: make sure it lets "
                                 f"{config.bridge} through (--probe shows it)")

    docker = (capture(["systemctl", "is-active", "docker"]).stdout.strip()
              == "active")
    if host_tool("iptables"):
        fwd = capture(["sudo", "iptables", "-S", "FORWARD"]).stdout
        user = capture(["sudo", "iptables", "-S", "DOCKER-USER"])
        if docker or user.returncode == 0:
            ours = f"-i {config.bridge} -j ACCEPT"
            if "-P FORWARD DROP" in fwd and ours not in fwd + user.stdout:
                report.add(rows, "warn",
                           f"Docker set iptables' FORWARD policy to DROP, "
                           f"which drops the direct sandboxes' traffic. Let "
                           f"it through: sudo iptables -I DOCKER-USER -i "
                           f"{config.bridge} -j ACCEPT (not kept across "
                           f"reboots by itself)")
            else:
                report.add(rows, "ok", "Docker is present and doesn't drop "
                                       f"{config.bridge}'s forwarded traffic")

    if host_tool("iptables-legacy-save"):
        legacy = capture(["sudo", "iptables-legacy-save"]).stdout
        lines = [ln for ln in legacy.splitlines()
                 if ln.startswith("-A") or (ln.startswith(":") and " DROP " in ln)]
        if lines:
            report.add(rows, "warn", f"legacy iptables has {len(lines)} "
                                     f"rule(s)/drop policies, invisible to nft: "
                                     f"check `sudo iptables-legacy-save`")

    r = capture(["sudo", "nft", "-j", "list", "ruleset"])
    if r.returncode != 0:
        report.add(rows, "FAIL", f"nft list ruleset failed: {r.stderr.strip()}")
        return
    foreign = []
    for item in json.loads(r.stdout).get("nftables", []):
        c = item.get("chain")
        if not c or c.get("table") in ("glovebox", GUARD_TABLE[1]) or c.get("hook") not in (
                "input", "forward"):
            continue
        foreign.append(f"{c['family']} {c['table']} {c['name']} "
                       f"(hook {c['hook']}, policy {c.get('policy', 'accept')})")
    for f in foreign:
        report.add(rows, "info", f"also filters: {f}")
    if not foreign:
        report.add(rows, "ok", "no other nftables chains on the input or "
                               "forward hooks")


# --- 5. what else the host forwards ---------------------------------------------

# Interfaces that forward through the host themselves: forward_guard stops
# them.
ROUTING_KINDS = ("bridge", "wireguard", "tun", "veth", "vxlan")


def check_forwarding(report):
    rows = report.section("IP forwarding beyond the sandboxes")
    if not ip_forward_on():
        report.add(rows, "info", "forwarding is off: the host routes nothing "
                                 "(see Live state)")
        return
    ifaces = other_interfaces()
    names = ", ".join(n for n, _ in ifaces) or "none"
    guard = capture(["sudo", "nft", "list", "table",
                     *GUARD_TABLE]).returncode == 0
    if guard:
        report.add(rows, "ok", f"forward_guard is on: the host forwards IPv4 "
                               f"only to and from {config.bridge}")
        routing = [n for n, kind in ifaces if kind in ROUTING_KINDS]
        if routing:
            report.add(rows, "warn", f"forward_guard also drops what these "
                                     f"forward through the host: "
                                     f"{', '.join(routing)} (Docker, other "
                                     f"VM networks, VPNs?). If they should "
                                     f"route: ./glovebox host-setup nftables "
                                     f"--no-forward-guard")
        return
    filters = forward_filters()
    if filters:
        report.add(rows, "ok", f"the host's own firewall filters forwarded "
                               f"traffic: {'; '.join(filters)}. What it "
                               f"lets through between {names} is up to its "
                               f"rules (not analyzed)")
    else:
        report.add(rows, "warn", f"nothing filters forwarded IPv4 except "
                                 f"glovebox's rules for {config.bridge}: the "
                                 f"host routes between {names} for whatever "
                                 f"uses it as a gateway (a LAN device, a VPN "
                                 f"peer). Filter forwarding in your firewall, "
                                 f"or turn on forward_guard: ./glovebox "
                                 f"host-setup nftables --forward-guard")


# --- 6. the journal ---------------------------------------------------------------

def check_journal(report):
    rows = report.section("Changed since host-setup (journal)")
    entries = journal.read()
    if not entries:
        report.add(rows, "info", f"no journal ({journal.JOURNAL}): not set up "
                                 f"with host-setup, or uninstalled")
        return
    latest = {}
    for e in entries:
        if e["type"] == "file":
            latest[e["path"]] = e
    changed = 0
    for path, e in latest.items():
        if not e.get("sha256"):
            continue
        cur = read_root(path)
        if cur is None:
            report.add(rows, "warn", f"{path} is gone")
            changed += 1
        elif journal.sha256(cur) != e["sha256"]:
            report.add(rows, "warn", f"{path} was edited since host-setup "
                                     f"wrote it")
            changed += 1
    if not changed:
        report.add(rows, "ok", f"the {len(latest)} file(s) host-setup wrote "
                               f"are as it left them")


# --- --probe: real traffic from the bridge -------------------------------------

PROBE_PY = r'''
import json, socket, sys
QUERY = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x07example\x03com\x00\x00\x01\x00\x01")
out = []
for kind, ip, port in json.loads(sys.argv[1]):
    s = socket.socket(socket.AF_INET,
                      socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        if kind == "tcp":
            s.connect((ip, port)); r = "open"
        else:
            s.sendto(QUERY, (ip, port)); s.recvfrom(512); r = "reply"
    except ConnectionRefusedError:
        r = "refused"
    except socket.timeout:
        r = "timeout"
    except OSError as e:
        r = "unreachable"
    finally:
        s.close()
    out.append(r)
print(json.dumps(out))
'''


class Probe:
    """A network namespace on the bridge, standing in for a VM."""

    def __init__(self):
        tag = os.getpid() % 100000
        self.ns = f"gbprobe{tag}"
        self.host_if, self.ns_if = f"gbp{tag}h", f"gbp{tag}n"
        self.netns_dir = f"/etc/netns/{self.ns}"

    def run(self, *cmd):
        r = capture(["sudo", *cmd])
        if r.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
        return r.stdout

    def __enter__(self):
        try:
            self.setup()
        except BaseException:
            self.__exit__()
            raise
        return self

    def setup(self):
        self.run("ip", "netns", "add", self.ns)
        self.run("ip", "link", "add", self.host_if, "type", "veth", "peer",
                 "name", self.ns_if, "netns", self.ns)
        self.run("ip", "link", "set", self.host_if, "master", config.bridge, "up")
        self.run("ip", "-n", self.ns, "link", "set", "lo", "up")
        self.run("ip", "-n", self.ns, "link", "set", self.ns_if, "up")
        self.run("ip", "netns", "exec", self.ns, "sysctl", "-qw",
                 "net.ipv6.conf.all.disable_ipv6=1")
        # `ip netns exec` uses this resolv.conf instead of the host's (which
        # often points at 127.0.0.53, unreachable from the namespace).
        self.run("mkdir", "-p", self.netns_dir)
        capture(["sudo", "tee", f"{self.netns_dir}/resolv.conf"],
                input="".join(f"nameserver {n}\n" for n in config.nameservers))

    def __exit__(self, *exc):
        capture(["sudo", "ip", "netns", "del", self.ns])
        capture(["sudo", "ip", "link", "del", self.host_if])
        capture(["sudo", "rm", "-rf", self.netns_dir])
        return False

    def use(self, ip, prefix, gateway):
        self.run("ip", "-n", self.ns, "addr", "flush", "dev", self.ns_if)
        self.run("ip", "-n", self.ns, "addr", "add", f"{ip}/{prefix}", "dev",
                 self.ns_if)
        self.run("ip", "-n", self.ns, "route", "replace", "default", "via",
                 str(gateway))

    def sockets(self, tests):
        r = capture(["sudo", "ip", "netns", "exec", self.ns, sys.executable,
                     "-I", "-c", PROBE_PY, json.dumps(tests)])
        if r.returncode != 0:
            raise RuntimeError(f"probe failed: {r.stderr.strip()}")
        return json.loads(r.stdout)

    def curl(self, url, proxy=None):
        cmd = ["sudo", "ip", "netns", "exec", self.ns, "curl", "-sS", "-o",
               "/dev/null", "-w", "%{http_connect} %{http_code}", "--max-time",
               "15", url]
        if proxy:
            cmd += ["-x", proxy, "--cacert", CA_CRT]
        r = capture(cmd)
        connect, _, code = r.stdout.strip().partition(" ")
        return r.returncode, connect, code


def cleanup_stale_probes():
    for line in capture(["sudo", "ip", "netns", "list"]).stdout.splitlines():
        name = line.split()[0] if line.split() else ""
        if name.startswith("gbprobe"):
            capture(["sudo", "ip", "netns", "del", name])
            capture(["sudo", "rm", "-rf", f"/etc/netns/{name}"])
            log(f"Removed a leftover probe namespace {name}.")


def probe_addresses(subnet, gateway):
    """One unused address per mode (direct, proxy, neither), from the top
    of the subnet down, skipping the addresses of existing VMs."""
    from .vms import domain_states
    used = {resolve_ip(parse_n(n), subnet, gateway, strict=False)
            for n in domain_states()}
    sets = {s: nft_set_json(s) for s in ("direct_internet", "proxy_internet")}
    found = {}
    for addr in reversed(list(subnet.hosts())):
        ip = str(addr)
        if addr == gateway or ip in used:
            continue
        mode = ("direct" if nft_set_contains(sets["direct_internet"], ip) else
                "proxy" if nft_set_contains(sets["proxy_internet"], ip) else
                "none")
        found.setdefault(mode, ip)
        if len(found) == 3:
            break
    return found


def lan_targets(gateway):
    """Private addresses that must stay unreachable: the host via the
    bridge, and the host's LAN gateway and own LAN address."""
    targets = [(str(gateway), 22, "the host (SSH) via the bridge")]
    r = capture(["ip", "-j", "-4", "route", "get", "1.1.1.1"])
    for route in json.loads(r.stdout or "[]")[:1]:
        if route.get("gateway"):
            targets += [(route["gateway"], 53, "the LAN gateway (DNS)"),
                        (route["gateway"], 80, "the LAN gateway (HTTP)")]
        if route.get("prefsrc"):
            targets.append((route["prefsrc"], 22, "the host's LAN address (SSH)"))
    return [t for t in targets
            if ipaddress.ip_address(t[0]).is_private]


def expect_blocked(report, rows, label, result):
    if result in ("timeout", "unreachable"):
        report.add(rows, "ok", f"{label}: blocked")
    elif result == "refused":
        report.add(rows, "warn", f"{label}: answered with a reset (another "
                                 f"firewall rejecting it, or it got through "
                                 f"to a closed port; glovebox drops silently)")
    else:
        report.add(rows, "FAIL", f"{label}: reachable ({result})")


def expect_allowed(report, rows, label, result, why):
    # Allowed on purpose: no answer is a functional problem, not a breach.
    if result == "open":
        report.add(rows, "ok", f"{label}: reachable, allowed by {why}")
    else:
        report.add(rows, "warn", f"{label}: allowed by {why}, but no "
                                 f"connection ({result})")


def allowed_by(mode, rules, private_dns_json, ip, port):
    """Why the configuration lets this mode reach ip:port over TCP, or
    None."""
    if mode == "direct" and port == 53 and \
            nft_set_contains(private_dns_json, ip):
        return "private_dns"
    for rule in rules:
        if rule.matches(ip, "tcp", port):
            return f"private_allow: {rule}"
    return None


def run_probe(report):
    rows = report.section("--probe: traffic from the bridge, per egress mode")
    subnet, gateway = resolve_subnet(config)
    cleanup_stale_probes()
    addrs = probe_addresses(subnet, gateway)
    addr, port = proxy_endpoint() if config.proxy else (None, None)
    proxy_url = config.proxy or None
    allowed = None
    if config.proxy and config.proxy_allowed_domains:
        lines = [ln.split("#", 1)[0].strip() for ln in
                 (read_root(config.proxy_allowed_domains) or "").splitlines()]
        allowed = next((ln.lstrip(".") for ln in lines if ln), None)
    lan = lan_targets(gateway)
    private_dns_json = nft_set_json("private_dns")

    def handler(signum, frame):
        raise KeyboardInterrupt
    old = signal.signal(signal.SIGTERM, handler)
    try:
        with Probe() as p:
            for mode in ("direct", "proxy", "none"):
                ip = addrs.get(mode)
                if not ip:
                    report.add(rows, "info", f"{mode}: no free address in "
                                             f"this mode, skipped")
                    continue
                p.use(ip, subnet.prefixlen, gateway)
                tag = f"{mode} ({ip})"
                # Direct VMs ask the configured resolver; the others must not
                # reach any. A raw query from the namespace: name lookups
                # in curl may go to the host's systemd-resolved over a unix
                # socket, outside the namespace.
                dns_ip = config.nameservers[0] if mode == "direct" else "1.1.1.1"
                tests = [("tcp", "1.1.1.1", 443), ("udp", dns_ip, 53)]
                if addr:
                    tests.append(("tcp", addr, port))
                tests += [("tcp", t, prt) for t, prt, _ in lan]
                res = p.sockets(tests)
                inet, dns = res[0], res[1]
                prox = res[2] if addr else None
                lan_res = res[3 if addr else 2:]
                if mode == "direct":
                    report.add(rows, "ok" if inet == "open" else "FAIL",
                               f"{tag}: internet (1.1.1.1:443) "
                               + ("reachable" if inet == "open" else
                                  f"not reachable ({inet}): something drops "
                                  f"it; see Other firewalls"))
                    hint = ""
                    if dns != "reply" and is_private_address(dns_ip, config) \
                            and not nft_set_contains(private_dns_json, dns_ip):
                        hint = (f": it's a private address and not in the "
                                f"nftables set private_dns; add it there "
                                f"(and ./glovebox host-setup nftables) or "
                                f"use a public resolver")
                    report.add(rows, "ok" if dns == "reply" else "FAIL",
                               f"{tag}: DNS ({dns_ip}:53, nameservers in "
                               f"the config) "
                               + ("answers" if dns == "reply" else
                                  f"doesn't answer ({dns}){hint}"))
                    rc, _, code = p.curl("https://example.com")
                    report.add(rows, "ok" if rc == 0 else "FAIL",
                               f"{tag}: HTTPS to example.com "
                               + (f"works ({code})" if rc == 0 else "fails"))
                    if prox:
                        expect_blocked(report, rows, f"{tag}: the proxy", prox)
                else:
                    expect_blocked(report, rows, f"{tag}: internet "
                                                 f"(1.1.1.1:443)", inet)
                    expect_blocked(report, rows, f"{tag}: DNS (1.1.1.1:53)",
                                   "timeout" if dns != "reply" else "open")
                if mode == "proxy" and prox:
                    report.add(rows, "ok" if prox == "open" else "FAIL",
                               f"{tag}: the proxy {addr}:{port} "
                               + ("answers" if prox == "open" else
                                  f"is not reachable ({prox})"))
                    if prox == "open" and allowed:
                        rc, connect, code = p.curl(f"https://{allowed}/", proxy_url)
                        report.add(rows, "ok" if rc == 0 else "warn",
                                   f"{tag}: allowlisted {allowed} through the "
                                   f"proxy " + (f"works ({code})" if rc == 0
                                                else f"fails (CONNECT {connect})"))
                    if prox == "open":
                        rc, connect, code = p.curl("https://example.com/", proxy_url)
                        denied = "403" in (connect, code)
                        report.add(rows, "ok" if denied else "FAIL",
                                   f"{tag}: example.com through the proxy "
                                   + ("refused (403)" if denied else
                                      f"not refused (CONNECT {connect}, "
                                      f"HTTP {code}; allowlisted?)"))
                if mode == "none" and prox:
                    expect_blocked(report, rows, f"{tag}: the proxy", prox)
                rules = private_allow_rules(ip)
                for (t, prt, what), r in zip(lan, lan_res):
                    label = f"{tag}: {what} {t}:{prt}"
                    why = allowed_by(mode, rules, private_dns_json, t, prt)
                    if why:
                        expect_allowed(report, rows, label, r, why)
                    else:
                        expect_blocked(report, rows, label, r)
    except RuntimeError as e:
        report.add(rows, "FAIL", f"the probe couldn't run: {e}")
    finally:
        signal.signal(signal.SIGTERM, old)


def cmd_host_check(a):
    pm = package_manager()
    log(f"Package manager: {pm}. Reading the host's state (sudo)...")
    report = Report()
    check_setup(report, pm)
    check_live(report)
    check_reboot(report)
    check_other_firewalls(report)
    check_forwarding(report)
    check_journal(report)
    if a.probe:
        run_probe(report)

    bar = "=" * 60
    print(f"\n{bar}\nHost check\n{bar}")
    for title, rows in report.sections:
        fails = sum(s == "FAIL" for s, _ in rows)
        warns = sum(s == "warn" for s, _ in rows)
        verdict = (f"{fails} FAIL" if fails else "ok") + (
            f", {warns} warning(s)" if warns else "")
        print(f"  {title}: {verdict}")
    print(bar)
    if not a.probe:
        print("  Real traffic not tested; ./glovebox host-check --probe "
              "does, without a VM.")
    print(f"Host check {'FAILED' if report.failed else 'PASSED'}.")
    sys.exit(1 if report.failed else 0)
