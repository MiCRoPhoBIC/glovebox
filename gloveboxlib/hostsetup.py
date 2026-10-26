# glovebox: hardened, network-contained KVM sandboxes for AI agents.
# Copyright (C) 2026 MiCRoPhoBIC
# Licensed under the GNU GPL v3 or later; see LICENSE.
# SPDX-License-Identifier: GPL-3.0-or-later

"""host-setup: QEMU/KVM and libvirt, the libvirt network, nftables and Squid
on the host.

The only glovebox command that writes to the host, and only when asked:
it reads the host's state, shows every step with its exact commands (and a
diff for each file it replaces), and changes nothing without a yes. In UFW
it only adds rules on the sandbox bridge.
"""

import atexit
import difflib
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from . import journal
from .config import config
from .common import (CLAUDE_DOMAINS, allowlist_covers, capture, die,
                     domain_entries, log, read_root, resolve_subnet,
                     root_exists)
from .journal import (STAMP, dir_hook, file_hook, libvirt_net_hook,
                      nft_tables_hook, packages_hook, service_hook,
                      sysctl_hook, ufw_rule_hook, unit_state)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "host-setup")
NET_XML = os.path.join(SRC, "libvirt-net", "glovebox.xml")
SYSCTL_SRC = os.path.join(SRC, "sysctl", "99-glovebox.conf")
NFT_SRC = os.path.join(SRC, "nftables", "glovebox.conf")
GUARD_SRC = os.path.join(SRC, "nftables", "forward-guard.conf")
HOOK_SRC = os.path.join(SRC, "libvirt-hook", "glovebox")
SQUID_SRC = os.path.join(SRC, "squid")

SYSCTL_DEST = "/etc/sysctl.d/99-glovebox.conf"
NFT_DEST = "/etc/glovebox/nftables.conf"
NFT_UNIT = "glovebox-nftables.service"
NFT_TABLES = (("inet", "glovebox"), ("ip", "glovebox"), ("bridge", "glovebox"))
# forward_guard (optional): NFT_DEST includes whatever is in GUARD_DIR.
GUARD_DIR = "/etc/glovebox/forward-guard.d"
GUARD_DEST = f"{GUARD_DIR}/forward-guard.conf"
GUARD_TABLE = ("ip", "glovebox_guard")
# A directory of hooks (libvirt 6.5+), so a qemu hook of the user's own
# stays as it is.
HOOK_DEST = "/etc/libvirt/hooks/qemu.d/glovebox"
LIBVIRT_DAEMONS = ("libvirtd.service", "virtqemud.service")
SQUID_DIR = "/etc/squid"
SQUID_DROPIN = "/etc/systemd/system/squid.service.d/glovebox.conf"
SSL_DIR = "/etc/squid/ssl_cert"
CA_PEM = f"{SSL_DIR}/sandboxCA.pem"  # key + certificate; never leaves the host
CA_CRT = f"{SSL_DIR}/sandboxCA.crt"  # public part, installed in the guests
SSL_DB = "/var/cache/squid/ssl_db"
CERTGEN = "/usr/lib/squid/security_file_certgen"  # as in squid.conf
SQUID_DEFAULT_USER = "proxy"  # Debian and Arch; verified after install

PARTS = ("virt", "network", "nftables", "squid", "ufw")
PACKAGES = {
    # QEMU/KVM, libvirt (with its nwfilter driver, for clean-traffic), UEFI
    # firmware, and the host tools create runs. On Arch, libvirt only
    # optionally depends on iptables (nft backend, provides the ebtables the
    # nwfilter driver runs) and dnsmasq (the network driver looks for it).
    "virt": {"apt": ["qemu-system-x86", "qemu-utils", "libvirt-daemon-system",
                     "libvirt-clients", "virtinst", "ovmf", "xorriso",
                     "openssl", "curl", "iproute2", "iputils-ping"],
             "pacman": ["qemu-system-x86", "qemu-img", "libvirt",
                        "virt-install", "edk2-ovmf", "libisoburn",
                        "iptables", "dnsmasq", "openssl", "curl", "iproute2",
                        "iputils"]},
    # Debian's plain squid is built with GnuTLS, without ssl_bump.
    "nftables": {"apt": ["nftables"], "pacman": ["nftables"]},
    "squid": {"apt": ["squid-openssl", "openssl"],
              "pacman": ["squid", "openssl"]},
}

NFT_UNIT_TEXT = f"""\
# Installed by glovebox host-setup. Loads only glovebox's own tables
# (inet/ip/bridge glovebox); the rest of the host's ruleset is untouched.
[Unit]
Description=glovebox containment rules (nftables tables glovebox)
DefaultDependencies=no
Wants=network-pre.target
# After nftables/firewalld, so a ruleset flush at their start can't drop ours.
After=nftables.service firewalld.service
# Debian's /etc/nftables.conf starts with `flush ruleset`: restarting or
# reloading nftables.service wipes our tables too, so follow it and load
# them again right after (fail-closed). Its stop flushes the whole ruleset;
# its next start brings this unit back (WantedBy below). No effect without
# nftables.service.
PartOf=nftables.service
ReloadPropagatedFrom=nftables.service
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f {NFT_DEST}
ExecReload=/usr/sbin/nft -f {NFT_DEST}
# No ExecStop on purpose: deleting the tables would open the bridge to the
# host and the LAN (fail-open). Remove them by hand if you must.

[Install]
WantedBy=multi-user.target nftables.service
"""

SQUID_DROPIN_TEXT = """\
# Installed by glovebox host-setup. Squid listens on the bridge address
# only, which exists once libvirt has started the glovebox network: start
# after libvirt, and retry for a while if the bridge isn't up yet.
[Unit]
After=libvirtd.service virtnetworkd.service
StartLimitIntervalSec=120
StartLimitBurst=20

[Service]
Restart=on-failure
RestartSec=5
"""

LOG_DIR = os.path.join(REPO, "logs")
DIFF_MAX_LINES = 60


class Step:
    def __init__(self, what, cmds=(), diff=None, fn=None, hooks=(), done=None,
                 check=False):
        self.what = what        # what it does and why, shown in the plan
        self.cmds = list(cmds)  # argv lists, shown and run in order
        self.diff = diff        # diff of a file it replaces
        self.fn = fn            # a check run in Python instead of commands
        self.hooks = list(hooks)  # journal records around the commands
        self.done = done        # runs once the step succeeded (uninstall)
        self.check = check      # only verifies; changes nothing (host-check)


class Plan:
    def __init__(self, parts):
        self.parts = parts
        self.apt_updated = False
        self.libvirt_pending = False  # the virt part installs/starts libvirt
        self.interactive = False  # may ask while planning (not a dry run)
        self.forward_guard = None  # --forward-guard / --no-forward-guard
        self.sections = []  # (title, steps, notes)
        self.staged = 0
        self.stage_dir = tempfile.mkdtemp(prefix="glovebox-host-setup-")
        os.chmod(self.stage_dir, 0o755)  # sudo install reads from here
        atexit.register(shutil.rmtree, self.stage_dir, True)

    def section(self, title):
        steps, notes = [], []
        self.sections.append((title, steps, notes))
        return steps, notes

    def stage(self, content, name):
        # Planned file contents are fixed here, so the diff shown is exactly
        # what gets installed.
        # Numbered, as two destinations may share a basename.
        self.staged += 1
        path = os.path.join(self.stage_dir, f"{self.staged}-{name}")
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o644)
        return path

    def steps(self):
        return [s for _, steps, _ in self.sections for s in steps]


def host_tool(name):
    # /usr/sbin is often not on a normal user's PATH (Debian).
    for path in (shutil.which(name), f"/usr/sbin/{name}", f"/sbin/{name}"):
        if path and os.access(path, os.X_OK):
            return path
    return None


def read_repo(path):
    with open(path) as f:
        return f.read()


def package_manager():
    ids = set()
    try:
        with open("/etc/os-release") as f:
            for line in f:
                key, _, value = line.strip().partition("=")
                if key in ("ID", "ID_LIKE"):
                    ids.update(value.strip('"').split())
    except OSError:
        pass
    if ids & {"debian", "ubuntu"} and shutil.which("apt-get"):
        return "apt"
    if "arch" in ids and shutil.which("pacman"):
        return "pacman"
    die(f"Unsupported distribution ({', '.join(sorted(ids)) or 'unknown'}): "
        f"host-setup knows apt-get (Debian/Ubuntu) and pacman (Arch). Set "
        f"the host up by hand as in docs/host-setup.md.")


def missing_packages(pm, pkgs):
    if pm == "apt":
        return [p for p in pkgs
                if "install ok installed" not in capture(
                    ["dpkg-query", "-W", "-f=${Status}", p]).stdout]
    return [p for p in pkgs if capture(["pacman", "-Q", p]).returncode != 0]


def package_steps(plan, pm, part, steps):
    missing = missing_packages(pm, PACKAGES[part][pm])
    if not missing:
        return False
    if pm == "apt":
        cmds = [] if plan.apt_updated else [["sudo", "apt-get", "update"]]
        plan.apt_updated = True
        cmds.append(["sudo", "env", "DEBIAN_FRONTEND=noninteractive",
                     "apt-get", "install", "-y", *missing])
    else:
        # No -y: syncing without upgrading is a partial upgrade on Arch. If
        # the package database is stale, run `sudo pacman -Syu` first.
        cmds = [["sudo", "pacman", "-S", "--needed", "--noconfirm", *missing]]
    steps.append(Step(f"Install {', '.join(missing)}.", cmds,
                      hooks=[packages_hook(pm)]))
    return True


def short_diff(old, new, dest, new_label=None):
    lines = list(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                      dest, new_label or f"{dest} (new)"))
    if len(lines) > DIFF_MAX_LINES:
        rest = len(lines) - DIFF_MAX_LINES
        lines = lines[:DIFF_MAX_LINES] + [
            f"... {rest} more diff lines (see the full files)\n"]
    return "".join(lines)


def file_step(plan, steps, notes, what, dest, content, mode="0644"):
    """Install content at dest: nothing if identical, else with a diff. The
    file there is saved in the journal first. Returns whether dest changes."""
    current = read_root(dest)
    if current == content:
        notes.append(f"{dest} is up to date.")
        return False
    diff = None
    if current is not None:
        diff = short_diff(current, content, dest)
        what += " Replaces the current file."
    src = plan.stage(content, os.path.basename(dest))
    steps.append(Step(what, [["sudo", "install", "-D", "-m", mode, "-o", "root",
                              "-g", "root", src, dest]], diff,
                      hooks=[file_hook(dest, content)]))
    return True


def require_consistent(problems):
    if problems:
        die("host-setup/ and the config disagree; make them match "
            "first:\n  " + "\n  ".join(problems))


def proxy_endpoint():
    u = urlsplit(config.proxy)
    return u.hostname, u.port or 80


def libvirt_reachable():
    return shutil.which("virsh") is not None and capture(
        ["sudo", "virsh", "-c", "qemu:///system", "version"]).returncode == 0


# --- virt: QEMU/KVM, libvirt and create's tools -----------------------------------

LIBVIRT_UNITS = ("libvirtd.service", "libvirtd.socket", "virtqemud.service",
                 "virtqemud.socket")

NO_KVM = ("/dev/kvm is missing: turn on hardware virtualization (VT-x/AMD-V) "
          "in the firmware setup and load the kvm module; without it no "
          "sandbox can start.")


def virt_problems():
    problems = []
    if not os.path.exists("/dev/kvm"):
        problems.append(NO_KVM)
    if not host_tool("ebtables"):
        problems.append("ebtables is missing; libvirt's clean-traffic filter "
                        "(anti-spoofing) needs it. It comes with the "
                        "iptables package (nft backend).")
    r = capture(["sudo", "virsh", "-c", "qemu:///system", "nwfilter-list"])
    if r.returncode != 0 or "clean-traffic" not in r.stdout:
        problems.append("libvirt has no clean-traffic nwfilter, which create "
                        "uses for anti-spoofing.")
    return problems


def verify_virt():
    problems = virt_problems()
    if problems:
        die("The virtualization stack is incomplete:\n  "
            + "\n  ".join(problems))
    log("KVM, ebtables and libvirt's clean-traffic filter are in place.")


def plan_virt(plan, pm):
    steps, notes = plan.section("virt: QEMU/KVM, libvirt and the tools create "
                                "needs")
    installs = package_steps(plan, pm, "virt", steps)
    # libvirt runs either as the monolithic libvirtd or as modular,
    # socket-activated daemons (virtqemud, ...). Either one set up is fine;
    # starting libvirtd next to the modular ones could disturb that setup.
    enabled = any(unit_state(u)[1] for u in LIBVIRT_UNITS)
    if installs or not (enabled and libvirt_reachable()):
        steps.append(Step("Start libvirt now and at every boot.",
                          [["sudo", "systemctl", "enable", "--now",
                            "libvirtd.service"]],
                          hooks=[service_hook("libvirtd.service")]))
        steps.append(Step("Check that KVM, ebtables and libvirt's "
                          "clean-traffic filter are available.",
                          fn=verify_virt, check=True))
        plan.libvirt_pending = True
        if not os.path.exists("/dev/kvm"):
            notes.append(NO_KVM)
        return
    notes.append("libvirt is installed, running and starts at boot.")
    notes.extend(virt_problems())


# --- network: libvirt network + IP forwarding --------------------------------

# Verdicts a chain may end with, after at most a counter or a log, to count
# as filtering (firewalld ends its chains with a reject, policy accept).
FINAL_DROP = {"drop", "reject"}


def forward_filters():
    """The host's own chains (not glovebox's) that filter forwarded IPv4:
    a drop policy, or a last rule that drops or rejects whatever reaches it.
    A heuristic: what they let through is up to their other rules."""
    found = []
    if host_tool("nft"):
        r = capture(["sudo", "nft", "-j", "list", "ruleset"])
        items = json.loads(r.stdout).get("nftables", []) if r.returncode == 0 else []
        last = {}
        for item in items:
            if "rule" in item:
                rule = item["rule"]
                last[rule["family"], rule["table"], rule["chain"]] = rule["expr"]
        for item in items:
            c = item.get("chain")
            if not c or c.get("hook") != "forward" or c["family"] not in (
                    "ip", "inet") or c["table"] in ("glovebox", GUARD_TABLE[1]):
                continue
            expr = [next(iter(x)) for x in last.get(
                (c["family"], c["table"], c["name"]), [])]
            if c.get("policy") == "drop":
                found.append(f"{c['family']} {c['table']} {c['name']} "
                             f"(policy drop)")
            elif expr and expr[-1] in FINAL_DROP and set(expr[:-1]) <= {
                    "counter", "log"}:
                found.append(f"{c['family']} {c['table']} {c['name']} "
                             f"(ends with {expr[-1]})")
    elif host_tool("iptables"):
        # No nft (yet) to read the ruleset with; iptables-nft shows its part.
        if "-P FORWARD DROP" in capture(["sudo", "iptables", "-S",
                                         "FORWARD"]).stdout:
            found.append("iptables FORWARD (policy DROP)")
    if host_tool("iptables-legacy-save"):
        legacy = capture(["sudo", "iptables-legacy-save", "-t", "filter"]).stdout
        if re.search(r"^:FORWARD DROP", legacy, re.M):
            found.append("legacy iptables FORWARD (policy DROP)")
    return found


def other_interfaces():
    """The host's network interfaces apart from loopback, the sandbox
    bridge and what is attached to it (the VMs' tap devices): what the host
    may route between once forwarding is on. (name, kind) pairs."""
    r = capture(["ip", "-j", "-d", "link", "show"])
    out = []
    for link in json.loads(r.stdout or "[]"):
        name = link.get("ifname", "")
        if name in ("lo", config.bridge) or link.get("master") == config.bridge:
            continue
        out.append((name, link.get("linkinfo", {}).get("info_kind", "")))
    return out


def ip_forward_on():
    with open("/proc/sys/net/ipv4/ip_forward") as f:
        return f.read().strip() == "1"


def guard_installed():
    return root_exists(GUARD_DEST)


def forward_explanation(filters, guard):
    """What turning forwarding on means on this host, for the plan and
    the forward_guard question. First line: the verdict."""
    names = ", ".join(n for n, _ in other_interfaces()) or "none"
    was = "on already" if ip_forward_on() else "off until now"
    common = (f"The sandboxes need net.ipv4.ip_forward=1 (on this host: "
              f"{was}). It lets the host route IPv4 between all its "
              f"interfaces, not only for the sandboxes; glovebox's rules "
              f"cover only {config.bridge}. Other interfaces here: {names}.")
    if guard:
        return (f"IP forwarding: limited to {config.bridge} by forward_guard.\n"
                f"    {common} forward_guard drops forwarded IPv4 that "
                f"neither comes from nor goes to {config.bridge}, which also "
                f"stops Docker, other libvirt NAT networks or VPN routing "
                f"here (turn it off with --no-forward-guard).")
    if filters:
        return (f"IP forwarding: your firewall filters forwarded traffic "
                f"({'; '.join(filters)}).\n"
                f"    {common} What else the host forwards is up to those "
                f"rules (found by their drop policy or final drop/reject; "
                f"their other rules are not analyzed).")
    return (f"WARNING: nothing on this host filters forwarded traffic.\n"
            f"    {common} With no firewall rules for forwarding, whatever "
            f"uses this host as its gateway (a device on the LAN, a VPN "
            f"peer) gets routed between those interfaces, without you "
            f"noticing. Either filter forwarding in your own firewall, or "
            f"turn on forward_guard: glovebox then drops forwarded IPv4 "
            f"that neither comes from nor goes to {config.bridge}. Its cost: "
            f"Docker, other libvirt NAT networks or VPN routing set up on "
            f"this host later won't forward until you turn it off "
            f"(./glovebox host-setup nftables --no-forward-guard).")


def plan_network(plan, pm):
    steps, notes = plan.section("network: libvirt network and IP forwarding")
    net = ET.parse(NET_XML).getroot()
    net_name = net.findtext("name")
    bridge = net.find("bridge").get("name")
    ip = net.find("ip")
    net_addr = ipaddress.ip_interface(f"{ip.get('address')}/{ip.get('netmask')}")
    problems = []
    if bridge != config.bridge:
        problems.append(f"libvirt-net/glovebox.xml: bridge {bridge}, "
                        f"the config: bridge {config.bridge}")
    if net_addr != ipaddress.ip_interface(config.host_address):
        problems.append(f"libvirt-net/glovebox.xml: {net_addr}, "
                        f"the config: host_address {config.host_address}")
    require_consistent(problems)

    if libvirt_reachable():
        networks = capture(["sudo", "virsh", "net-list", "--all",
                            "--name"]).stdout.split()
    elif plan.libvirt_pending:
        # The virt part installs/starts libvirt first, so no network yet.
        networks = []
    else:
        die("libvirt is not installed or not running: run `./glovebox "
            "host-setup virt network` (or all).")

    changed = file_step(
        plan, steps, notes,
        "Turn on IPv4 forwarding at boot: the sandboxes reach the internet "
        "through NAT on the host.",
        SYSCTL_DEST, read_repo(SYSCTL_SRC))
    if changed or not ip_forward_on():
        steps.append(Step(f"Turn on IPv4 forwarding now, from {SYSCTL_DEST}.",
                          [["sudo", "sysctl", "-p", SYSCTL_DEST]],
                          hooks=[sysctl_hook("net.ipv4.ip_forward")]))
    guard = guard_installed()
    filters = forward_filters()
    notes.append(forward_explanation(filters, guard))
    if not guard and not filters:
        notes.append("forward_guard is decided in the nftables part"
                     + (" below." if "nftables" in plan.parts else
                        ": ./glovebox host-setup nftables (asks), or with "
                        "--forward-guard / --no-forward-guard."))

    if net_name not in networks:
        steps.append(Step(
            f"Define the libvirt network {net_name}: bridge {bridge} with "
            f"{net_addr}, no DHCP and no DNS (each VM gets a static IP); "
            f"start it now and at every boot.",
            [["sudo", "virsh", "net-define", NET_XML],
             ["sudo", "virsh", "net-autostart", net_name],
             ["sudo", "virsh", "net-start", net_name]],
            hooks=[libvirt_net_hook(net_name)]))
        return

    # Already defined: check it, but don't redefine a network VMs may use.
    cur = ET.fromstring(capture(["sudo", "virsh", "net-dumpxml", net_name]).stdout)
    cur_ip = cur.find("ip")
    cur_bridge = cur.find("bridge")
    if cur_bridge is None or cur_bridge.get("name") != bridge or cur_ip is None \
            or ipaddress.ip_interface(f"{cur_ip.get('address')}/"
                                      f"{cur_ip.get('netmask')}") != net_addr:
        notes.append(f"The libvirt network {net_name} exists but differs from "
                     f"{os.path.relpath(NET_XML, REPO)}; left as is. To "
                     f"redefine it (stop the VMs first): sudo virsh "
                     f"net-destroy {net_name}; sudo virsh net-undefine "
                     f"{net_name}; then re-run host-setup network.")
    info = capture(["sudo", "virsh", "net-info", net_name]).stdout
    if not re.search(r"^Autostart:\s+yes", info, re.M):
        steps.append(Step(f"Start the libvirt network {net_name} at every boot.",
                          [["sudo", "virsh", "net-autostart", net_name]],
                          hooks=[libvirt_net_hook(net_name)]))
    if not re.search(r"^Active:\s+yes", info, re.M):
        steps.append(Step(f"Start the libvirt network {net_name}.",
                          [["sudo", "virsh", "net-start", net_name]],
                          hooks=[libvirt_net_hook(net_name)]))
    else:
        notes.append(f"The libvirt network {net_name} is defined and running.")


# --- nftables -------------------------------------------------------------------

def plan_nftables(plan, pm):
    steps, notes = plan.section("nftables: the sandboxes' firewall rules")
    subnet, _ = resolve_subnet(config)
    text = read_repo(NFT_SRC)
    defines = {k: v.strip('"') for k, v in
               re.findall(r"^define\s+(\w+)\s*=\s*(.+?)\s*$", text, re.M)}
    problems = []
    if defines.get("BRIDGE_DEV") != config.bridge:
        problems.append(f"nftables BRIDGE_DEV {defines.get('BRIDGE_DEV')}, "
                        f"the config bridge {config.bridge}")
    if defines.get("BRIDGE_NET") != str(subnet):
        problems.append(f"nftables BRIDGE_NET {defines.get('BRIDGE_NET')}, "
                        f"the config host_address {config.host_address}")
    if config.proxy and (defines.get("PROXY_ADDR"), defines.get("PROXY_PORT")) \
            != tuple(map(str, proxy_endpoint())):
        problems.append(f"nftables PROXY_ADDR:PROXY_PORT {defines.get('PROXY_ADDR')}"
                        f":{defines.get('PROXY_PORT')}, the config proxy "
                        f"{config.proxy}")
    guard_text = read_repo(GUARD_SRC)
    guard_dev = re.search(r'^define\s+GUARD_DEV\s*=\s*"?([^"\s]+)', guard_text, re.M)
    if not guard_dev or guard_dev.group(1) != config.bridge:
        problems.append(f"nftables/forward-guard.conf GUARD_DEV "
                        f"{guard_dev.group(1) if guard_dev else '?'}, the "
                        f"config bridge {config.bridge}")
    require_consistent(problems)

    package_steps(plan, pm, "nftables", steps)
    guard = want_forward_guard(plan, notes)
    steps.append(Step(f"Check the syntax of {os.path.relpath(NFT_SRC, REPO)} "
                      f"(changes nothing).",
                      [["sudo", "nft", "-c", "-f", NFT_SRC]], check=True))
    changed = file_step(
        plan, steps, notes,
        "Install the rules. They live in glovebox's own tables and match "
        "only traffic from the bridge, so the host's other rules stay as "
        "they are. Edit the sets in the repo and re-run to change them.",
        NFT_DEST, text)
    if guard:
        steps.append(Step(f"Check the syntax of "
                          f"{os.path.relpath(GUARD_SRC, REPO)} (changes "
                          f"nothing).", [["sudo", "nft", "-c", "-f", GUARD_SRC]],
                          check=True))
        changed |= file_step(
            plan, steps, notes,
            f"Install forward_guard: the host forwards IPv4 only to and from "
            f"{config.bridge}. Unlike the rules above, this affects the "
            f"host's other traffic: Docker, other libvirt NAT networks or "
            f"VPN routing here won't forward while it is on "
            f"(--no-forward-guard removes it).",
            GUARD_DEST, guard_text)
    elif guard_installed():
        changed = True
        steps.append(Step(
            f"Remove forward_guard ({GUARD_DEST}): the host forwards IPv4 "
            f"between all its interfaces again, as far as its own firewall "
            f"lets it.", [["sudo", "rm", "-f", GUARD_DEST]]))
    changed |= file_step(
        plan, steps, notes,
        f"Install {NFT_UNIT}, which loads the rules at boot, before the "
        f"network comes up. /etc/nftables.conf is not touched (on Debian it "
        f"starts with `flush ruleset`, which would also wipe UFW's rules).",
        f"/etc/systemd/system/{NFT_UNIT}", NFT_UNIT_TEXT)
    active, enabled = unit_state(NFT_UNIT)
    loaded = capture(["sudo", "nft", "list", "table", "inet",
                      "glovebox"]).returncode == 0
    guard_loaded = capture(["sudo", "nft", "list", "table",
                            *GUARD_TABLE]).returncode == 0
    if changed or not (active and enabled and loaded) or guard != guard_loaded:
        steps.append(Step(
            "Load the rules now and at every boot. The file replaces "
            "glovebox's tables in one transaction, so there's no moment "
            "without them.",
            [["sudo", "systemctl", "daemon-reload"],
             ["sudo", "systemctl", "enable", NFT_UNIT],
             ["sudo", "systemctl", "restart", NFT_UNIT]],
            hooks=[service_hook(NFT_UNIT),
                   nft_tables_hook(NFT_TABLES + ((GUARD_TABLE,) if guard
                                                 else ()))]))
    else:
        notes.append("The rules are loaded and load at boot.")

    if file_step(
            plan, steps, notes,
            "Install a libvirt hook that refuses to start a sandbox VM while "
            "these rules aren't loaded (autostart at boot, virsh, "
            "virt-manager): the bridge has no other filter. Other VMs pass "
            "untouched.",
            HOOK_DEST, read_repo(HOOK_SRC), mode="0755"):
        # libvirt looks for hooks only when it starts. A restart leaves the
        # running VMs running; try-restart leaves a stopped daemon stopped.
        daemons = [u for u in LIBVIRT_DAEMONS if capture(
            ["systemctl", "show", "-p", "LoadState", "--value", u]
        ).stdout.strip() == "loaded"]
        if plan.libvirt_pending and "libvirtd.service" not in daemons:
            daemons.append("libvirtd.service")
        if daemons:
            steps.append(Step(
                "Restart libvirt, which finds new hooks only when it starts. "
                "Running VMs keep running.",
                [["sudo", "systemctl", "try-restart", *daemons]]))

    # The distro's own nftables.service may load a copy too: from
    # /etc/nftables.conf, or a directory it includes (Arch, CachyOS).
    r = capture(["sudo", "grep", "-rl", "glovebox",
                 "/etc/nftables.conf", "/etc/nftables.d"])
    for path in r.stdout.split():
        notes.append(f"{path} also loads or mentions glovebox's rules. "
                     f"Remove that, so only one copy applies: {NFT_DEST}.")


def want_forward_guard(plan, notes):
    """Whether forward_guard should be on after this run: as the flag says,
    else as it is; but when it's off and nothing on the host filters
    forwarded traffic, the reason is shown and the question asked."""
    installed = guard_installed()
    want = plan.forward_guard
    if want is None and not installed and not forward_filters():
        if not plan.interactive:
            notes.append("forward_guard is off and nothing on this host "
                         "filters forwarded traffic: the real run asks "
                         "whether to turn it on (or pass --forward-guard / "
                         "--no-forward-guard).")
            return False
        print("\n" + forward_explanation([], False) + "\n")
        want = ask(f"Turn on forward_guard (limit the host's IPv4 "
                   f"forwarding to {config.bridge})?")
        if not want:
            notes.append("forward_guard stays off (your answer): nothing "
                         "filters the host's other forwarded traffic, and "
                         "host-check warns about it. Turn it on later with "
                         "./glovebox host-setup nftables --forward-guard, or "
                         "pass --no-forward-guard not to be asked.")
    if want is None:
        want = installed
    if want and installed:
        notes.append(f"forward_guard is on: the host forwards IPv4 only to "
                     f"and from {config.bridge} (--no-forward-guard removes "
                     f"it).")
    return want


# --- squid ----------------------------------------------------------------------

def squid_build():
    # (built with OpenSSL, default user) of the installed Squid.
    squid = host_tool("squid")
    if not squid:
        return None, None
    v = capture([squid, "-v"]).stdout
    m = re.search(r"--with-default-user=([\w.-]+)", v)
    return "--with-openssl" in v, m.group(1) if m else None


def verify_squid(user):
    def fn():
        openssl, default_user = squid_build()
        if openssl is None:
            die("squid is not installed.")
        if not openssl:
            die("This Squid is built without OpenSSL, so it has no ssl_bump. "
                "On Debian, install squid-openssl (and check `update-"
                "alternatives --display squid`).")
        if default_user != user:
            die(f"Squid runs as '{default_user}', not '{user}'; set "
                f"cache_effective_user, or the owner of {SSL_DIR} and "
                f"{SSL_DB}, by hand.")
        if not os.access(CERTGEN, os.X_OK):
            die(f"{CERTGEN} not found; this Squid can't generate TLS "
                f"certificates. Fix the sslcrtd_program path in squid.conf.")
        log(f"Squid: OpenSSL build, runs as {user}, {CERTGEN} present.")
    return fn


def plan_squid(plan, pm):
    steps, notes = plan.section("squid: the proxy for proxy-only sandboxes")
    if not config.proxy:
        die("proxy is off (\"\") in the config: there is no proxy to set up.")
    if config.proxy_ca_days < 1:
        die(f"proxy_ca_days in the config is {config.proxy_ca_days}; it must "
            f"be at least 1.")
    subnet, _ = resolve_subnet(config)
    conf = read_repo(os.path.join(SQUID_SRC, "squid.conf"))
    port = re.search(r"^http_port\s+(\S+):(\d+)", conf, re.M)
    acl = re.search(r"^acl\s+sandbox_net\s+src\s+(\S+)", conf, re.M)
    problems = []
    if not port or (port.group(1), port.group(2)) != tuple(map(str, proxy_endpoint())):
        problems.append(f"squid.conf http_port "
                        f"{port.group(1) + ':' + port.group(2) if port else '?'}, "
                        f"the config proxy {config.proxy}")
    if not acl or acl.group(1) != str(subnet):
        problems.append(f"squid.conf acl sandbox_net {acl.group(1) if acl else '?'}, "
                        f"the config host_address {config.host_address}")
    if config.proxy_ca and config.proxy_ca != CA_CRT:
        problems.append(f"host-setup installs the CA certificate at {CA_CRT}, "
                        f"the config proxy_ca is {config.proxy_ca}")
    require_consistent(problems)

    installed = host_tool("squid") is not None
    package_steps(plan, pm, "squid", steps)
    user = squid_build()[1] if installed else None
    user = user or SQUID_DEFAULT_USER
    steps.append(Step(f"Check that Squid is built with OpenSSL (for ssl_bump) "
                      f"and runs as {user}.", fn=verify_squid(user),
                      check=True))

    if not root_exists(SSL_DIR):
        steps.append(Step(f"Create {SSL_DIR} for the TLS-inspection CA, "
                          f"readable only by root and {user}.",
                          [["sudo", "install", "-d", "-o", user, "-g", user,
                            "-m", "0750", SSL_DIR]],
                          hooks=[dir_hook(SSL_DIR)]))
    new_ca = not root_exists(CA_PEM)
    if new_ca:
        steps.append(Step(
            f"Create the CA Squid signs the inspected HTTPS sites with (valid "
            f"{config.proxy_ca_days} days, proxy_ca_days in the config). "
            f"{os.path.basename(CA_PEM)} holds its private key and never "
            f"leaves the host.",
            # umask 077: the private key is never readable by others, not
            # even before the chmod.
            [["sudo", "sh", "-c", "umask 077 && " + shlex.join(
                ["openssl", "req", "-new", "-newkey", "rsa:4096", "-sha256",
                 "-days", str(config.proxy_ca_days), "-nodes", "-x509", "-subj",
                 "/CN=sandbox-squid-CA", "-keyout", CA_PEM, "-out", CA_PEM])],
             ["sudo", "chown", f"{user}:{user}", CA_PEM],
             ["sudo", "chmod", "600", CA_PEM]],
            hooks=[file_hook(CA_PEM)]))
    else:
        notes.append(f"{CA_PEM} exists and is kept: the proxy-only VMs trust it.")
        if capture(["sudo", "openssl", "x509", "-checkend", str(30 * 86400),
                    "-noout", "-in", CA_PEM]).returncode != 0:
            notes.append(f"The CA in {CA_PEM} expires within 30 days (or "
                         f"has). To renew it, delete {CA_PEM} and {CA_CRT}, "
                         f"re-run, and recreate the proxy-only VMs.")
    if not root_exists(CA_PEM) or not root_exists(CA_CRT):
        steps.append(Step(
            f"Extract the CA's public certificate, {CA_CRT}: create installs "
            f"it in proxy-only VMs.",
            [["sudo", "openssl", "x509", "-in", CA_PEM, "-out", CA_CRT],
             ["sudo", "chown", f"{user}:{user}", CA_CRT],
             ["sudo", "chmod", "644", CA_CRT]],
            hooks=[file_hook(CA_CRT)]))

    create_db = [["sudo", "mkdir", "-p", os.path.dirname(SSL_DB)],
                 ["sudo", CERTGEN, "-c", "-s", SSL_DB, "-M", "4MB"],
                 ["sudo", "chown", "-R", f"{user}:{user}", SSL_DB]]
    if not root_exists(SSL_DB):
        steps.append(Step(
            f"Create {SSL_DB}, Squid's cache of the certificates it generates.",
            create_db, hooks=[dir_hook(SSL_DB, tree=True)]))
    elif new_ca:
        # Squid would keep serving the cached certificates, which the new CA
        # didn't sign, so the guests (trusting only the new one) reject them.
        steps.append(Step(
            f"Recreate {SSL_DB}, Squid's certificate cache: what it holds was "
            f"signed by an earlier CA, not the one created above. Only a "
            f"cache (Squid regenerates it), so it isn't saved; uninstall "
            f"removes the new one.",
            [["sudo", "rm", "-rf", "--one-file-system", SSL_DB]] + create_db,
            hooks=[dir_hook(SSL_DB, tree=True, replaced=True)]))

    changed = file_step(
        plan, steps, notes,
        "Install squid.conf: listens on the bridge address only, inspects "
        "TLS, and lets the sandboxes reach only the allowlisted domains."
        + ("" if installed else " Replaces the package's default config."),
        f"{SQUID_DIR}/squid.conf", conf)
    for name in ("allowed_domains.txt", "provision_domains.txt"):
        dest = f"{SQUID_DIR}/{name}"
        current = read_root(dest)
        if current is not None:
            # Edited in place (provisioning entries get commented out), so
            # never overwritten; only what create --claude needs is added.
            entries = domain_entries(current)
            missing = [d for d in CLAUDE_DOMAINS
                       if not allowlist_covers(entries, d)]
            if name != "allowed_domains.txt" or not missing:
                notes.append(f"{dest} exists and is kept as is.")
                continue
            changed |= file_step(
                plan, steps, notes,
                f"Add what Claude Code needs (create --claude) to {dest}: "
                f"{', '.join(missing)}. The rest of the file stays as it is.",
                dest, current + ("" if current.endswith("\n") or not current
                                 else "\n")
                + "\n# Added by glovebox host-setup: Claude Code (create "
                  "--claude)\n" + "".join(f"{d}\n" for d in missing))
            continue
        changed = True
        src = os.path.join(SQUID_SRC, name)
        steps.append(Step(f"Install the allowlist {dest}.",
                          [["sudo", "install", "-m", "0644", "-o", "root",
                            "-g", "root", src, dest]],
                          hooks=[file_hook(dest, read_repo(src))]))
    changed |= file_step(
        plan, steps, notes,
        "Install a systemd drop-in: Squid starts after libvirt and retries "
        "while the bridge isn't up yet, as its address only exists then.",
        SQUID_DROPIN, SQUID_DROPIN_TEXT)

    if capture(["ip", "link", "show", config.bridge]).returncode != 0 and \
            "network" not in plan.parts:
        notes.append(f"The bridge {config.bridge} is not up, so Squid can't "
                     f"start yet: run host-setup network first.")
    # A running Squid keeps the CA it started with (and its certificate
    # cache) until restarted.
    changed |= new_ca
    active, enabled = unit_state("squid.service")
    if changed or not (active and enabled):
        steps.append(Step(
            "Check the config, then start Squid now and at every boot.",
            [["sudo", "squid", "-k", "parse"],
             ["sudo", "systemctl", "daemon-reload"],
             ["sudo", "systemctl", "enable", "squid.service"],
             ["sudo", "systemctl", "restart", "squid.service"]],
            hooks=[service_hook("squid.service")]))
    else:
        notes.append("Squid is running and starts at boot.")


# --- ufw: bridge-scoped rules only -------------------------------------------------

def plan_ufw(plan, pm):
    steps, notes = plan.section("ufw: only rules on the bridge")
    if capture(["systemctl", "is-active", "firewalld"]).stdout.strip() == "active":
        notes.append(f"firewalld is active and isn't checked: make sure it "
                     f"doesn't drop traffic on {config.bridge}.")
    if not host_tool("ufw"):
        notes.append("UFW is not installed: nothing in the way.")
        return
    r = capture(["sudo", "ufw", "status", "verbose"])
    if r.returncode != 0:
        die(f"`ufw status verbose` failed: {r.stderr.strip()}")
    if "Status: active" not in r.stdout:
        notes.append("UFW is inactive: nothing in the way.")
        return
    m = re.search(r"^Default:\s*(\w+) \(incoming\).*?(\w+) \(routed\)",
                  r.stdout, re.M)
    if not m:
        die("Could not read UFW's default policies from `sudo ufw status "
            "verbose`; set UFW up by hand as docs/host-setup.md describes.")
    incoming, routed = m.groups()
    if routed == "disabled":
        # UFW shows "disabled" while IP forwarding is off, whatever its
        # forward policy; host-setup network may turn forwarding on in this
        # very run, and then the policy in /etc/default/ufw applies.
        policy = ufw_default("DEFAULT_FORWARD_POLICY")
        routed = {"ACCEPT": "allow", "DROP": "deny",
                  "REJECT": "reject"}.get((policy or "").upper())
        if routed is None:
            die(f"Could not read UFW's routed policy (DEFAULT_FORWARD_POLICY "
                f"in /etc/default/ufw: {policy!r}); set UFW up by hand as "
                f"docs/host-setup.md describes.")
    on_bridge = [l for l in r.stdout.splitlines() if f"on {config.bridge}" in l]
    blocking = ("deny", "reject")

    # ufw writes each rule to /etc/ufw/user.rules at once: it survives
    # reboots and `ufw reload`.
    if routed in blocking and not any("ALLOW FWD" in l for l in on_bridge):
        rule = ["route", "allow", "in", "on", config.bridge]
        steps.append(Step(
            f"UFW's routed policy is {routed}: it would drop what the "
            f"sandboxes send through the host. Allow routing from "
            f"{config.bridge} (saved by UFW, kept across reboots).",
            [["sudo", "ufw", *rule, "comment", "glovebox"]],
            hooks=[ufw_rule_hook(rule)]))
    if config.proxy and incoming in blocking:
        addr, port = proxy_endpoint()
        if not any("ALLOW IN" in l and f"{port}/tcp" in l for l in on_bridge):
            rule = ["allow", "in", "on", config.bridge, "to", addr, "port",
                    str(port), "proto", "tcp"]
            steps.append(Step(
                f"UFW's incoming policy is {incoming}: it would drop the "
                f"proxy-only sandboxes' connections to Squid. Allow only "
                f"{addr} port {port}/tcp from {config.bridge} (saved by "
                f"UFW, kept across reboots).",
                [["sudo", "ufw", *rule, "comment", "glovebox"]],
                hooks=[ufw_rule_hook(rule)]))

    sysctl_file, _, fixed = ufw_sysctl_fix()
    if fixed is not None:
        file_step(plan, steps, notes,
                  f"{sysctl_file} turns IPv4 forwarding off: UFW applies it "
                  f"at every start, after {SYSCTL_DEST}. Comment that line "
                  f"out.", sysctl_file, fixed)
    if steps:
        notes.append(f"These UFW changes affect {config.bridge} only; "
                     f"glovebox's own rules still decide what each VM may "
                     f"reach.")
    else:
        notes.append(f"UFW is active and lets the sandbox traffic through "
                     f"(defaults: {incoming} incoming, {routed} routed).")


def ufw_default(key):
    """The value of key in /etc/default/ufw (the last one wins, as when the
    shell sources it), or None."""
    value = None
    for line in (read_root("/etc/default/ufw") or "").splitlines():
        m = re.match(rf"\s*{key}\s*=\s*(['\"]?)(.*?)\1\s*$", line)
        if m:
            value = m.group(2)
    return value


def ufw_sysctl_fix():
    """UFW runs `sysctl -p` on the file named by IPT_SYSCTL in
    /etc/default/ufw at every start, after systemd-sysctl, so a value for
    ip_forward there wins over SYSCTL_DEST. Returns (file, content, the
    content with every ip_forward line other than 1 commented out, or None
    when there is nothing to fix)."""
    sysctl_file = ufw_default("IPT_SYSCTL")
    if sysctl_file is None:
        sysctl_file = "/etc/ufw/sysctl.conf"
    current = read_root(sysctl_file) if sysctl_file else None
    if current is None:
        return sysctl_file, None, None
    out, changed = [], False
    for line in current.splitlines(True):
        text = line.strip()
        if text and text[0] not in "#;" and "=" in text:
            key, _, val = text.partition("=")
            if key.strip().replace("/", ".") == "net.ipv4.ip_forward" \
                    and val.strip() != "1":
                line = f"# {line.lstrip()}" if line.endswith("\n") \
                    else f"# {line.lstrip()}\n"
                out.append("# glovebox: commented out, the sandboxes need "
                           "forwarding\n")
                changed = True
        out.append(line)
    return sysctl_file, current, "".join(out) if changed else None


PLANNERS = {"virt": plan_virt, "network": plan_network, "nftables": plan_nftables,
            "squid": plan_squid, "ufw": plan_ufw}


class Tee:
    """Writes what goes to the screen to the log file as well."""

    def __init__(self, stream, log_file):
        self.stream = stream
        self.log_file = log_file

    def write(self, text):
        self.stream.write(text)
        self.stream.flush()
        self.log_file.write(text)
        self.log_file.flush()
        return len(text)

    def flush(self):
        self.stream.flush()
        self.log_file.flush()


def start_log(command="host-setup"):
    """Copy the whole session (plan, answers, every command's output) to
    logs/<command>-<STAMP>.log, so what was done can be checked later."""
    os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
    # Named like the journal entries of this run; -2, -3... if run twice a
    # second.
    for i in range(1, 100):
        path = os.path.join(LOG_DIR, f"{command}-{STAMP}"
                            + (f"-{i}" if i > 1 else "") + ".log")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            continue
    else:
        die(f"Could not create a log file in {LOG_DIR}.")
    log_file = os.fdopen(fd, "w", encoding="utf-8")
    log_file.write(f"# glovebox {command} log\n# started: {journal.now()}\n"
                   f"# host: {socket.gethostname()}, user: "
                   f"{os.environ.get('USER', '?')}\n# command: "
                   f"{shlex.join(sys.argv)}\n\n")
    log_file.flush()
    sys.stdout = Tee(sys.stdout, log_file)
    sys.stderr = Tee(sys.stderr, log_file)

    def finish():
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__
        log_file.write(f"\n# finished: {journal.now()}\n")
        log_file.close()
        print(f"Log: {path}", file=sys.__stdout__, flush=True)
    atexit.register(finish)


def ask(prompt):
    """A yes/no question; the answer goes into the log too."""
    reply = input(f"{prompt} [y/N] ")
    if isinstance(sys.stdout, Tee):
        sys.stdout.log_file.write(f"{reply}\n")  # the terminal echoes it
    return reply.strip().lower() in ("y", "yes")


def run_logged(cmd):
    """Run cmd with its output shown and logged as it comes."""
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    last = b"\n"
    while chunk := p.stdout.read1(4096):
        sys.stdout.write(chunk.decode("utf-8", "replace"))
        last = chunk
    if not last.endswith(b"\n"):
        sys.stdout.write("\n")
    return p.wait()


def show(plan):
    n = 0
    for title, steps, notes in plan.sections:
        print(f"\n[{title}]")
        for s in steps:
            n += 1
            print(f"  {n}. {s.what}")
            for h in s.hooks:
                print(f"       + journal: {h.desc}")
            for cmd in s.cmds:
                print(f"       $ {shlex.join(cmd)}")
            if s.diff:
                for line in s.diff.splitlines():
                    print(f"       | {line}")
        if not steps and not notes:
            notes.append("Nothing to do.")
        for note in notes:
            print(f"  - {note}")
    return n


def execute(plan):
    steps = plan.steps()
    for i, s in enumerate(steps, 1):
        log(f"Step {i}/{len(steps)}: {s.what}")
        for h in s.hooks:
            if h.pre:
                h.pre()
        if s.fn:
            s.fn()
        failed = False
        for cmd in s.cmds:
            print(f"  $ {shlex.join(cmd)}", flush=True)
            if run_logged(cmd) != 0:
                failed = True
                break
        for h in s.hooks:
            if h.post:
                h.post()
        if failed:
            die(f"Step {i} failed; the steps after it did not run. What ran "
                f"is recorded in {journal.JOURNAL}.")
        if s.done:
            s.done()
    log(f"Done: {len(steps)} step(s).")


def confirm(plan, a):
    """Show the plan; True when it should run."""
    n = show(plan)
    print()
    if not n:
        log("Nothing to change.")
        return False
    if a.dry_run:
        log(f"Dry run: {n} step(s) planned, nothing changed.")
        return False
    if not ask(f"Run these {n} step(s)?"):
        log("Nothing changed.")
        return False
    return True


def cmd_host_setup(a):
    start_log()
    parts = [p for p in PARTS if p in a.parts or "all" in a.parts]
    pm = package_manager()
    log(f"Package manager: {pm}. Reading the host's current state (sudo)...")
    if a.forward_guard is not None and "nftables" not in parts:
        die("--forward-guard and --no-forward-guard belong to the nftables "
            "part: ./glovebox host-setup nftables --forward-guard (or all).")
    plan = Plan(parts)
    plan.interactive = not a.dry_run
    plan.forward_guard = a.forward_guard
    for part in parts:
        PLANNERS[part](plan, pm)
    if not confirm(plan, a):
        return
    execute(plan)
    log(f"Every change is recorded in {journal.JOURNAL}; ./glovebox "
        f"uninstall undoes them.")
    log("Verify from inside a VM: ./glovebox check <name>")
