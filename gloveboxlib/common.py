# glovebox: hardened, network-contained KVM sandboxes for AI agents.
# Copyright (C) 2026 MiCRoPhoBIC
# Derived from kvm-sandbox, Copyright (c) 2026 Ertuğ Karamatlı, under the
# MIT License (see LICENSE.MIT); modified by MiCRoPhoBIC in October 2026.
# Licensed under the GNU GPL v3 or later; see LICENSE.
# SPDX-License-Identifier: GPL-3.0-or-later

import getpass
import ipaddress
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import NoReturn


def log(msg):
    print(f"==> {msg}", flush=True)


def die(msg, code=1) -> NoReturn:
    print(f"ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


# Output glovebox parses (ufw status, virsh list/net-info, ...) is
# translated in other locales, so it's always read in the C locale. sudo
# may not pass LC_ALL on, hence env behind it too.
C_LOCALE = {"LC_ALL": "C", "LANGUAGE": ""}


def capture(cmd, **kwargs):
    if cmd and cmd[0] == "sudo":
        cmd = ["sudo", "env", "LC_ALL=C", "LANGUAGE=", *cmd[1:]]
    env = {**os.environ, **C_LOCALE}
    return subprocess.run(cmd, capture_output=True, text=True, env=env,
                          **kwargs)


def root_exists(path):
    return capture(["sudo", "test", "-e", path]).returncode == 0


def read_root(path):
    if not root_exists(path):
        return None
    r = capture(["sudo", "cat", path])
    if r.returncode != 0:
        die(f"Could not read {path}: {r.stderr.strip()}")
    return r.stdout


PASSWORD_ENV_VAR = "GLOVEBOX_PASSWORD"


def resolve_password(config, what="VM password", confirm=True):
    env_pw = os.environ.get(PASSWORD_ENV_VAR)
    if env_pw is not None:
        if not env_pw.strip():
            die(f"{PASSWORD_ENV_VAR} must be a non-empty string.")
        log(f"Using the {what} from ${PASSWORD_ENV_VAR}.")
        return env_pw

    pw = getattr(config, "password", None)
    if pw is not None:
        if not str(pw).strip():
            die("password in the config must not be blank; leave it out to "
                "be prompted for it.")
        log(f"Using the {what} from the config.")
        return pw

    return prompt_password(what, confirm=confirm)


def prompt_password(what="VM password", confirm=True):
    while True:
        pw = getpass.getpass(f"{what}: ")
        if not pw.strip():
            print("Password must not be empty.", file=sys.stderr, flush=True)
            continue
        if confirm and pw != getpass.getpass(f"Confirm {what}: "):
            print("Passwords do not match; try again.", file=sys.stderr, flush=True)
            continue
        return pw


# Label is one or more hyphen-separated alphanumeric segments, so no doubled
# or trailing hyphens leak into the hostname (an RFC-invalid hostname).
NAME_RE = re.compile(r"^sandbox([1-9][0-9]*)(?:-[A-Za-z0-9]+)*$")


def parse_n(name):
    m = NAME_RE.match(name)
    return int(m.group(1)) if m else None


def validate_name(name):
    n = parse_n(name)
    if n is None:
        die(f"VM name '{name}' must be 'sandbox<n>' or 'sandbox<n>-<label>', "
            f"e.g. sandbox5 or sandbox5-my-project.")
    return n


def resolve_ip(n, subnet, gateway, strict=True):
    if n is None or n >= subnet.num_addresses - 1:
        if strict:
            die(f"VM number {n} is out of range for {subnet}.")
        return None
    addr = subnet[n]
    if addr == gateway:
        if strict:
            die(f"VM number {n} maps to the gateway address ({addr}).")
        return None
    return str(addr)


def resolve_subnet(config):
    try:
        iface = ipaddress.ip_interface(config.host_address)
    except ValueError as e:
        die(f"Invalid host_address {config.host_address!r} in the config: {e}")
    subnet = iface.network
    gateway = iface.ip
    if gateway in (subnet.network_address, subnet.broadcast_address):
        die(f"host_address {config.host_address!r} in the config must "
            f"be a usable host address in its subnet, not the network or "
            f"broadcast address.")
    return subnet, gateway


def _nft_elem_contains(elem, addr):
    # An element with a comment/timeout is wrapped as {"elem": {"val": ...}}.
    if isinstance(elem, dict) and "elem" in elem:
        elem = elem["elem"].get("val")
    if isinstance(elem, str):
        return ipaddress.ip_address(elem) == addr
    if isinstance(elem, dict) and "range" in elem:
        lo, hi = (ipaddress.ip_address(x) for x in elem["range"])
        return lo <= addr <= hi
    if isinstance(elem, dict) and "prefix" in elem:
        p = elem["prefix"]
        return addr in ipaddress.ip_network(f"{p['addr']}/{p['len']}", strict=False)
    # Unknown form: not a match, so the VM is treated as proxy-only.
    return False


def nft_set_contains(nft_json, ip):
    addr = ipaddress.ip_address(ip)
    for obj in json.loads(nft_json).get("nftables", []):
        elems = obj.get("set", {}).get("elem", [])
        if any(_nft_elem_contains(e, addr) for e in elems):
            return True
    return False


def nft_set_json(set_name):
    # Read-only: the host ruleset is the source of truth; glovebox never
    # adds or removes elements itself.
    r = capture(["sudo", "nft", "-j", "list", "set", "inet", "glovebox",
                 set_name])
    if r.returncode != 0:
        die(f"nftables set 'inet glovebox {set_name}' not found; load the "
            f"rules with ./glovebox host-setup nftables (see docs/host-setup.md).\n"
            f"  nft: {r.stderr.strip()}")
    return r.stdout


def in_nft_set(set_name, ip):
    try:
        return nft_set_contains(nft_set_json(set_name), ip)
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        die(f"Could not parse the nftables set '{set_name}': {e}")


def _nft_addr_range(spec):
    # (low, high, text) of an address, range or prefix in nft JSON.
    if isinstance(spec, str):
        a = ipaddress.ip_address(spec)
        return a, a, spec
    if "range" in spec:
        lo, hi = (ipaddress.ip_address(x) for x in spec["range"])
        return lo, hi, f"{lo}-{hi}"
    p = spec["prefix"]
    net = ipaddress.ip_network(f"{p['addr']}/{p['len']}", strict=False)
    return net[0], net[-1], str(net)


class AllowRule:
    """One private_allow entry that applies to a VM: destination address(es),
    protocol and port(s), with the entry's comment if it has one."""

    PROTOS = {6: "tcp", 17: "udp"}

    def __init__(self, dst, proto, ports, comment=None):
        self.dst_lo, self.dst_hi, self.dst_text = _nft_addr_range(dst)
        self.proto = self.PROTOS.get(proto, str(proto))
        if isinstance(ports, dict):
            self.port_lo, self.port_hi = (int(x) for x in ports["range"])
        else:
            self.port_lo = self.port_hi = int(ports)
        self.comment = comment

    def sample_ip(self):
        # The first usable address: a prefix's first one is its network
        # address.
        if "/" in self.dst_text and int(self.dst_hi) - int(self.dst_lo) > 1:
            return self.dst_lo + 1
        return self.dst_lo

    def matches(self, ip, proto, port):
        return (proto == self.proto
                and self.dst_lo <= ipaddress.ip_address(ip) <= self.dst_hi
                and self.port_lo <= int(port) <= self.port_hi)

    def ports_text(self):
        if self.port_lo == self.port_hi:
            return str(self.port_lo)
        return f"{self.port_lo}-{self.port_hi}"

    def __str__(self):
        return (f"{self.dst_text} {self.proto}/{self.ports_text()}"
                + (f" ({self.comment})" if self.comment else ""))


def private_allow_rules(ip):
    """The private_allow entries whose source covers ip."""
    addr = ipaddress.ip_address(ip)
    rules = []
    try:
        for obj in json.loads(nft_set_json("private_allow")).get("nftables", []):
            for elem in obj.get("set", {}).get("elem", []):
                comment = None
                if "elem" in elem:  # an element with a comment
                    comment = elem["elem"].get("comment")
                    elem = elem["elem"]["val"]
                src, dst, proto, ports = elem["concat"]
                lo, hi, _ = _nft_addr_range(src)
                if lo <= addr <= hi:
                    rules.append(AllowRule(dst, proto, ports, comment))
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        die(f"Could not parse the nftables set 'private_allow': {e}")
    return rules


DIRECT, PROXY = "direct", "proxy"

# Guest kernel hardening that create applies and check verifies.
GUEST_LOCKDOWN = "integrity"
GUEST_SYSCTLS = {
    "kernel.kptr_restrict": "2",            # no kernel addresses for exploits
    "kernel.dmesg_restrict": "1",
    "kernel.yama.ptrace_scope": "1",        # ptrace own children only
    "kernel.unprivileged_bpf_disabled": "1",  # and can't be turned back on
    "kernel.kexec_load_disabled": "1",
}
MODE_DESCRIPTIONS = {
    DIRECT: "direct internet",
    PROXY: "internet only through the proxy",
}


def egress_mode(ip):
    direct = in_nft_set("direct_internet", ip)
    proxied = in_nft_set("proxy_internet", ip)
    if direct and proxied:
        die(f"{ip} is in both nftables sets direct_internet and proxy_internet; "
            f"fix host-setup/nftables/glovebox.conf and reload it.")
    if not (direct or proxied):
        # The firewall still drops such a VM (fail-closed); there is just no
        # supported no-internet mode to configure or verify it for.
        die(f"{ip} is in neither nftables set direct_internet nor "
            f"proxy_internet; pick a VM number from one of their ranges.")
    return DIRECT if direct else PROXY


def is_private_address(ip, config):
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(n) for n in config.check_private_nets)


def require_not_root():
    if os.geteuid() == 0:
        die("Run as your normal user, not root. The script calls sudo itself.")


# The guest account names a VM was created with, kept in its libvirt domain
# XML (<metadata>), so check logs in with the names create used.
METADATA_URI = "urn:glovebox"
METADATA_KEY = "glovebox"


def vm_users_metadata(user, agent_user):
    el = ET.Element("users", user=user)
    if agent_user:
        el.set("agent_user", agent_user)
    return ET.tostring(el, encoding="unicode")


def glovebox_users(name):
    """(user, agent_user) from the metadata create records, or None for a VM
    glovebox didn't create."""
    r = capture(["sudo", "virsh", "metadata", name, METADATA_URI, "--config"])
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        el = ET.fromstring(r.stdout)
    except ET.ParseError:
        return None
    return (el.get("user"), el.get("agent_user")) if el.get("user") else None


def read_vm_users(name):
    # (user, agent_user) as create recorded them in the VM's metadata.
    r = capture(["sudo", "virsh", "metadata", name, METADATA_URI, "--config"])
    # Missing metadata is an error on some libvirt versions and empty output
    # on others.
    if r.returncode != 0 or not r.stdout.strip():
        die(f"Could not read the account names of '{name}' from its libvirt "
            f"metadata{': ' + r.stderr.strip() if r.stderr.strip() else ''}."
            f"\nIs it a VM glovebox create made? Check 'sudo virsh list "
            f"--all'.", code=2)
    try:
        el = ET.fromstring(r.stdout)
    except ET.ParseError as e:
        die(f"Bad glovebox metadata on '{name}': {e}", code=2)
    if not el.get("user"):
        die(f"The glovebox metadata on '{name}' names no user.", code=2)
    return el.get("user"), el.get("agent_user")


# What Claude Code (create --claude) reaches: the API, login (OAuth), and
# the installer and its updates. host-setup keeps them in the permanent
# allowlist; create --claude checks them on a proxy-only VM.
CLAUDE_DOMAINS = ("api.anthropic.com", "claude.ai", "platform.claude.com",
                  "downloads.claude.ai")
CLAUDE_INSTALLER = "https://claude.ai/install.sh"


def domain_entries(text):
    """The entries of a Squid dstdomain file, without comments."""
    return [ln.split("#", 1)[0].strip() for ln in text.splitlines()
            if ln.split("#", 1)[0].strip()]


def allowlist_covers(allowlist, domain):
    # Squid dstdomain: "example.com" is that host only; ".example.com" is the
    # domain and all its subdomains.
    return any(e == domain or (e.startswith(".") and
                               (domain == e[1:] or domain.endswith(e)))
               for e in allowlist)


# Debian package names (policy 5.6.1), optionally with =version or /release.
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]+(?:[=/][A-Za-z0-9+.:~-]+)?$")


def read_packages(path):
    # One or more whitespace-separated names per line; # starts a comment.
    packages = []
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            for word in line.split("#", 1)[0].split():
                if not PACKAGE_RE.fullmatch(word):
                    die(f"{path}:{lineno}: '{word}' is not a Debian package "
                        f"name.")
                if word not in packages:
                    packages.append(word)
    return packages
