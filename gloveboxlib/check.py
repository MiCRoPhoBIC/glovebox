# glovebox: hardened, network-contained KVM sandboxes for AI agents.
# Copyright (C) 2026 MiCRoPhoBIC
# Derived from kvm-sandbox, Copyright (c) 2026 Ertuğ Karamatlı, under the
# MIT License (see LICENSE.MIT); modified by MiCRoPhoBIC in October 2026.
# Licensed under the GNU GPL v3 or later; see LICENSE.
# SPDX-License-Identifier: GPL-3.0-or-later

import ipaddress
import os
import re
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from .config import config
from .common import (DIRECT, GUEST_LOCKDOWN, GUEST_SYSCTLS, MODE_DESCRIPTIONS,
                     PROXY, allowlist_covers, capture, die, domain_entries,
                     egress_mode, in_nft_set, log, parse_n,
                     private_allow_rules, read_vm_users, resolve_ip,
                     resolve_password)

# The VM's accounts, from its metadata (set by cmd_check).
vm_user, vm_agent_user = None, None


def private_nets():
    try:
        nets = [ipaddress.ip_network(n) for n in config.check_private_nets]
    except ValueError as e:
        die(f"invalid check_private_nets in the config: {e}")
    if not nets:
        die("check_private_nets in the config must list at least "
            "one network.")
    return nets


def is_probe_target(ip_str, nets):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    is_private = any(addr in net for net in nets)
    return not addr.is_loopback and is_private


def ssh_vm(ip, command, sudo_password=None, stream=False):
    # sudo_password is forwarded on stdin to the remote command
    # (e.g. for a `sudo -S ...` command), not consumed by ssh.
    cmd = ["ssh", "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null",
           "-o", "ConnectTimeout=5",
           f"{vm_user}@{ip}", command]
    stdin = None if sudo_password is None else sudo_password + "\n"
    # stream=True: output goes straight to the terminal (for long-running
    # commands like apt-get), so stdout/stderr come back as None.
    if stream:
        r = subprocess.run(cmd, text=True, input=stdin)
    else:
        r = capture(cmd, input=stdin)
    if r.returncode == 255:
        die(f"Cannot SSH to {vm_user}@{ip}. The VM may not exist, may not "
            f"be running, may still be finishing cloud-init, or may use a "
            f"different user. Check 'sudo virsh list --all' and wait for SSH "
            f"to come up.\n  ssh error: {(r.stderr or '').strip()}", code=2)
    return r


def die_tool_missing(tool, vm_ip):
    die(f"{tool} is not installed in the VM ({vm_user}@{vm_ip}); the check "
        f"runs {tool} from inside the sandbox.\n"
        f"Re-run with --install-tools, or install it there yourself.", code=2)


def sandbox_ips(subnet, gateway):
    r = capture(["sudo", "virsh", "list", "--name"])
    if r.returncode != 0:
        log(f"WARNING: could not list running VMs (virsh exit "
            f"{r.returncode}): {r.stderr.strip()}")
        return []
    return [ip for name in r.stdout.split()
            if (ip := resolve_ip(parse_n(name), subnet, gateway, strict=False))]


def enumerate_targets(vm_ip, subnet, gateway, nets):
    # simply grab all IPs, false positives don't matter
    cmds = [
        ["ip", "-4", "addr"],
        ["ip", "-4", "neigh"],
        ["ip", "-4", "route", "show", "table", "all"],
        ["ss", "-4tn"],
        ["ss", "-4un"],
    ]
    lines = []
    for cmd in cmds:
        try:
            r = capture(cmd)
        except FileNotFoundError as e:
            die(f"'{shlex.join(cmd)}' failed: {e}.", code=2)
        if r.returncode != 0:
            die(f"'{shlex.join(cmd)}' failed (exit {r.returncode}): "
                f"{r.stderr.strip()}.", code=2)
        lines.extend(r.stdout.splitlines())

    lines = [ln for ln in lines if "FAILED" not in ln and "INCOMPLETE" not in ln]
    cands = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "\n".join(lines)))

    # Cloud-metadata service and a common router address, plus a representative
    # IP per private block so ranges the host has no presence in are still probed.
    cands.update(["169.254.169.254", "192.168.1.1"])
    cands.update(str(net[1]) if net.num_addresses > 2 else str(net[0])
                 for net in nets)

    cands.update(sandbox_ips(subnet, gateway))

    unhostable = {str(subnet.network_address), str(subnet.broadcast_address)}

    cands = {c for c in cands
             if c != vm_ip and c not in unhostable and is_probe_target(c, nets)}

    return sorted(cands, key=ipaddress.ip_address)


def _parse_nmap_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    results = []
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue
        ip = addr.get("addr")
        ports = []
        for port in host.findall("./ports/port"):
            st = port.find("state")
            ports.append((port.get("protocol"), port.get("portid"),
                          st.get("state") if st is not None else None))
        results.append((ip, ports))
    return results


def install_tools(vm_ip, sudo_password):
    log("Installing nmap and curl in the VM...")
    # -p '' suppresses sudo's password prompt, which would otherwise show up
    # in the streamed output.
    r = ssh_vm(vm_ip, "sudo -S -p '' sh -c "
                      "'apt-get update && apt-get install -y nmap curl'",
               sudo_password=sudo_password, stream=True)
    if r.returncode != 0:
        die(f"Failed to install nmap/curl in the VM ({vm_user}@{vm_ip}, "
            f"exit {r.returncode}); see output above.", code=2)


def nmap_states(vm_ip, targets, tcp_ports, udp_ports, sudo_password):
    """Scan from inside the VM; returns ({(ip, proto, port): state}, the
    targets nmap reported nothing for)."""
    # -Pn skips host discovery, which would just be another redundant connect.
    port_spec = ",".join(f"{kind}:{ports}" for kind, ports
                         in (("T", tcp_ports), ("U", udp_ports)) if ports)
    scan = ["sudo", "-S", "nmap", "-n", "-Pn",
            *(["-sS"] if tcp_ports else []), *(["-sU"] if udp_ports else []),
            "-p", port_spec,
            "--max-retries", "1",
            "-T4", "-oX", "-"] + targets
    r = ssh_vm(vm_ip, shlex.join(scan), sudo_password=sudo_password)
    if r.returncode != 0:
        if "not found" in r.stderr.lower():
            die_tool_missing("nmap", vm_ip)
        # includes a wrong sudo password
        die(f"nmap scan failed (exit {r.returncode}): {r.stderr.strip()}",
            code=2)
    states = {}
    scanned_ips = set()
    for ip, ports in _parse_nmap_xml(r.stdout):
        scanned_ips.add(ip)
        for proto, port, state in ports:
            states[(ip, proto, port)] = state
    missing = sorted((t for t in targets if t not in scanned_ips),
                     key=ipaddress.ip_address)
    return states, missing


def run_remote_nmap(vm_ip, targets, tcp_ports, udp_ports, sudo_password):
    states, missing = nmap_states(vm_ip, targets, tcp_ports, udp_ports,
                                  sudo_password)
    if missing:
        log(f"WARNING: nmap reported no result for {len(missing)} "
            f"target(s); their containment is UNVERIFIED: "
            f"{', '.join(missing)}")
    # open or closed: a packet came back, so nothing on the way dropped it.
    findings = {}
    for (ip, proto, port), state in states.items():
        if state in ("open", "closed"):
            findings.setdefault(ip, set()).add((proto, port))
    return findings


# What a probe of an allowed service found, by nmap port state.
ALLOWED_RESULTS = {
    "open": ("ok", "reachable, the service answers"),
    "closed": ("warn", "the firewall lets it through, but nothing listens "
                       "on that port"),
    "filtered": ("warn", "no answer: the service is down, or something "
                         "outside glovebox drops it (the target's own "
                         "firewall, UFW's routed policy)"),
    "open|filtered": ("info", "no UDP reply, so it can't be confirmed (many "
                              "UDP services ignore an empty probe)"),
}


def check_private_allow(vm_ip, mode, rules, sudo_password, report):
    """Probe every private_allow entry for this VM from inside it: an allowed
    service should answer. For a range, its first address and port stand in
    for the rest."""
    if not rules:
        report.add("ok", "none configured: no private service is allowed "
                         "for this VM (nftables set private_allow)")
        return
    probes = {}
    for rule in rules:
        probes[rule] = (str(rule.sample_ip()), rule.proto, str(rule.port_lo))
    tcp = sorted({p for _, proto, p in probes.values() if proto == "tcp"}, key=int)
    udp = sorted({p for _, proto, p in probes.values() if proto == "udp"}, key=int)
    targets = sorted({ip for ip, _, _ in probes.values()}, key=ipaddress.ip_address)
    log(f"Probing the {len(rules)} allowed private service(s) from inside "
        f"the VM...")
    states, _ = nmap_states(vm_ip, targets, ",".join(tcp), ",".join(udp),
                            sudo_password)
    for rule, (ip, proto, port) in probes.items():
        state = states.get((ip, proto, port), "no result")
        status, what = ALLOWED_RESULTS.get(
            state, ("warn", f"nmap: {state}"))
        sample = ""
        if (rule.dst_lo, rule.port_lo) != (rule.dst_hi, rule.port_hi):
            sample = f" [probed {ip} {proto}/{port}]"
        report.add(status, f"{rule}{sample}: {what}")
        if mode == PROXY and rule.port_lo <= 53 <= rule.port_hi:
            report.add("info", f"{rule}: a DNS resolver reachable from a "
                               f"proxy-only VM can carry data around the "
                               f"proxy; keep it if that's intended")


INTERNET_URL = "https://example.com"
# An IP literal, so a blocked VM's direct probe tests the firewall rather
# than failing early on DNS.
DIRECT_PROBE_URL = "https://1.1.1.1"
DNS_PROBE_NAME = "example.com"


class Report:
    # Egress results: FAIL rows mean containment is broken; warn rows are
    # functional problems (e.g. an allowlisted domain not loading).
    def __init__(self):
        self.rows = []
        self.failed = False

    def add(self, status, what):
        self.rows.append((status, what))
        if status == "FAIL":
            self.failed = True
        log(f"[{status}] {what}")


def proxy_endpoint():
    u = urlsplit(config.proxy)
    return u.hostname, u.port or 80


def check_internet_reachable(vm_ip, report):
    # The check is "internet reachable, private addresses not" — confirm the
    # internet half first, since a dead NIC or no route would make every
    # private target look unreachable too.
    log("Checking that the internet is reachable...")
    r = ssh_vm(vm_ip, f"curl -fsS --max-time 15 -o /dev/null {INTERNET_URL}")
    if r.returncode != 0:
        if "not found" in r.stderr.lower():
            die_tool_missing("curl", vm_ip)
        die(f"Internet unreachable: the VM could not fetch {INTERNET_URL}: "
            f"{r.stderr.strip()}\nThe VM may have no egress, no DNS, or a "
            f"dead network, so a containment result would be meaningless. "
            f"Fix connectivity and re-run.", code=2)
    report.add("ok", f"direct internet and DNS work ({INTERNET_URL})")


def run_remote_ping(vm_ip, targets, sudo_password):
    # ICMP echo only (-sn -PE): a host reported up answered a ping.
    scan = ["sudo", "-S", "nmap", "-n", "-sn", "-PE", "--max-retries", "1",
            "-oX", "-"] + list(targets)
    r = ssh_vm(vm_ip, shlex.join(scan), sudo_password=sudo_password)
    if r.returncode != 0:
        if "not found" in r.stderr.lower():
            die_tool_missing("nmap", vm_ip)
        die(f"nmap ping scan failed (exit {r.returncode}): {r.stderr.strip()}",
            code=2)
    try:
        root = ET.fromstring(r.stdout)
    except ET.ParseError:
        die("Could not parse the nmap ping scan output.", code=2)
    return [h.find("address[@addrtype='ipv4']").get("addr")
            for h in root.findall("host")
            if h.find("status") is not None
            and h.find("status").get("state") == "up"]


def check_direct_blocked(vm_ip, sudo_password, report):
    # Proxy-only VMs: nothing may leave directly, over any
    # protocol, including DNS (a tunnel around the proxy).
    log(f"Checking that direct HTTPS is blocked ({DIRECT_PROBE_URL})...")
    # --noproxy: the guest's /etc/environment sets the proxy for SSH sessions.
    # Blocked means no TCP connection at all (7: refused, 28: timed out);
    # anything else, even a TLS error, means a packet got out directly.
    r = ssh_vm(vm_ip, f"curl -sS -k --noproxy '*' --connect-timeout 8 "
                      f"--max-time 15 -o /dev/null {DIRECT_PROBE_URL}")
    if r.returncode == 127 or "not found" in r.stderr.lower():
        die_tool_missing("curl", vm_ip)
    if r.returncode in (7, 28):
        report.add("ok", f"direct HTTPS to {DIRECT_PROBE_URL} blocked")
    else:
        report.add("FAIL", f"direct HTTPS to {DIRECT_PROBE_URL} got through "
                           f"(curl exit {r.returncode})")

    r = ssh_vm(vm_ip, f"getent ahostsv4 {DNS_PROBE_NAME}")
    if r.returncode == 0:
        report.add("FAIL", f"name resolution works ({DNS_PROBE_NAME}); DNS "
                           f"could tunnel around the proxy")
    else:
        report.add("ok", f"no name resolution ({DNS_PROBE_NAME})")

    targets = list(config.check_public_targets)
    log(f"Probing public targets directly with nmap: {', '.join(targets)}...")
    findings = run_remote_nmap(vm_ip, targets, config.check_tcp_ports,
                               config.check_udp_ports, sudo_password)
    for ip in sorted(findings, key=ipaddress.ip_address):
        for proto, port in sorted(findings[ip], key=lambda t: (t[0], int(t[1]))):
            report.add("FAIL", f"direct {proto}/{port} to {ip} got through")
    if not findings:
        report.add("ok", f"no TCP/UDP port reachable directly on "
                         f"{', '.join(targets)}")
    up = run_remote_ping(vm_ip, targets, sudo_password)
    if up:
        report.add("FAIL", f"ICMP echo answered by {', '.join(up)}")
    else:
        report.add("ok", "no ICMP echo reply from public targets")


def check_proxy_reachable(vm_ip, expected, report):
    if not config.proxy:
        report.add("warn", "proxy is off (\"\") in the config; proxy "
                           "reachability not tested")
        return False
    # Any CONNECT reply, including a 403 for a domain outside the allowlist,
    # means the proxy is reachable; 000 means no reply.
    r = ssh_vm(vm_ip, f"curl -sS --connect-timeout 8 --max-time 15 "
                      f"-o /dev/null --proxy {shlex.quote(config.proxy)} "
                      f"-w '%{{http_connect}}' {INTERNET_URL}")
    code = r.stdout.strip()
    reachable = bool(code) and code != "000"
    if reachable == expected:
        report.add("ok", f"proxy {config.proxy} "
                         f"{'reachable' if reachable else 'unreachable'}")
    elif expected:
        report.add("FAIL", f"proxy {config.proxy} unreachable: "
                           f"{r.stderr.strip()} (does it listen on the bridge "
                           f"address; does the host firewall, e.g. UFW, admit "
                           f"the bridge to its port?)")
    else:
        report.add("FAIL", f"proxy {config.proxy} reachable, but this VM "
                           f"isn't in proxy_internet")
    return reachable


def proxy_fetch(vm_ip, url, host_header=None):
    # Returns (outcome, detail); outcome is "passed" (the origin answered),
    # "denied" (the proxy refused), "terminated" (the proxy cut the TLS
    # handshake after CONNECT, i.e. ssl_bump terminate) or "error".
    cmd = (f"curl -sS --max-time 20 -o /dev/null -D - "
           f"--proxy {shlex.quote(config.proxy)} "
           f"-w '\\n__kvm__ %{{http_connect}} %{{http_code}}\\n' ")
    if host_header:
        cmd += f"-H {shlex.quote('Host: ' + host_header)} "
    r = ssh_vm(vm_ip, cmd + shlex.quote(url))
    m = re.search(r"^__kvm__ (\d+) (\d+)$", r.stdout, re.M)
    connect, code = m.groups() if m else ("000", "000")
    squid_err = re.search(r"^x-squid-error:\s*(\S+)", r.stdout, re.I | re.M)
    if squid_err:
        err = squid_err.group(1)
        denied = err in ("ERR_ACCESS_DENIED", "ERR_CONFLICT_HOST")
        return ("denied" if denied else "error"), f"proxy {err}"
    if connect not in ("000", "200"):
        return "denied", f"CONNECT answered {connect}"
    if r.returncode == 35 and connect == "200":
        return "terminated", "TLS cut by the proxy"
    if r.returncode == 60:
        return "error", "TLS certificate not trusted (proxy CA missing in the VM?)"
    if r.returncode == 0 and code != "000":
        return "passed", f"HTTP {code}"
    return "error", f"curl exit {r.returncode}: {r.stderr.strip()}"


def read_domain_file(setting):
    # A Squid dstdomain file named by a the config setting, read via
    # sudo; None when the setting is None.
    path = getattr(config, setting)
    if not path:
        return None
    r = capture(["sudo", "cat", path])
    if r.returncode != 0:
        die(f"Could not read {setting} '{path}': {r.stderr.strip()}", code=2)
    return domain_entries(r.stdout)


def check_proxy_policy(vm_ip, report):
    def expect_denied(what, url, host_header=None, allow_terminated=True):
        outcome, detail = proxy_fetch(vm_ip, url, host_header)
        ok = outcome == "denied" or (allow_terminated and outcome == "terminated")
        report.add("ok" if ok else "FAIL", f"{what}: {outcome} ({detail})")

    allowlist = read_domain_file("proxy_allowed_domains")
    if allowlist is None:
        report.add("warn", "proxy_allowed_domains is None; allowlist, domain "
                           "fronting and port tests skipped")
        allowlist = []
    provision = read_domain_file("proxy_provision_domains") or []
    for what, entries in (("allowlisted", allowlist),
                          ("provisioning", provision)):
        for entry in entries:
            host = entry.lstrip(".")
            outcome, detail = proxy_fetch(vm_ip, f"https://{host}/")
            report.add("ok" if outcome == "passed" else "warn",
                       f"{what} {host}: {outcome} ({detail})")
    if provision:
        report.add("warn", f"provisioning domains open "
                           f"({config.proxy_provision_domains}); comment them "
                           f"out and `sudo squid -k reconfigure` when done")
    # Fronting and port tests below need an allowed entry, the denial tests a
    # domain that no list allows.
    allowlist = allowlist + provision

    denied = [d for d in config.check_denied_domains
              if not allowlist_covers(allowlist, d)]
    for d in denied:
        expect_denied(f"non-allowlisted https://{d}", f"https://{d}/")
        expect_denied(f"non-allowlisted http://{d}", f"http://{d}/")
    for ip in config.check_public_targets[:1]:
        expect_denied(f"IP literal https://{ip}", f"https://{ip}/")
        # Plain HTTP too: that's where a reverse-DNS match would get through.
        expect_denied(f"IP literal http://{ip}", f"http://{ip}/")
    if allowlist and denied:
        a = allowlist[0].lstrip(".")
        # Domain fronting: an allowed name on the wire, another in Host.
        expect_denied(f"fronting https://{a} with Host: {denied[0]}",
                      f"https://{a}/", host_header=denied[0])
        # CONNECT to a non-TLS port of an allowed host (e.g. an SSH tunnel)
        # must be refused outright, not merely fail later.
        expect_denied(f"CONNECT to {a}:22", f"https://{a}:22/",
                      allow_terminated=False)


# Groups that amount to root (or to reading secrets) in the guest.
PRIVILEGED_GROUPS = {"root", "sudo", "wheel", "admin", "adm", "disk", "shadow",
                     "docker", "lxd", "libvirt"}


def read_host_file(path):
    r = capture(["sudo", "cat", path])
    return r.stdout if r.returncode == 0 else None


def check_host_hardening(name, report):
    # The QEMU process is what a VM escape lands in: it must run unprivileged
    # under QEMU's seccomp sandbox. LSM confinement (AppArmor/SELinux via
    # libvirt's sVirt) is not required, only reported: many hosts (e.g.
    # Arch-based ones) run without either.
    pid = (read_host_file(f"/run/libvirt/qemu/{name}.pid") or "").strip()
    status = read_host_file(f"/proc/{pid}/status") if pid.isdigit() else None
    if status is None:
        report.add("FAIL", f"QEMU process of '{name}' not found "
                           f"(/run/libvirt/qemu/{name}.pid)")
        return
    fields = dict(ln.split(":", 1) for ln in status.splitlines() if ":" in ln)
    euid = fields.get("Uid", "0 0").split()[1]
    report.add("ok" if euid != "0" else "FAIL",
               f"QEMU runs as uid {euid}" + ("" if euid != "0" else " (root)"))
    seccomp = fields.get("Seccomp", "").strip()
    report.add("ok" if seccomp == "2" else "FAIL",
               "QEMU seccomp sandbox " + ("on" if seccomp == "2" else
                                          f"off (Seccomp: {seccomp or '?'}; "
                                          f"seccomp_sandbox in qemu.conf)"))
    label = (read_host_file(f"/proc/{pid}/attr/apparmor/current")
             or read_host_file(f"/proc/{pid}/attr/current") or "").strip("\0\n ")
    confined = label and label != "unconfined" and \
        ("libvirt-" in label or "svirt" in label) and "complain" not in label
    report.add("ok" if confined else "info",
               f"QEMU confined by sVirt: {label}" if confined else
               f"QEMU not confined by AppArmor/SELinux "
               f"({label or 'no LSM label'}; optional)")

    xml = capture(["sudo", "virsh", "dumpxml", name]).stdout
    ksm_on = (read_host_file("/sys/kernel/mm/ksm/run") or "0").strip() != "0"
    if "<nosharepages/>" in xml or not ksm_on:
        report.add("ok", "no memory page sharing with other VMs"
                         + ("" if ksm_on else " (KSM off)"))
    else:
        report.add("FAIL", "KSM is on and the VM lacks nosharepages, so it "
                           "may share memory pages with other VMs")

    vulns = []
    vdir = "/sys/devices/system/cpu/vulnerabilities"
    for entry in sorted(os.listdir(vdir)) if os.path.isdir(vdir) else []:
        with open(os.path.join(vdir, entry)) as f:
            if f.read().startswith("Vulnerable"):
                vulns.append(entry)
    report.add("warn" if vulns else "ok",
               "host CPU: " + (f"unmitigated {', '.join(vulns)} (update "
                               f"kernel/microcode)" if vulns else
                               "no unmitigated vulnerabilities"))


def check_guest_hardening(vm_ip, sudo_password, report):
    keys = list(GUEST_SYSCTLS)
    agent = vm_agent_user
    script = ["cat /sys/kernel/security/lockdown 2>/dev/null || echo none"]
    script += [f"sysctl -n {k} 2>/dev/null || echo missing" for k in keys]
    if agent:
        script += [f"(id -nG {shlex.quote(agent)} 2>/dev/null || echo nouser) | tr ' ' ,",
                   f"sudo -n -l -U {shlex.quote(agent)} 2>&1 | head -n 1",
                   f"stat -c %a /home/{shlex.quote(vm_user)}"]
    r = ssh_vm(vm_ip, "sudo -S -p '' sh -c " + shlex.quote("; ".join(script)),
               sudo_password=sudo_password)
    out = r.stdout.splitlines()
    if r.returncode != 0 or len(out) < 1 + len(keys):
        report.add("FAIL", f"guest hardening check failed: {r.stderr.strip()}")
        return
    lockdown = out[0]
    ok = f"[{GUEST_LOCKDOWN}]" in lockdown or "[confidentiality]" in lockdown
    # Lockdown starts with the reboot that ends the first boot.
    report.add("ok" if ok else "FAIL", f"guest kernel lockdown: {lockdown}"
               + ("" if ok else " (first boot not finished yet? Wait for its "
                                "reboot and re-run)"))
    wrong = [f"{k}={v}" for k, v in zip(keys, out[1:]) if v != GUEST_SYSCTLS[k]]
    report.add("FAIL" if wrong else "ok", "guest sysctls " +
               (f"not hardened: {', '.join(wrong)}" if wrong else "hardened"))
    if not agent:
        report.add("warn", "agent_user is off: the agent runs with sudo rights")
        return
    groups, sudo_l, home_mode = out[1 + len(keys):4 + len(keys)]
    if groups == "nouser":
        report.add("FAIL", f"no '{agent}' account in the VM")
        return
    bad = PRIVILEGED_GROUPS & set(groups.split(","))
    report.add("FAIL" if bad else "ok", f"agent '{agent}' groups: {groups}"
               + (f" (privileged: {', '.join(sorted(bad))})" if bad else ""))
    no_sudo = "not allowed to run sudo" in sudo_l
    report.add("ok" if no_sudo else "FAIL",
               f"agent '{agent}' has no sudo" if no_sudo else
               f"agent '{agent}' can use sudo: {sudo_l}")
    private = home_mode.isdigit() and home_mode.endswith("0")
    report.add("ok" if private else "FAIL",
               f"/home/{vm_user} mode {home_mode}"
               + ("" if private else " (readable by the agent)"))


def allowed_reason(mode, rules, ip, proto, port):
    """Why the configuration allows the VM to reach a private service, or
    None if it doesn't."""
    if mode == PROXY and config.proxy and \
            (ip, proto, port) == (proxy_endpoint()[0], "tcp",
                                  str(proxy_endpoint()[1])):
        return "the proxy (egress mode: proxy-only)"
    if mode == DIRECT and port == "53" and in_nft_set("private_dns", ip):
        return "private DNS resolver (nftables set private_dns)"
    for rule in rules:
        if rule.matches(ip, proto, port):
            return f"private_allow: {rule}"
    return None


def cmd_check(a):
    global vm_user, vm_agent_user
    name, vm_ip = a.name, a.ip
    nets = private_nets()
    vm_user, vm_agent_user = read_vm_users(name)

    # Connectivity probe before the password prompt
    ssh_vm(vm_ip, "true")

    mode = egress_mode(vm_ip)
    log(f"Egress mode: {MODE_DESCRIPTIONS[mode]} (per the nftables sets).")
    rules = private_allow_rules(vm_ip)

    sudo_password = resolve_password(config, what="VM sudo password", confirm=False)

    hardening = Report()
    check_host_hardening(name, hardening)
    check_guest_hardening(vm_ip, sudo_password, hardening)

    # Before the egress checks, which need curl and nmap in the guest.
    if a.install_tools:
        install_tools(vm_ip, sudo_password)

    report = Report()
    if mode == DIRECT:
        check_internet_reachable(vm_ip, report)
        check_proxy_reachable(vm_ip, False, report)
    else:
        check_direct_blocked(vm_ip, sudo_password, report)
        if check_proxy_reachable(vm_ip, True, report):
            check_proxy_policy(vm_ip, report)

    allowed = Report()
    check_private_allow(vm_ip, mode, rules, sudo_password, allowed)

    targets = enumerate_targets(vm_ip, a.subnet, a.gateway, nets)
    # The allowed services' hosts too, so their other ports are shown blocked.
    extra = {str(r.sample_ip()) for r in rules}
    targets = sorted(set(targets) | {ip for ip in extra if ip != vm_ip and
                                     is_probe_target(ip, nets)},
                     key=ipaddress.ip_address)
    log(f"Enumerated {len(targets)} private target(s) from the host:")
    log(f"  {', '.join(targets)}")

    log("Probing the targets from inside the VM with nmap...")
    findings = run_remote_nmap(vm_ip, targets, config.check_tcp_ports,
                               config.check_udp_ports, sudo_password)
    reachable = [(ip, proto, port, allowed_reason(mode, rules, ip, proto, port))
                 for ip in sorted(findings, key=ipaddress.ip_address)
                 for proto, port in sorted(findings[ip],
                                           key=lambda t: (t[0], int(t[1])))]
    unexpected = [f for f in reachable if f[3] is None]

    bar = "=" * 60
    label_w = 20
    print(f"\n{bar}")
    print(f"Containment check for '{name}' ({vm_ip})")
    print(bar)
    print(f"  {'Hardening:':{label_w}}")
    for status, what in hardening.rows:
        print(f"    [{status:>4}] {what}")
    print(f"  {'Egress mode:':{label_w}} {MODE_DESCRIPTIONS[mode]}")
    for status, what in report.rows:
        print(f"    [{status:>4}] {what}")
    print(f"  Allowed private services (nftables set private_allow): "
          f"{len(rules)}")
    for status, what in allowed.rows:
        print(f"    [{status:>4}] {what}")
    print(f"  Private network scan: {len(targets)} address(es) on "
          f"check_tcp_ports/check_udp_ports; whatever answers must be allowed")
    if not reachable:
        print("    [  ok] nothing reachable: all blocked")
    else:
        ip_w = max(len(ip) for ip, _, _, _ in reachable)
        for ip, proto, port, why in reachable:
            status = "ok" if why else "FAIL"
            note = (f"allowed: {why}" if why else
                    "NOT allowed by the configuration")
            print(f"    [{status:>4}] {ip:<{ip_w}}  {proto + '/' + port:<9}  "
                  f"{note}")
    print(bar)

    failed = report.failed or hardening.failed or bool(unexpected)
    print(f"  Hardening:          "
          f"{'FAILED (see the FAIL rows)' if hardening.failed else 'as expected'}")
    print(f"  Egress mode:        "
          f"{'FAILED (see the FAIL rows)' if report.failed else 'as expected'}")
    warned = sum(1 for status, _ in allowed.rows if status == "warn")
    print(f"  Allowed services:   " +
          (f"{warned} of {len(rules)} not answering (see the warn rows; not "
           f"a containment failure)" if warned else
           "all answering" if rules else "none configured"))
    print(f"  Private network:    " +
          (f"FAILED: {len(unexpected)} service(s) reachable that the "
           f"configuration doesn't allow" if unexpected else
           "blocked, apart from what the configuration allows"))
    print(bar)
    print(f"Containment check {'FAILED' if failed else 'PASSED'} for '{name}'.")
    sys.exit(1 if failed else 0)
