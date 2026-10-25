# glovebox: hardened, network-contained KVM sandboxes for AI agents.
# Copyright (C) 2026 MiCRoPhoBIC
# Licensed under the GNU GPL v3 or later; see LICENSE.
# SPDX-License-Identifier: GPL-3.0-or-later

"""list, start and stop: the sandbox VMs' lifecycle after create."""

import time

from .config import config
from .common import (DIRECT, MODE_DESCRIPTIONS, PROXY, capture, die,
                     egress_mode, glovebox_users, log, nft_set_contains,
                     parse_n, read_vm_users, resolve_ip, resolve_subnet)
from .manage import check_nftables, run

SHUT_OFF = "shut off"


def domain_states():
    """{name: state} of every libvirt domain, from one `virsh list`."""
    r = capture(["sudo", "virsh", "list", "--all"])
    if r.returncode != 0:
        die(f"Could not list the VMs: {r.stderr.strip()}")
    states = {}
    # " Id   Name   State" header, a dashed rule, then "<id|-> <name> <state>".
    for line in r.stdout.splitlines()[2:]:
        parts = line.split(None, 2)
        if len(parts) == 3:
            states[parts[1]] = parts[2].strip()
    return states


def set_json(set_name):
    r = capture(["sudo", "nft", "-j", "list", "set", "inet", "glovebox",
                 set_name])
    return r.stdout if r.returncode == 0 else None


def mode_text(ip, direct_json, proxy_json):
    if direct_json is None or proxy_json is None:
        return "? (rules not loaded)"
    try:
        direct = nft_set_contains(direct_json, ip)
        proxied = nft_set_contains(proxy_json, ip)
    except (ValueError, KeyError, TypeError, AttributeError):
        return "? (sets unreadable)"
    if direct and proxied:
        return "both sets!"
    if not (direct or proxied):
        return "none (dropped)"
    return DIRECT if direct else PROXY


def cmd_list(a):
    states = domain_states()
    subnet, gateway = resolve_subnet(config)
    direct_json, proxy_json = set_json("direct_internet"), set_json("proxy_internet")
    rows, others = [], 0
    for name in sorted(states, key=lambda n: (parse_n(n) or 0, n)):
        users = glovebox_users(name)
        if users is None:
            others += 1
            continue
        ip = resolve_ip(parse_n(name), subnet, gateway, strict=False)
        rows.append((name, states[name], ip or "?",
                     mode_text(ip, direct_json, proxy_json) if ip else "?",
                     users[0], users[1] or "-"))
    if not rows:
        print("No glovebox sandboxes. Create one with: ./glovebox create "
              "sandbox<n>")
    else:
        head = ("NAME", "STATE", "IP", "MODE", "USER", "AGENT")
        widths = [max(len(r[i]) for r in rows + [head]) for i in range(len(head))]
        for r in [head] + rows:
            print("  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())
    if others:
        print(f"\n({others} other libvirt VM(s) not made by glovebox not "
              f"shown; see sudo virsh list --all)")


def require_glovebox_vm(name):
    state = domain_states().get(name)
    if state is None:
        die(f"No VM named '{name}'. See ./glovebox list.")
    read_vm_users(name)  # stops when glovebox didn't create it
    return state


def cmd_start(a):
    state = require_glovebox_vm(a.name)
    if state == "running":
        log(f"'{a.name}' is already running.")
        return
    # The libvirt network is in 'open' mode: without glovebox's rules nothing
    # filters what the VM can reach, so refuse rather than start it unguarded.
    check_nftables()
    mode = egress_mode(a.ip)
    log(f"Mode: {MODE_DESCRIPTIONS[mode]}.")
    if state == "paused":
        run(["sudo", "virsh", "resume", a.name])
    else:
        run(["sudo", "virsh", "start", a.name])
    user, agent_user = read_vm_users(a.name)
    log(f"'{a.name}' started at {a.ip}. SSH once it has booted: "
        f"ssh {user}@{a.ip}"
        + (f" (agent: ssh {agent_user}@{a.ip})" if agent_user else ""))


def cmd_stop(a):
    state = require_glovebox_vm(a.name)
    if state == SHUT_OFF:
        log(f"'{a.name}' is already shut off.")
        return
    if a.force:
        # Like pulling the plug: unsaved data in the VM is lost.
        run(["sudo", "virsh", "destroy", a.name])
        log(f"'{a.name}' powered off.")
        return
    if state == "paused":
        die(f"'{a.name}' is paused and can't shut itself down. Resume it "
            f"(./glovebox start {a.name}) or power it off: "
            f"./glovebox stop --force {a.name}")
    run(["sudo", "virsh", "shutdown", a.name])
    log(f"Waiting up to {a.timeout}s for '{a.name}' to shut down...")
    deadline = time.monotonic() + a.timeout
    while time.monotonic() < deadline:
        time.sleep(2)
        if domain_states().get(a.name) == SHUT_OFF:
            log(f"'{a.name}' is shut off.")
            return
    die(f"'{a.name}' did not shut down within {a.timeout}s (still "
        f"{domain_states().get(a.name)}). Wait longer, or power it off: "
        f"./glovebox stop --force {a.name}")
