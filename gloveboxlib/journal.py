# glovebox: hardened, network-contained KVM sandboxes for AI agents.
# Copyright (C) 2026 MiCRoPhoBIC
# Licensed under the GNU GPL v3 or later; see LICENSE.
# SPDX-License-Identifier: GPL-3.0-or-later

"""The host-setup journal: every change host-setup makes to the host, with
what was there before, so `glovebox uninstall` can undo exactly that.

Entries are recorded while the steps run (not when they're planned), right
before each change, so they describe the host as it really was. One JSON
object per line in JOURNAL; replaced files are kept under BACKUP_DIR. Both
are root-owned and live on the host, not in the repo, so uninstall works
from any checkout.

Entry types and their undo:
  file      path, sha256 of what we installed (None: generated), backup of
            what was there (None: we created it) -> restore it, or remove
  dir       a directory we created (tree: with contents we didn't write
            ourselves) -> rmdir if empty, or rm -r for a tree
  packages  the packages that appeared with an install step -> removed
            only if you say so, separately
  service   a unit's enabled/active state before -> restored
  sysctl    a live value before -> restored
  libvirt_net  whether the network existed, autostarted, ran -> restored
  nft_tables   the glovebox tables that didn't exist before -> deleted
  ufw_rule  a rule we added -> ufw delete
"""

import datetime
import hashlib
import itertools
import json
import os

from .common import capture, die, read_root, root_exists

STATE_DIR = "/var/lib/glovebox"
JOURNAL = f"{STATE_DIR}/journal.jsonl"
BACKUP_DIR = f"{STATE_DIR}/backups"

STAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
_seq = itertools.count(1)


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sudo(cmd, what, **kwargs):
    r = capture(["sudo", *cmd], **kwargs)
    if r.returncode != 0:
        die(f"{what} failed, so nothing was changed by this step: "
            f"{r.stderr.strip()}")
    return r


def describe(e):
    t = e["type"]
    if t == "file":
        if e.get("backup"):
            return f"replaced {e['path']} (was saved to {e['backup']})"
        return f"created {e['path']}"
    if t == "dir":
        return f"created directory {e['path']}" + (" (tree)" if e.get("tree") else "")
    if t == "packages":
        return f"installed {' '.join(e['names'])}"
    if t == "service":
        return (f"{e['unit']} was {'enabled' if e['was_enabled'] else 'disabled'}"
                f" and {'active' if e['was_active'] else 'inactive'}")
    if t == "sysctl":
        return f"{e['key']} was {e['previous']}"
    if t == "libvirt_net":
        if not e["was_defined"]:
            return f"defined the libvirt network {e['name']}"
        return (f"libvirt network {e['name']} had autostart "
                f"{'on' if e['was_autostart'] else 'off'}, was "
                f"{'active' if e['was_active'] else 'inactive'}")
    if t == "nft_tables":
        return f"created nftables tables {', '.join(' '.join(x) for x in e['tables'])}"
    if t == "ufw_rule":
        return f"added the UFW rule `ufw {' '.join(e['rule'])}`"
    return t


def append(entry):
    entry = {"id": f"{STAMP}-{next(_seq)}", "time": now(), **entry}
    sudo(["install", "-d", "-m", "0755", STATE_DIR], f"Creating {STATE_DIR}")
    sudo(["tee", "-a", JOURNAL], f"Writing {JOURNAL}",
         input=json.dumps(entry, sort_keys=True) + "\n")
    print(f"  + journal: {describe(entry)}", flush=True)


def read():
    text = read_root(JOURNAL)
    if not text:
        return []
    entries = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except ValueError as e:
            die(f"{JOURNAL} line {n} is not valid JSON ({e}); fix or remove "
                f"that line by hand.")
    return entries


def forget(ids):
    """Drop entries whose change has been undone."""
    ids = set(ids)
    rest = [e for e in read() if e["id"] not in ids]
    # Written beside it and renamed, so an interruption never leaves a
    # half-written journal.
    tmp = f"{JOURNAL}.tmp"
    sudo(["tee", tmp], f"Writing {tmp}",
         input="".join(json.dumps(e, sort_keys=True) + "\n" for e in rest))
    sudo(["mv", "-f", tmp, JOURNAL], f"Replacing {JOURNAL}")


# --- hooks: what a host-setup step records, run as it executes ------------------

class Hook:
    def __init__(self, desc, pre=None, post=None):
        self.desc = desc  # shown in the plan
        self.pre = pre    # runs right before the step's commands
        self.post = post  # runs after them, even if one failed


def missing_dirs(path):
    """The directories, outermost first, that don't exist on the way to
    path (which install -D or mkdir -p would create)."""
    out, d = [], os.path.dirname(path)
    while d not in ("", "/") and not root_exists(d):
        out.insert(0, d)
        d = os.path.dirname(d)
    return out


def file_hook(dest, content=None):
    """Before dest gets written: record the directories that will appear,
    and save what's at dest now. content=None: generated (no hash)."""
    def pre():
        for d in missing_dirs(dest):
            append({"type": "dir", "path": d})
        backup = None
        if root_exists(dest):
            backup = f"{BACKUP_DIR}{dest}.{STAMP}"
            sudo(["install", "-d", "-m", "0700", BACKUP_DIR],
                 f"Creating {BACKUP_DIR}")
            sudo(["mkdir", "-p", os.path.dirname(backup)],
                 f"Creating {os.path.dirname(backup)}")
            sudo(["cp", "-p", dest, backup], f"Saving {dest}")
        append({"type": "file", "path": dest,
                "sha256": sha256(content) if content is not None else None,
                "backup": backup})
    return Hook(f"records {dest}, saving the current file if there is one",
                pre)


def dir_hook(path, tree=False, replaced=False):
    """replaced: the step deletes what's at path and creates it anew, so
    it's recorded as glovebox's even though it exists now."""
    def pre():
        for d in missing_dirs(path):
            append({"type": "dir", "path": d})
        if replaced or not root_exists(path):
            append({"type": "dir", "path": path, "tree": tree})
    return Hook(f"records {path}" + ("" if replaced else " if it's new"), pre)


def installed_packages(pm):
    if pm == "apt":
        r = capture(["dpkg-query", "-W", "-f=${binary:Package}\t${db:Status-Abbrev}\n"])
        return {ln.split("\t")[0] for ln in r.stdout.splitlines()
                if ln.split("\t")[-1].startswith("ii")}
    return set(capture(["pacman", "-Qq"]).stdout.split())


def packages_hook(pm):
    before = set()

    def pre():
        before.update(installed_packages(pm))
        if not before:
            die("Could not list the installed packages, so the install "
                "couldn't be recorded; nothing was installed.")

    def post():
        new = sorted(installed_packages(pm) - before)
        if new:
            append({"type": "packages", "pm": pm, "names": new})
    return Hook("records every package that appears, dependencies included",
                pre, post)


def unit_state(unit):
    active = capture(["systemctl", "is-active", unit]).stdout.strip()
    enabled = capture(["systemctl", "is-enabled", unit]).stdout.strip()
    return active == "active", enabled == "enabled"


def service_hook(unit):
    def pre():
        active, enabled = unit_state(unit)
        append({"type": "service", "unit": unit, "was_enabled": enabled,
                "was_active": active})
    return Hook(f"records whether {unit} was enabled and running", pre)


def sysctl_hook(key):
    def pre():
        with open("/proc/sys/" + key.replace(".", "/")) as f:
            append({"type": "sysctl", "key": key, "previous": f.read().strip()})
    return Hook(f"records the current {key}", pre)


def libvirt_net_state(name):
    r = capture(["sudo", "virsh", "net-info", name])
    if r.returncode != 0:
        return None
    flags = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition(":")
        flags[k.strip()] = v.strip() == "yes"
    return flags.get("Autostart", False), flags.get("Active", False)


def libvirt_net_hook(name):
    def pre():
        state = libvirt_net_state(name)
        append({"type": "libvirt_net", "name": name,
                "was_defined": state is not None,
                "was_autostart": bool(state and state[0]),
                "was_active": bool(state and state[1])})
    return Hook(f"records the state of the libvirt network {name}", pre)


def nft_tables_hook(tables):
    def pre():
        new = [list(t) for t in tables
               if capture(["sudo", "nft", "list", "table", *t]).returncode != 0]
        if new:
            append({"type": "nft_tables", "tables": new})
    return Hook("records which glovebox nftables tables are new", pre)


def ufw_rule_hook(rule):
    def pre():
        append({"type": "ufw_rule", "rule": list(rule)})
    return Hook("records the UFW rule", pre)
