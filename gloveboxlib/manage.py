# glovebox: hardened, network-contained KVM sandboxes for AI agents.
# Copyright (C) 2026 MiCRoPhoBIC
# Derived from kvm-sandbox, Copyright (c) 2026 Ertuğ Karamatlı, under the
# MIT License (see LICENSE.MIT); modified by MiCRoPhoBIC in October 2026.
# Licensed under the GNU GPL v3 or later; see LICENSE.
# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

from . import journal
from .config import config
from .common import (CLAUDE_DOMAINS, CLAUDE_INSTALLER, DIRECT, GUEST_LOCKDOWN,
                     GUEST_SYSCTLS, METADATA_KEY, METADATA_URI,
                     MODE_DESCRIPTIONS, PROXY, allowlist_covers, capture, die,
                     domain_entries, egress_mode, glovebox_users, in_nft_set,
                     is_private_address, log, parse_n, read_packages,
                     read_root, resolve_password, vm_users_metadata)


def run(cmd, check=True):
    print(f"  $ {shlex.join(cmd)}", flush=True)
    return subprocess.run(cmd, check=check, text=True).returncode


def sudo_file_exists(path):
    # image_dir might not be traversable by the invoking user, use sudo
    return capture(["sudo", "test", "-e", path]).returncode == 0


def sudo_file_nonempty(path):
    return capture(["sudo", "test", "-s", path]).returncode == 0


def run_umask077(cmd):
    # Runs cmd with umask 077, so any file/dir it creates is 0600/0700 from the
    # first write instead of briefly world-readable.
    run(["sudo", "sh", "-c", f"umask 077 && {shlex.join(cmd)}"])


def hash_password(plaintext):
    # openssl because the stdlib crypt module was removed in Python 3.13.
    r = capture(["openssl", "passwd", "-6", "-stdin"], input=plaintext)
    if r.returncode != 0 or not r.stdout.strip():
        die(f"Failed to hash the VM password with openssl: {r.stderr.strip()}")
    return r.stdout.strip()


def removal_hint(name):
    return f"{sys.argv[0]} delete {name}"


def virsh_list():
    r = capture(["sudo", "virsh", "list", "--all", "--name"])
    if r.returncode != 0:
        die(f"Could not list existing VMs: {r.stderr.strip()}")
    return r.stdout.split()


def check_nftables():
    for family in ("inet", "ip", "bridge"):
        r = capture(["sudo", "nft", "list", "table", family, "glovebox"])
        if r.returncode != 0:
            die(f"nftables table '{family} glovebox' not found "
                f"(rules not loaded?). Run ./glovebox host-setup nftables; "
                f"see docs/host-setup.md.")
    log("nftables sandbox tables verified.")


def check_ip_forward():
    with open("/proc/sys/net/ipv4/ip_forward") as f:
        if f.read().strip() != "1":
            die("IP forwarding ('net.ipv4.ip_forward') is not enabled. Run "
                "./glovebox host-setup network; see docs/host-setup.md.")
    log("IP forwarding ('net.ipv4.ip_forward') is enabled.")


DEFAULT_SSH_KEYS = ("id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub")
PUBKEY_RE = re.compile(r"^(ssh-|ecdsa-|sk-)\S+ \S+")


def other_ssh_keys():
    """The other *.pub files in ~/.ssh that hold exactly one public key."""
    d = os.path.expanduser("~/.ssh")
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return []
    found = []
    for name in names:
        p = os.path.join(d, name)
        if not name.endswith(".pub") or not os.path.isfile(p):
            continue
        try:
            with open(p) as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
        except (OSError, UnicodeDecodeError):
            continue
        if len(lines) == 1 and PUBKEY_RE.match(lines[0]):
            found.append((p, lines[0]))
    return found


def choose_ssh_key():
    """No key with a default name: offer the other public keys in ~/.ssh."""
    keys = other_ssh_keys()
    hint = ("Set ssh_key in the config to choose one."
            if keys else "Generate one (ssh-keygen -t ed25519) or set "
            "ssh_key in the config.")
    if not keys or not sys.stdin.isatty():
        listed = "".join(f"\n  {p}" for p, _ in keys)
        die(f"No SSH public key with a default name "
            f"({', '.join(DEFAULT_SSH_KEYS)}) in ~/.ssh"
            + (f"; found:{listed}\n" if keys else ". ") + hint)
    print("No SSH public key with a default name in ~/.ssh. Found:",
          flush=True)
    for i, (p, line) in enumerate(keys, 1):
        parts = line.split(None, 2)
        comment = f"  ({parts[2]})" if len(parts) > 2 else ""
        print(f"  {i}) {p}: {parts[0]}{comment}", flush=True)
    while True:
        reply = input(f"Which key to install in the VM? [1-{len(keys)}, "
                      f"empty to cancel] ").strip()
        if not reply:
            die("No SSH key chosen. " + hint)
        if reply.isdigit() and 1 <= int(reply) <= len(keys):
            return keys[int(reply) - 1][0]
        print(f"Enter a number from 1 to {len(keys)}.", file=sys.stderr,
              flush=True)


def check_ssh_key():
    ssh_key = config.ssh_key
    if ssh_key:
        ssh_key = os.path.expanduser(ssh_key)
        if not os.path.exists(ssh_key):
            die(f"ssh_key '{ssh_key}' from the config not found.")
    else:
        for cand in DEFAULT_SSH_KEYS:
            p = os.path.expanduser(f"~/.ssh/{cand}")
            if os.path.exists(p):
                ssh_key = p
                break
        if not ssh_key:
            ssh_key = choose_ssh_key()
    log(f"Using SSH key: {ssh_key}")
    # Exactly one key: a multi-line .pub would otherwise break the YAML list
    # in write_cloud_init.
    with open(ssh_key) as f:
        keys = [ln for ln in f.read().splitlines() if ln.strip()]
    if len(keys) != 1:
        die(f"ssh_key '{ssh_key}' must contain exactly one public key "
            f"(found {len(keys)}).")
    return keys[0]


def check_bridge():
    r = capture(["ip", "-4", "-j", "addr", "show", "dev", config.bridge])
    if r.returncode != 0:
        die(f"Bridge '{config.bridge}' not found. Run ./glovebox host-setup "
            f"network; see docs/host-setup.md.")
    bridge_addrs = [ipaddress.ip_interface(f"{ai['local']}/{ai['prefixlen']}")
                    for link in json.loads(r.stdout)
                    for ai in link.get("addr_info", [])]
    if ipaddress.ip_interface(config.host_address) not in bridge_addrs:
        die(f"Bridge '{config.bridge}' does not carry host_address "
            f"{config.host_address} from the config (found: "
            f"{', '.join(map(str, bridge_addrs)) or 'no IPv4 address'}).")


def read_proxy_ca():
    # The Squid cert directory is usually not readable by the invoking user.
    r = capture(["sudo", "cat", config.proxy_ca])
    if r.returncode != 0:
        die(f"Could not read proxy_ca '{config.proxy_ca}' from "
            f"the config: {r.stderr.strip()}")
    # The CA key would let anything in the guest forge certificates the
    # guest trusts; only the public certificate may be embedded.
    if "PRIVATE KEY" in r.stdout:
        die(f"proxy_ca '{config.proxy_ca}' contains a private key; point it "
            f"at the public certificate (.crt) only.")
    if "BEGIN CERTIFICATE" not in r.stdout:
        die(f"proxy_ca '{config.proxy_ca}' is not a PEM certificate.")
    log(f"Using proxy CA: {config.proxy_ca}")
    return r.stdout


def check_egress_mode(a):
    # nftables decides, the guest config only follows: whatever is configured
    # inside a VM, it can't get out other than its set in the ruleset allows.
    a.mode = egress_mode(a.ip)
    log(f"Egress: {MODE_DESCRIPTIONS[a.mode]} ({a.ip}, per the nftables sets).")
    if a.mode == PROXY and not config.proxy:
        die(f"{a.ip} is in the nftables proxy_internet set, but proxy is None "
            f"in the config.")
    if a.mode == DIRECT:
        check_nameservers()
    a.use_proxy = a.mode == PROXY
    a.proxy_ca_pem = read_proxy_ca() if a.use_proxy and config.proxy_ca else None
    if a.claude and a.use_proxy:
        check_claude_domains()


def check_claude_domains():
    # Installing and running Claude Code on a proxy-only VM needs its
    # domains in Squid's allowlists (permanent or, for now, provisioning).
    if not config.proxy_allowed_domains:
        log("proxy_allowed_domains is off in the config: can't check that "
            "Squid lets Claude Code through.")
        return
    entries = []
    for setting in ("proxy_allowed_domains", "proxy_provision_domains"):
        path = getattr(config, setting)
        if path:
            entries += domain_entries(read_root(path) or "")
    missing = [d for d in CLAUDE_DOMAINS if not allowlist_covers(entries, d)]
    if missing:
        die(f"--claude on a proxy-only VM needs {', '.join(missing)} in "
            f"Squid's allowlist ({config.proxy_allowed_domains}). Run "
            f"./glovebox host-setup squid, which adds them, or add them "
            f"yourself and run `sudo squid -k reconfigure`.")
    log(f"Squid allows what Claude Code needs: {', '.join(CLAUDE_DOMAINS)}.")


def check_nameservers():
    # A private resolver is behind the PRIVATE_NET drop unless private_dns
    # lists it; a public one is reachable like the rest of the internet.
    if not config.nameservers:
        die("nameservers in the config is empty; a direct-internet VM "
            "needs at least one resolver.")
    for ns in config.nameservers:
        try:
            private = is_private_address(ns, config)
        except ValueError:
            die(f"nameservers in the config: '{ns}' is not an IPv4 address.")
        if private and not in_nft_set("private_dns", ns):
            die(f"Nameserver {ns} is a private address but not in the nftables "
                f"private_dns set, so the VM couldn't reach it. Add it to "
                f"private_dns in host-setup/nftables/glovebox.conf and reload, "
                f"or use a public resolver.")
        log(f"Nameserver {ns}: {'private (private_dns exception)' if private else 'public'}.")


USER_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def check_users(a):
    for setting, flag in (("user", "--user"), ("agent_user", "--agent-user")):
        value = getattr(a, setting)
        if value is None and setting == "agent_user":
            log("agent_user is off: the agent runs as your sudo user.")
            continue
        if not isinstance(value, str) or not USER_NAME.fullmatch(value) or \
                value == "root":
            die(f"{value!r} ({flag} or {setting} in the config) is not "
                f"a valid user name.")
    if a.agent_user == a.user:
        die("The agent account must differ from the login account (--user/"
            "--agent-user, or user/agent_user in the config); the "
            "point is an account without sudo.")
    log(f"Accounts: '{a.user}' (login, sudo)"
        + (f", '{a.agent_user}' (agent, no sudo)." if a.agent_user else "."))


def work_user(a):
    # Who the agent, --claude and --provision's tools (GLOVEBOX_USER) are
    # set up for.
    return a.agent_user or a.user


def resolve_packages(a):
    # --packages must exist; the default packages_file is optional.
    if a.packages:
        path = os.path.abspath(os.path.expanduser(a.packages))
        if not os.path.isfile(path):
            die(f"--packages file '{path}' not found.")
    elif config.packages_file:
        # Relative to the config file (or the repo, without one).
        path = os.path.join(config.dir, os.path.expanduser(config.packages_file))
        if not os.path.isfile(path):
            log(f"Extra packages: none ({path} doesn't exist; see "
                f"glovebox-packages.txt.example).")
            return []
    else:
        return []
    packages = read_packages(path)
    log(f"Extra packages from {path}: "
        + (" ".join(packages) if packages else "none (the list is empty)."))
    return packages


def check_prereqs(a):
    # Local, free checks first, so they fail before the first sudo prompt.
    for tool in ("openssl", "curl", "sudo", "ip", "ping", "virt-install",
                 "qemu-img", "xorrisofs"):
        if not shutil.which(tool):
            die(f"Required tool '{tool}' not found. Run ./glovebox host-setup "
                f"virt; see docs/host-setup.md.")

    if a.provision:
        a.provision = os.path.abspath(os.path.expanduser(a.provision))
        if not os.path.isfile(a.provision):
            die(f"--provision executable '{a.provision}' not found.")
        a.provision_name = os.path.basename(a.provision)

    check_users(a)
    if a.provision_as != "root" and not a.provision:
        die("--provision-as needs --provision.")
    if a.provision_as == "agent" and not a.agent_user:
        die("--provision-as agent, but agent_user is off; use user or root.")
    a.provision_user = {"root": "root", "user": a.user,
                        "agent": a.agent_user}[a.provision_as]
    a.extra_packages = resolve_packages(a)
    a.pubkey = check_ssh_key()
    check_bridge()
    check_ip_forward()
    check_nftables()
    check_egress_mode(a)

    new_n = parse_n(a.name)
    for name in virsh_list():
        if name == a.name:
            die(f"A VM named '{a.name}' already exists. Pick another name, "
                f"or remove it: {removal_hint(name)}")
        if parse_n(name) == new_n:
            die(f"VM '{name}' already uses the same IP {a.ip}; two names "
                f"sharing <n> map to the same IP. Pick another number, or "
                f"remove it: {removal_hint(name)}")

    if capture(["ping", "-c1", "-W1", a.ip]).returncode == 0:
        die(f"{a.ip} already answers ping; another host is using this IP. "
            f"Pick another number.")

    for path, what in ((a.disk_path, "disk"),
                       (a.seed_iso, "cloud-init seed")):
        if sudo_file_exists(path):
            die(f"A {what} for '{a.name}' already exists at {path}. "
                f"Remove it first: {removal_hint(a.name)}")


def prepare_disk(a):
    if not os.path.isdir(config.image_dir):
        # Recorded, like what host-setup creates, so uninstall removes it.
        for d in journal.missing_dirs(os.path.join(config.image_dir, "-")):
            journal.append({"type": "dir", "path": d})
        run(["sudo", "mkdir", "-p", config.image_dir])
    base = os.path.join(config.image_dir,
                        f"base-{os.path.basename(config.image_url)}")
    part = base + ".part"
    cached = sudo_file_exists(base)
    if cached:
        log("Checking the mirror for a newer cloud image...")
    else:
        log(f"Downloading cloud image (cached for future VMs): {config.image_url}")
    # Download to a .part file and rename only on success, so the cache never
    # holds a partial or error download. -R + -z make the request conditional on
    # the cached copy's Last-Modified (the default URL is a `latest` symlink); a
    # failed check (e.g. offline) falls back to the cached copy.
    # some mirrors just hang instead of answering; bound the connect and
    # stalled-transfer time so a bad mirror fails fast.
    try:
        rc = run(["sudo", "curl", "-fLR",
                  "--connect-timeout", "10", "--speed-limit", "1", "--speed-time", "30",
                  "-o", part, config.image_url]
                 + (["-z", base] if cached else []), check=False)
        if rc != 0:
            if not cached:
                die(f"Downloading the cloud image failed (curl exit {rc}).")
            log("Mirror unreachable; using the cached image as-is.")
        elif sudo_file_nonempty(part):
            if not cached:
                # The image cache stays after delete (the next create reuses
                # it); uninstall removes it.
                journal.append({"type": "file", "path": base, "sha256": None,
                                "backup": None})
            run(["sudo", "mv", part, base])
            if cached:
                log("Cached base image refreshed from the mirror.")
        elif cached:
            # 304 Not Modified: -z suppressed the download, keep the cache.
            log("Cached base image is up to date.")
        else:
            die("curl reported success but downloaded no cloud image "
                f"from {config.image_url}.")
    finally:
        # On success the mv consumed the .part; nothing else must leave one.
        if sudo_file_exists(part):
            run(["sudo", "rm", "-f", part], check=False)
    # A plain file copy keeps the image's qcow2 compression; cloud-init's
    # growpart expands the guest filesystem into the resized disk on boot.
    log(f"Copying base image to {a.disk_path} and resizing to {a.disk}...")
    # The per-VM disk holds the guest's filesystem, so it's created 0600
    run_umask077(["cp", "--reflink=auto", base, a.disk_path])
    run(["sudo", "qemu-img", "resize", "-q", a.disk_path, a.disk])


GUEST_PROXY_CA = "/usr/local/share/ca-certificates/glovebox-proxy-ca.crt"
CLAUDE_SETTINGS_STAGING = "/root/claude-settings.json"


def cloud_init_file(path, content, permissions, append=False):
    # base64 keeps arbitrary content clear of YAML quoting and indentation.
    b64 = base64.b64encode(content.encode()).decode("ascii")
    return (f"  - path: {json.dumps(path)}\n"
            f"    encoding: b64\n"
            f"    permissions: '{permissions}'\n"
            + ("    append: true\n" if append else "")
            + f"    content: {b64}\n")


def cloud_init_cmd(argv):
    return f"  - [{', '.join(json.dumps(arg) for arg in argv)}]\n"


GUEST_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def run_as_cmd(account, script, args=(), env=None):
    """A runcmd entry running the sh script as account, in its home with a
    clean environment plus /etc/environment: runcmd runs as root and skips
    PAM, so nothing would load it otherwise."""
    home = "/root" if account == "root" else f"/home/{account}"
    load = ("if [ -r /etc/environment ]; then set -a; . /etc/environment; "
            "set +a; fi; cd; ")
    argv = (["runuser", "-u", account, "--"] if account != "root" else []) + [
        "env", "-i", f"HOME={home}", f"USER={account}", f"LOGNAME={account}",
        "SHELL=/bin/bash", f"PATH={home}/.local/bin:{GUEST_PATH}",
        *(f"{k}={v}" for k, v in (env or {}).items()),
        "sh", "-c", load + script, "sh", *args]
    return cloud_init_cmd(argv)


# Prepended to the account's ~/.bashrc, ahead of its "not interactive"
# return, so `ssh agent@vm claude ...` finds it too. Debian's ~/.profile
# adds ~/.local/bin for login shells only if it existed at login.
BASHRC_PATH = """\
# Added by glovebox create --claude: Claude Code lives in ~/.local/bin.
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) PATH="$HOME/.local/bin:$PATH" ;; esac

"""
BASHRC_STAGING = "/root/glovebox-bashrc-path"


def claude_cloud_init(a):
    """(write_files, runcmd) installing Claude Code for the work account,
    with ~/.local/bin on its PATH. Output in /var/log/cloud-init-output.log."""
    user = work_user(a)
    files = cloud_init_file(BASHRC_STAGING, BASHRC_PATH, "0600")
    bashrc = f"/home/{user}/.bashrc"
    cmds = cloud_init_cmd([
        "sh", "-c", '{ cat "$1"; cat "$2" 2>/dev/null; } > "$2.glovebox" && '
                    'chown "$3:$3" "$2.glovebox" && chmod 0644 "$2.glovebox" '
                    '&& mv "$2.glovebox" "$2"; rm -f "$1"',
        "sh", BASHRC_STAGING, bashrc, user])
    # The installer needs curl (or wget); the cloud image may lack both.
    cmds += cloud_init_cmd([
        "sh", "-c", "command -v curl >/dev/null || { apt-get update && "
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y curl; }"])
    # Fetched to a file first: piped into bash, a failed download would
    # look like success.
    cmds += run_as_cmd(user, (
        'f=$(mktemp) && curl -fsSL "$1" -o "$f" && bash "$f"; rc=$?; '
        'rm -f "$f"; [ "$rc" -eq 0 ] || echo "glovebox: installing Claude '
        'Code failed (exit $rc)" >&2; exit "$rc"'), [CLAUDE_INSTALLER])
    return files, cmds


def guest_hardening_files():
    # Guest kernel hardening, aimed at keeping guest root (which most VM
    # escapes start from) harder to reach and use. check verifies it.
    sysctls = "".join(f"{k} = {v}\n" for k, v in GUEST_SYSCTLS.items())
    # lockdown=integrity: no unsigned modules (Debian's are signed), no
    # /dev/mem, kexec or raw PCI/IO port access, even for root. Secure Boot
    # would turn it on by itself, but it's off here (see virt_install).
    grub = ('GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX '
            f'lockdown={GUEST_LOCKDOWN}"\n')
    return (cloud_init_file("/etc/sysctl.d/90-glovebox-hardening.conf",
                            sysctls, "0644")
            + cloud_init_file("/etc/default/grub.d/99-glovebox-lockdown.cfg",
                              grub, "0644"))


def guest_env_cloud_init(a):
    # Returns (write_files entries, runcmd entries) for the guest environment:
    # the proxy setup for a proxy-only VM, and with --claude the Claude Code
    # variables (claude_env, plus the proxy ones on a proxy-only VM) in both
    # /etc/environment and the user's ~/.claude/settings.json.
    env = {}
    claude_env = {}
    files = ""
    cmds = ""
    if a.use_proxy:
        proxy = config.proxy
        env.update({"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy,
                    "http_proxy": proxy, "https_proxy": proxy,
                    "NO_PROXY": config.no_proxy, "no_proxy": config.no_proxy})
        # apt ignores the environment when run from units/cron; configure it
        # directly.
        files += cloud_init_file(
            "/etc/apt/apt.conf.d/95proxy",
            f'Acquire::http::Proxy "{proxy}";\n'
            f'Acquire::https::Proxy "{proxy}";\n', "0644")
        if a.proxy_ca_pem:
            files += cloud_init_file(GUEST_PROXY_CA, a.proxy_ca_pem, "0644")
            cmds += cloud_init_cmd(["update-ca-certificates"])
        claude_env.update({"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy,
                           "NO_PROXY": config.no_proxy})
        if a.proxy_ca_pem:
            # Node (Claude Code) ignores the system store; must be absolute.
            claude_env["NODE_EXTRA_CA_CERTS"] = GUEST_PROXY_CA
    if a.claude:
        env.update(config.claude_env)
        claude_env.update(config.claude_env)
        if a.proxy_ca_pem:
            env["NODE_EXTRA_CA_CERTS"] = GUEST_PROXY_CA
    if env:
        # Appended: Debian's /etc/environment may already hold lines (e.g. PATH).
        files = cloud_init_file(
            "/etc/environment",
            "".join(f"{k}={v}\n" for k, v in env.items()), "0644",
            append=True) + files
    if a.claude:
        settings = json.dumps({"env": claude_env}, indent=2) + "\n"
        # Staged under /root and installed by runcmd: write_files may run
        # before the user and its home directory exist.
        files += cloud_init_file(CLAUDE_SETTINGS_STAGING, settings, "0600")
        user = work_user(a)
        claude_dir = f"/home/{user}/.claude"
        cmds += cloud_init_cmd(["install", "-d", "-m", "0700", "-o", user,
                                "-g", user, claude_dir])
        cmds += cloud_init_cmd(["install", "-m", "0600", "-o", user, "-g", user,
                                CLAUDE_SETTINGS_STAGING,
                                f"{claude_dir}/settings.json"])
        cmds += cloud_init_cmd(["rm", "-f", CLAUDE_SETTINGS_STAGING])
    return files, cmds


def write_cloud_init(seed_dir, a):
    # json.dumps wraps the key in a quoted YAML scalar; an OpenSSH comment can
    # contain ": ", which an unquoted scalar would parse as a mapping.
    pubkey = json.dumps(a.pubkey)
    # sudo requires the password (no NOPASSWD), and only the hash is stored,
    # so in-guest code can't read the plaintext out of the cloud-init seed.
    pwhash = hash_password(a.password)
    provision_file = ""
    provision_cmd = ""
    if a.provision:
        # The --provision executable is embedded base64 (binary-safe in YAML);
        # write_files places it before runcmd execs it, exactly once
        # (per-instance module + stable instance-id). Its output lands in
        # /var/log/cloud-init-output.log in the guest.
        with open(a.provision, "rb") as f:
            content = base64.b64encode(f.read()).decode("ascii")
        guest_path = f"/root/{a.provision_name}"
        provision_file = (f"  - path: {json.dumps(guest_path)}\n"
                          f"    encoding: b64\n"
                          f"    permissions: '0700'\n"
                          f"    content: {content}\n")
        if a.provision_user != "root":
            # /root is closed to the account: it runs a copy of its own,
            # under /run, so it's gone after the first boot's reboot.
            run_path = f"/run/glovebox-provision/{a.provision_name}"
            provision_cmd = cloud_init_cmd([
                "install", "-D", "-m", "0700", "-o", a.provision_user, "-g",
                a.provision_user, guest_path, run_path])
            guest_path = run_path
        # GLOVEBOX_USER tells the script the account to set tools up for
        # (agent_user, else user), so scripts don't hardcode it.
        provision_cmd += run_as_cmd(a.provision_user, 'exec "$1"', [guest_path],
                                    env={"GLOVEBOX_USER": work_user(a)})
    proxy_files, proxy_cmds = guest_env_cloud_init(a)
    claude_files, claude_cmds = claude_cloud_init(a) if a.claude else ("", "")
    packages_cmd = ""
    if a.extra_packages:
        # In runcmd rather than cloud-init's packages module: on a proxy-only
        # VM apt needs the proxy CA, which proxy_cmds trusts first. Output in
        # /var/log/cloud-init-output.log; a failure doesn't stop the rest.
        packages_cmd = (cloud_init_cmd(["apt-get", "update"])
                        + cloud_init_cmd(["env", "DEBIAN_FRONTEND=noninteractive",
                                          "apt-get", "install", "-y",
                                          *a.extra_packages]))
    # The agent account: no sudo entry, no groups, no password (locked), so
    # it can't become root even if it sees your password typed elsewhere.
    agent = ""
    homes = [f"/home/{a.user}"]
    if a.agent_user:
        agent = (f"  - name: {a.agent_user}\n"
                 f"    shell: /bin/bash\n"
                 f"    lock_passwd: true\n"
                 f"    ssh_authorized_keys:\n"
                 f"      - {pubkey}\n")
        homes.append(f"/home/{a.agent_user}")
    homes_cmd = cloud_init_cmd(["chmod", "0700", *homes])
    user_data = f"""\
#cloud-config
hostname: {a.name}
users:
  - name: {a.user}
    shell: /bin/bash
    sudo: ALL=(ALL) ALL
    lock_passwd: false
    ssh_authorized_keys:
      - {pubkey}
{agent}\
ssh_pwauth: false
chpasswd:
  expire: false
  users:
    - name: {a.user}
      password: {json.dumps(pwhash)}
      type: hash
write_files:
  - path: /etc/sysctl.d/99-disable-ipv6.conf
    content: |
      net.ipv6.conf.all.disable_ipv6 = 1
      net.ipv6.conf.default.disable_ipv6 = 1
      net.ipv6.conf.lo.disable_ipv6 = 1
{guest_hardening_files()}\
{proxy_files}\
{claude_files}\
{provision_file}\
runcmd:
  - sysctl --system
{homes_cmd}\
  - update-grub
{proxy_cmds}\
{packages_cmd}\
{claude_cmds}\
{provision_cmd}\
  - touch /etc/cloud/cloud-init.disabled
# One reboot at the end of the first boot, for lockdown= on the kernel
# command line.
power_state:
  mode: reboot
  message: "glovebox: rebooting to enable kernel lockdown"
  condition: true
"""
    # Only a direct-internet VM gets resolvers: the others couldn't reach one,
    # and an unreachable resolver turns every lookup into a timeout.
    nameservers = ""
    if a.mode == DIRECT:
        ns_lines = "\n".join(f"        - {ns}" for ns in config.nameservers)
        nameservers = f"    nameservers:\n      addresses:\n{ns_lines}\n"
    network_config = f"""\
version: 2
ethernets:
  primary:
    match:
      macaddress: {a.mac}
    dhcp4: false
    addresses:
      - {a.ip}/{a.subnet.prefixlen}
    routes:
      - to: default
        via: {a.gateway}
{nameservers}"""
    # NoCloud requires meta-data; a stable instance-id makes the per-instance
    # modules (user, password, hostname) run exactly once across reboots.
    meta_data = f"instance-id: {a.name}\nlocal-hostname: {a.name}\n"
    # NoCloud requires exactly these filenames at the cidata root.
    for fname, content in (("user-data", user_data),
                           ("meta-data", meta_data),
                           ("network-config", network_config)):
        path = os.path.join(seed_dir, fname)
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o600)


def build_seed_iso(a, seed_dir):
    # virt-install's --cloud-init also stamps an SMBIOS serial of "ds=nocloud"
    # on the VM; recent cloud-init (25.x) then seeds "from dmi" with an empty
    # payload and never reads the attached cidata ISO. Building the
    # cidata-labelled seed ourselves and attaching it as a plain read-only
    # virtio disk sidesteps that: cloud-init discovers it by filesystem label.
    log(f"Building cloud-init seed ISO {a.seed_iso}...")
    # The seed ISO holds the sudo password hash, so it's created 0600
    run_umask077(["xorrisofs", "-output", a.seed_iso, "-volid", "cidata",
                  "-joliet", "-rock", seed_dir])


def virt_install(a):
    log("Creating the VM with virt-install...")
    cmd = [
        "sudo", "virt-install",
        "--name", a.name,
        "--virt-type", "kvm",
        "--osinfo", config.osinfo,
        "--memory", str(a.memory),
        "--vcpus", str(a.vcpus),
        # Mask the virtualization flags so the guest can't run its own
        # hypervisor: nested virt exercises KVM's most complex code paths
        # (a disable policy is a no-op for a flag the host CPU lacks, so
        # listing both vmx and svm works on Intel and AMD).
        "--cpu", "host-model,disable=vmx,disable=svm",
        # Strip the emulated devices a headless dev box never uses (QEMU's
        # device emulation is where most VM escapes have lived). The
        # video-less config requires UEFI: only under OVMF does GRUB
        # fall back to serial (a BIOS boot wedges at GRUB). Secure boot
        # stays off so libvirt picks the OVMF build that doesn't need
        # QEMU's SMM emulation.
        "--boot", ("firmware=efi,firmware.feature0.name=secure-boot,"
                   "firmware.feature0.enabled=no"),
        "--graphics", "none",
        "--video", "none",
        "--sound", "none",
        "--controller", "usb,model=none",
        "--memballoon", "none",
        "--channel", "none",
        # Drop the default TPM 2.0 virt-install adds to UEFI guests;
        # nothing here does measured boot or attestation.
        "--tpm", "none",
        # No KSM page merging with other VMs: shared pages are a timing side
        # channel between guests.
        "--memorybacking", "nosharepages=yes",
        # Guests use kvm-clock; HPET is an unused chipset default.
        "--clock", "hpet_present=no",
        "--console", "pty,target.type=serial",
        "--disk", f"path={a.disk_path},bus=virtio,format=qcow2",
        # Read-only virtio disk rather than an emulated cdrom; cloud-init
        # finds it by its "cidata" volume label. format=raw stops
        # virt-install probing the ISO's format.
        "--disk", f"path={a.seed_iso},bus=virtio,readonly=on,format=raw",
        "--import",
        "--network",
        # Anti-spoofing: clean-traffic pinned to the VM's IP. The parameter
        # is injected via xpath (virt-install has no dedicated
        # filterref.parameter option). network-config matches the MAC.
        (f"bridge={config.bridge},model=virtio,mac={a.mac},"
         f"filterref.filter=clean-traffic,"
         f"xpath1.set=./filterref/parameter/@name,xpath1.value=IP,"
         f"xpath2.set=./filterref/parameter/@value,xpath2.value={a.ip}"),
        "--noautoconsole",
    ]
    run(cmd)
    # --config: into the persistent definition, which check reads.
    run(["sudo", "virsh", "metadata", a.name, METADATA_URI,
         "--key", METADATA_KEY, "--set",
         vm_users_metadata(a.user, a.agent_user), "--config"])
    if config.autostart:
        run(["sudo", "virsh", "autostart", a.name])
    else:
        log("Autostart disabled; the VM will not start at host boot.")


def detach_seed(a):
    log("Waiting for the VM to come up on its IP...")
    deadline = time.time() + 60
    while capture(["ping", "-c1", "-W1", a.ip]).returncode != 0:
        if time.time() > deadline:
            log(f"WARNING: {a.ip} not answering; seed ISO left attached "
                f"({a.seed_iso}).")
            return
        time.sleep(2)
    log("Detaching and deleting the cloud-init seed ISO...")
    if run(["sudo", "virsh", "detach-disk", a.name, a.seed_iso,
            "--persistent"], check=False) != 0:
        log(f"WARNING: detach failed; seed ISO left attached ({a.seed_iso}).")
        return
    run(["sudo", "rm", "-f", a.seed_iso])


def cleanup_failed_create(a):
    # check_prereqs verified none of these existed beforehand. Errors are
    # ignored so cleanup never masks the original failure.
    log("Create failed; removing this run's artifacts...")
    capture(["sudo", "virsh", "destroy", a.name])
    capture(["sudo", "virsh", "undefine", "--nvram", a.name])
    capture(["sudo", "rm", "-f", a.disk_path, a.seed_iso])


def summary(a):
    bar = "=" * 60
    print(f"\n{bar}")
    print(f"Sandbox VM '{a.name}' created at {a.ip} (cloud-init runs on first boot).")
    print(bar)
    print(f"  SSH:            ssh {a.user}@{a.ip}")
    print(f"  Console:        sudo virsh console {a.name}  (serial; exit with Ctrl+])")
    print(f"  Login & sudo:   user '{a.user}' & password you set")
    if a.agent_user:
        print(f"  Agent account:  ssh {a.agent_user}@{a.ip}  (no sudo; "
              f"for Claude Code and untrusted work)")
    print("  Hardening:      kernel lockdown after the one reboot that ends "
          "first boot")
    if a.extra_packages:
        print(f"  Packages:       {' '.join(a.extra_packages)} (apt-get on "
              f"first boot)")
    if a.provision:
        print(f"  Provision:      {a.provision_name} runs as "
              f"{a.provision_user} on first boot; log: "
              f"/var/log/cloud-init-output.log")
    if a.mode == PROXY:
        print(f"  Internet:       only through {config.proxy} (/etc/environment, apt"
              + (", system CA" if a.proxy_ca_pem else "") + "); no DNS")
    else:
        print(f"  Internet:       direct; DNS {', '.join(config.nameservers)}")
    if a.claude:
        what = "telemetry" + (" + proxy" if a.use_proxy else "")
        print(f"  Claude Code:    installed for '{work_user(a)}' on first boot "
              f"(~/.local/bin, on its PATH); {what} env in /etc/environment "
              f"and /home/{work_user(a)}/.claude/settings.json")
    print()


def vm_paths(name):
    return (os.path.join(config.image_dir, f"{name}.qcow2"),
            os.path.join(config.image_dir, f"{name}-seed.iso"))


def vm_mac(ip):
    # Deterministic MAC in QEMU's 52:54:00 OUI from the IP's last three
    # octets: unique per VM for any sandbox subnet of /8 or narrower
    octets = ipaddress.ip_address(ip).packed[-3:]
    return "52:54:00:" + ":".join(f"{b:02x}" for b in octets)


def cmd_create(a):
    a.disk_path, a.seed_iso = vm_paths(a.name)
    a.mac = vm_mac(a.ip)
    check_prereqs(a)
    a.password = resolve_password(config)
    try:
        prepare_disk(a)
        # TemporaryDirectory is created 0700, so the seed files (which hold
        # the sudo password hash) are never visible to other users.
        with tempfile.TemporaryDirectory() as seed_dir:
            write_cloud_init(seed_dir, a)
            build_seed_iso(a, seed_dir)
            virt_install(a)
    except BaseException:
        cleanup_failed_create(a)
        raise
    detach_seed(a)
    summary(a)


def cmd_delete(a):
    a.disk_path, a.seed_iso = vm_paths(a.name)
    exists = a.name in virsh_list()
    # Also clean up leftover files from an earlier undefine without rm.
    leftovers = [path for path in (a.disk_path, a.seed_iso)
                 if sudo_file_exists(path)]
    if not exists and not leftovers:
        die(f"No VM named '{a.name}' and no leftover files for it "
            f"in {config.image_dir}.")
    if exists and glovebox_users(a.name) is None:
        die(f"'{a.name}' wasn't created by glovebox (it has no glovebox "
            f"metadata), so glovebox won't delete it. Use virsh or "
            f"virt-manager if you mean to.")
    what = ([f"VM '{a.name}'"] if exists else []) + leftovers
    reply = input(f"Delete {', '.join(what)}? [y/N] ")
    if reply.strip().lower() not in ("y", "yes"):
        die("Aborted; nothing deleted.")
    if exists:
        # destroy fails when the VM isn't running; that's fine.
        capture(["sudo", "virsh", "destroy", a.name])
        # --managed-save: undefine otherwise refuses when a managed save exists
        run(["sudo", "virsh", "undefine", "--nvram", "--managed-save", a.name])
    if leftovers:
        run(["sudo", "rm", "-f"] + leftovers)
    log(f"Sandbox '{a.name}' deleted.")
