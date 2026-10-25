# glovebox: hardened, network-contained KVM sandboxes for AI agents.
# Copyright (C) 2026 MiCRoPhoBIC
# Licensed under the GNU GPL v3 or later; see LICENSE.
# SPDX-License-Identifier: GPL-3.0-or-later

"""The configuration: built-in defaults, overridden by a TOML file.

The file holds only what you change; every setting, with its meaning, is in
glovebox.toml.example. The first of these that exists is used:

1. the file named by $GLOVEBOX_CONFIG (which must exist),
2. glovebox.toml next to the glovebox command,
3. $XDG_CONFIG_HOME/glovebox/config.toml (default ~/.config/glovebox/).

Without any, the defaults apply. TOML has no null: for a setting that can be
off (marked OPT below), "" turns it off.
"""

import difflib
import os
import sys
import types

from .common import die

if sys.version_info < (3, 11):
    die("glovebox needs Python 3.11 or newer (for tomllib).")
import tomllib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INT, STR, OPT, BOOL, STRS, ENV = "int", "str", "opt", "bool", "strs", "env"
KIND_TEXT = {INT: "an integer", STR: "a string", OPT: 'a string ("" for none)',
             BOOL: "true or false", STRS: "a list of strings",
             ENV: "a table of string values"}

SETTINGS = {
    # Per-VM defaults (create flags override them)
    "memory": (INT, 1024),
    "vcpus": (INT, 1),
    "disk": (STR, "20G"),
    "user": (STR, "user"),
    "agent_user": (OPT, "agent"),
    "packages_file": (OPT, "glovebox-packages.txt"),
    # Guest
    "ssh_key": (OPT, None),
    "password": (OPT, None),
    "image_url": (STR, "https://cloud.debian.org/images/cloud/trixie/latest/"
                       "debian-13-genericcloud-amd64.qcow2"),
    "osinfo": (STR, "debian13"),
    "nameservers": (STRS, ["1.1.1.1", "1.0.0.1"]),
    "autostart": (BOOL, False),
    # Proxy
    "proxy": (OPT, "http://10.248.0.254:3128"),
    "no_proxy": (STR, "localhost,127.0.0.1,::1"),
    "proxy_ca": (OPT, "/etc/squid/ssl_cert/sandboxCA.crt"),
    "proxy_ca_days": (INT, 3650),
    "proxy_allowed_domains": (OPT, "/etc/squid/allowed_domains.txt"),
    "proxy_provision_domains": (OPT, "/etc/squid/provision_domains.txt"),
    "proxy_access_log": (STR, "/var/log/squid/access.log"),
    # Claude Code (--claude)
    "claude_env": (ENV, {"DISABLE_TELEMETRY": "1",
                         "DISABLE_ERROR_REPORTING": "1",
                         "DISABLE_BUG_COMMAND": "1"}),
    # check
    "check_tcp_ports": (STR, "21-23,53,80,111,139,443,445,631,1433,2049,"
                             "2375-2376,3000,3306,3389,5000-5001,5173,5432,"
                             "5900,5985,6379,6443,8000,8006,8080,8443,8888,"
                             "9000,9090,9100,9200,10250,11211,16509,27017"),
    "check_udp_ports": (STR, "53,67-69,111,123,137,161,500,514,623,1900,4500,"
                             "5353,51820"),
    "check_denied_domains": (STRS, ["example.com", "github.com", "pypi.org"]),
    "check_public_targets": (STRS, ["1.1.1.1", "8.8.8.8", "9.9.9.9"]),
    "check_private_nets": (STRS, ["10.0.0.0/8", "172.16.0.0/12",
                                  "192.168.0.0/16", "127.0.0.0/8",
                                  "169.254.0.0/16", "100.64.0.0/10"]),
    # Host topology (must match host-setup/)
    "host_address": (STR, "10.248.0.254/24"),
    "bridge": (STR, "br-glovebox"),
    "image_dir": (STR, "/var/lib/libvirt/images"),
}


def find_file():
    env = os.environ.get("GLOVEBOX_CONFIG")
    if env:
        path = os.path.abspath(os.path.expanduser(env))
        if not os.path.isfile(path):
            die(f"$GLOVEBOX_CONFIG names {path}, which doesn't exist.")
        return path
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    for path in (os.path.join(REPO, "glovebox.toml"),
                 os.path.join(xdg, "glovebox", "config.toml")):
        if os.path.isfile(path):
            return path
    return None


def check_value(path, key, kind, value):
    ok = {
        INT: isinstance(value, int) and not isinstance(value, bool),
        STR: isinstance(value, str),
        OPT: isinstance(value, str),
        BOOL: isinstance(value, bool),
        STRS: isinstance(value, list) and all(isinstance(v, str) for v in value),
        ENV: isinstance(value, dict) and all(isinstance(v, str)
                                             for v in value.values()),
    }[kind]
    if not ok:
        die(f"{path}: {key} must be {KIND_TEXT[kind]}, not {value!r}.")
    return None if kind == OPT and value == "" else value


def load():
    values = {key: default for key, (_, default) in SETTINGS.items()}
    path = find_file()
    if path:
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            die(f"{path}: not valid TOML: {e}")
        except OSError as e:
            die(f"Could not read {path}: {e}")
        for key, value in data.items():
            if key not in SETTINGS:
                hint = difflib.get_close_matches(key, SETTINGS, n=1)
                die(f"{path}: unknown setting '{key}'"
                    + (f"; did you mean '{hint[0]}'?" if hint else ".")
                    + " See glovebox.toml.example.")
            values[key] = check_value(path, key, SETTINGS[key][0], value)
    # Relative paths in the config (packages_file) are relative to it.
    return types.SimpleNamespace(**values, path=path,
                                 dir=os.path.dirname(path) if path else REPO)


config = load()
