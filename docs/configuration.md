# Configuration

## The configuration file

Settings have built-in defaults, so glovebox works without a configuration
file. To change some, put only those in a [TOML](https://toml.io) file, in
the first of these places that exists:

1. the file named by `$GLOVEBOX_CONFIG`;
2. `glovebox.toml` next to the `glovebox` command (git-ignored);
3. `~/.config/glovebox/config.toml` (or under `$XDG_CONFIG_HOME`).

[`glovebox.toml.example`](../glovebox.toml.example) lists every setting,
commented out with its default and an explanation; copy it and uncomment
what you change:

```toml
memory = 2048
user = "alice"
nameservers = ["192.168.1.1"]
```

An unknown setting (a typo) or a wrong type stops every command with a clear
message. TOML has no null: a setting that can be off (`agent_user`, `proxy`,
`proxy_ca`, `packages_file`, ...) takes `""` for off. Relative paths
(`packages_file`) are relative to the configuration file. A `git pull` never
touches your file.

| Settings | What they set |
| :-- | :-- |
| `memory`, `vcpus`, `disk` | VM size defaults (`create --memory/--vcpus/--disk`). |
| `user`, `agent_user` | The guest accounts (`create --user/--agent-user`); see [Accounts](#accounts). |
| `packages_file` | The optional extra-package list (`create --packages`); see [Extra packages](#extra-packages). |
| `ssh_key` | Your public key, for both accounts. Unset: `~/.ssh/id_ed25519.pub`, `id_rsa.pub` or `id_ecdsa.pub`, the first that exists; if none does, `create` lists the other `*.pub` keys in `~/.ssh` and asks which to use. |
| `password` | The VM's console and sudo password (unset: asked for; see below). |
| `image_url`, `osinfo`, `image_dir` | The cloud image, its `osinfo-query os` id, and where disks live. |
| `nameservers` | DNS for direct-internet VMs; a private one must also be in `private_dns`. |
| `autostart` | Start VMs at host boot. |
| `proxy`, `no_proxy`, `proxy_ca` | The proxy proxy-only VMs use, and the CA they trust. |
| `proxy_ca_days` | How long the CA host-setup creates is valid (default 3650 days, 10 years). An existing CA is kept: to renew it, delete `/etc/squid/ssl_cert/sandboxCA.{pem,crt}`, re-run `host-setup squid` (it also recreates Squid's certificate cache and restarts Squid) and recreate the proxy-only VMs. |
| `proxy_allowed_domains`, `proxy_provision_domains`, `proxy_access_log` | Squid's files, read by `check` and `squid-denied`. |
| `claude_env` | Variables `--claude` sets for Claude Code (telemetry off). |
| `check_*` | What `check` probes: ports, private ranges, public targets, denied domains. |
| `host_address`, `bridge` | Host topology; must match `host-setup/` (`host-setup` checks). |

The VM password (console login + sudo) is prompted for by default. To skip
the prompt, set `GLOVEBOX_PASSWORD` in the environment, or `password` in
the configuration file (stored in the clear).

## Egress modes

Edit the ranges of `direct_internet` and `proxy_internet` in
[`glovebox.conf`](../host-setup/nftables/glovebox.conf) and run
`./glovebox host-setup nftables`. An IP must be in exactly one of them. The
firewall applies a change at once, but a VM is set up for its mode when
it's created (proxy variables, CA, DNS): recreate a VM whose number moves
to the other set.

- **Direct:** the VM gets the DNS servers in `nameservers`
  (configuration).
  - A public server (the default, Cloudflare) needs nothing else.
  - A server on a private address (your router, a Pi-hole, a resolver on
    the host) is blocked like any private address. Add its IP to the
    `private_dns` set in
    [`glovebox.conf`](../host-setup/nftables/glovebox.conf) as well and
    run `./glovebox host-setup nftables`: that opens port 53 to it, for
    direct-internet VMs only. `create` refuses a private server that isn't
    in `private_dns`, so you never get a VM without working DNS.

  ```toml
  nameservers = ["192.168.1.1"]          # glovebox.toml
  ```
  ```nft
  set private_dns {                      # host-setup/nftables/glovebox.conf
      type ipv4_addr
      flags interval
      elements = {
          192.168.1.1,
      }
  }
  ```
- **Proxy-only:** on first boot the VM gets the proxy variables
  (`HTTP(S)_PROXY`, `http(s)_proxy`, `NO_PROXY`) in `/etc/environment`, apt
  gets `/etc/apt/apt.conf.d/95proxy`, and `proxy_ca` (the public certificate
  of Squid's TLS-inspection CA, read on the host via `sudo`) joins the system
  trust store. `--provision` scripts and extra packages download through the
  proxy, so it must allow their domains.

## Allow services on the LAN or the host

To let sandboxes reach specific private services (DNS, mail, databases and
the like), list them in the `private_allow` set of
[`glovebox.conf`](../host-setup/nftables/glovebox.conf). It applies in
both modes. Each entry is `source VM(s) . destination . protocol . port(s)`;
addresses take a single IP, a range or a prefix, ports a number or a range,
and an optional `comment` labels the entry in `check`'s report:

```nft
set private_allow {
    type ipv4_addr . ipv4_addr . inet_proto . inet_service
    flags interval
    elements = {
        10.248.0.5 . 192.168.1.10 . tcp . 3306 comment "MySQL",
        10.248.0.1-10.248.0.199 . 192.168.1.20 . tcp . 587 comment "mail submission, all VMs",
        10.248.0.5 . 10.248.0.254 . tcp . 5432 comment "PostgreSQL on the host",
    }
}
```

Then run `./glovebox host-setup nftables` and `./glovebox check <name>`,
which probes every entry from inside the VM. Keep in mind:

- **Use IP addresses.** Proxy-only VMs have no DNS, and their proxy variables
  only matter for HTTP(S), which goes through Squid anyway.
- **The LAN target sees the host's address**, not the VM's: sandbox traffic
  is NAT'd. Grant access (database users, firewall rules) to the host's LAN
  IP.
- **A service on the host itself** (destination `10.248.0.254`) also needs
  UFW, if active, to let it in: `sudo ufw allow in on br-glovebox to
  10.248.0.254 port <port> proto <tcp|udp>`.
- **DNS and other open relays bypass the proxy.** A recursive resolver (or
  mail relay) a proxy-only VM can reach is a way around the proxy's
  allowlist; `check` points that out for DNS.

## Squid allowlists

Two allowlists in `/etc/squid/`, both read by `check`:

- [`allowed_domains.txt`](../host-setup/squid/allowed_domains.txt): what the
  sandboxes need for good: by default Claude Code's API, login, installer
  and updates, which `host-setup squid` adds to an existing file when they
  are missing (`create --claude` needs them). Allow only domains
  whose DNS you trust: Squid connects wherever a name resolves, the LAN
  included, so never a domain where anyone can pick a name's address
  (`nip.io`, `sslip.io`, a wildcard over a hosting service).
- [`provision_domains.txt`](../host-setup/squid/provision_domains.txt): package
  mirrors and installers, needed by `create --provision`, extra packages and
  `check --install-tools`. Comment its entries out (the file must stay) once
  the sandboxes are set up; `check` warns while any are open.

The lists match the name a sandbox asks for, never an IP address's reverse
DNS name (`dstdomain -n`), so an address can't pass by claiming an
allowlisted name. After editing either, run `sudo squid -k reconfigure`.
host-setup installs them only when missing, as you edit them in place. To
find what's missing, list what Squid refused a sandbox, from its access
log:

```bash
./glovebox squid-denied sandbox5
```

## Accounts

Every VM gets two accounts, both logging in over SSH with your key:

- `user` (default `user`): yours, with sudo (the VM password).
- `agent_user` (default `agent`): for Claude Code and other untrusted work,
  with no sudo and no password. If the agent ran in your account, it could
  capture your sudo password (e.g. with a `sudo` alias in `~/.bashrc`) and
  become root.

Home directories are mode `0700`. Pick other names per VM with `--user` and
`--agent-user`; `create` records them in the VM's libvirt metadata, and
`check` logs in with them. `agent_user = ""` runs everything as `user` (not
recommended).

## Extra packages

Optional. `create` installs the Debian packages listed in
`glovebox-packages.txt` in every new VM on first boot, with `apt-get`,
before `--provision`. The file is looked for next to the configuration
file, or next to the `glovebox` command when there is none; `packages_file`
names another one. `create --packages FILE` uses another list for one VM.
One package per line, or several per line separated by spaces; `#` starts a
comment:

```text
git
tmux vim
build-essential python3-venv   # for Python projects
```

Copy [`glovebox-packages.txt.example`](../glovebox-packages.txt.example) to start;
the file is git-ignored. `create` logs which packages it will install, or
that there is no list. On a proxy-only VM apt goes through Squid, so
`deb.debian.org` must be open in `provision_domains.txt`. Failures show up in
`/var/log/cloud-init-output.log` in the guest.
