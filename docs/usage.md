# Usage

## `create`

```bash
./glovebox create sandbox5                     # IP 10.248.0.5, proxy-only
./glovebox create sandbox105-web               # IP 10.248.0.105, direct
./glovebox create sandbox7 --memory 2048 --vcpus 2 --disk 40G
./glovebox create sandbox8 --claude
./glovebox create sandbox10 --claude --provision ./provision/sample-dev-env.sh
./glovebox create sandbox11 --provision ./my-setup.sh --provision-as agent
./glovebox create sandbox9 --user alice --agent-user claude --packages ~/dev-packages.txt
```

| Option | Effect |
| :-- | :-- |
| `--memory`, `--vcpus`, `--disk` | VM size (defaults from the configuration). |
| `--user`, `--agent-user` | Account names for this VM. |
| `--packages FILE` | Extra-package list for this VM instead of `glovebox-packages.txt`. |
| `--provision EXECUTABLE` | A host executable copied into the VM and run once, on first boot (see below). |
| `--provision-as root\|user\|agent` | The account `--provision` runs as (default `root`). |
| `--claude` | Install Claude Code for the agent account and set it up (see below). |

`create` checks the host first (tools, bridge, forwarding, the nftables
mode, the accounts, the package list) and refuses before changing anything
if something is off. It returns once the VM answers on its IP, and prints
how to log in. cloud-init may still be finishing in the background, and the
VM reboots once at the end of its first boot; `ssh user@<ip> cloud-init
status --wait` waits for that (retry if SSH isn't up yet).

**`--provision`** embeds the executable (a script with a shebang line, or a
binary) in the cloud-init config, writes it to `/root/<filename>` in the
guest and runs it once, after the extra packages and Claude Code; its
output ends up in `/var/log/cloud-init-output.log`. It runs as
`--provision-as`: `root` (the default; for `apt-get` and the like), or the
`user` or `agent` account, in that account's home directory. Either way it
starts with a clean environment plus `/etc/environment` (the proxy
variables on a proxy-only VM), and gets the account to set tools up for
(the agent account, else `user`) in `GLOVEBOX_USER`, so a root script
doesn't hardcode it; see [`provision/`](../provision/). On a proxy-only VM,
Squid must allow what it downloads (`provision_domains.txt`).

**`--claude`** installs Claude Code for the agent account (the login
account when `agent_user` is off) with Anthropic's native installer
(`https://claude.ai/install.sh`), so it lives in that account's
`~/.local/bin`, which is put on its `PATH` (`~/.bashrc`). It also writes
`claude_env` (telemetry, error reporting and `/bug` off by default) into
both `/etc/environment` and that account's `~/.claude/settings.json` (`env`
block). On a proxy-only VM, `settings.json` also gets the proxy variables,
and both files get `NODE_EXTRA_CA_CERTS` (Node.js, and so Claude Code,
ignores the system trust store); `create` refuses unless Squid's allowlist
has Claude Code's domains (`host-setup squid` adds them). A failed install
shows up in `/var/log/cloud-init-output.log`.

For the console, resources and snapshots,
[virt-manager](https://virt-manager.org/) and
[Cockpit](https://cockpit-project.org/) (`cockpit-machines`) work with
glovebox's VMs too.

## `list`, `start`, `stop`

```bash
./glovebox list                    # every sandbox: state, IP, mode, accounts
./glovebox start sandbox5          # start (or resume) it
./glovebox stop sandbox5           # clean shutdown; waits up to 120 s
./glovebox stop sandbox5 --timeout 300
./glovebox stop sandbox5 --force   # power off at once; unsaved data is lost
```

- **`list`** shows only the VMs `create` made (those with glovebox's
  metadata) and counts the other libvirt VMs. The mode comes from the
  nftables sets: `none (dropped)` for an IP in neither set, and `?` when
  glovebox's rules aren't loaded.
- **`start`** refuses when glovebox's nftables tables aren't loaded or the
  VM's IP is in neither set (or both): the libvirt network is in `open` mode,
  so without those rules nothing would filter the VM's traffic.
- **`stop`** asks the guest to shut down (ACPI) and waits; on timeout it says
  so and suggests `--force`. A paused VM can only be resumed or forced off.

## `check`

```bash
./glovebox check sandbox5                  # nmap and curl already in the VM
./glovebox check sandbox5 --install-tools  # install them first (apt-get)
```

It logs in as the VM's `user` (from its metadata) and tests, from inside the
VM, both what must work and what must not. It asks for the VM password, as
the scan runs `nmap` with sudo in the guest (or takes it from
`GLOVEBOX_PASSWORD` or `password` in the configuration). On a proxy-only
VM, `--install-tools` needs `deb.debian.org` open in
`provision_domains.txt`. Every row is `[ok]`, `[warn]`
(something allowed doesn't work), `[info]`, or `[FAIL]` (containment or
hardening is broken):

- **Hardening.** On the host: QEMU runs as non-root, under seccomp, and with
  KSM on the VM has `nosharepages` (FAIL otherwise); sVirt confinement is
  reported, unmitigated CPU vulnerabilities warned about. In the guest: the
  agent has no sudo and no privileged group, there is an agent account,
  kernel lockdown is on, the sysctls are hardened and your home is private
  (FAIL otherwise).
- **Egress mode.**
  - Direct: the internet and DNS work; the proxy is unreachable.
  - Proxy-only: nothing gets out directly (HTTPS, DNS, TCP/UDP to
    `check_public_targets`, ICMP); the proxy answers; every entry of both
    allowlists loads through it; `check_denied_domains` (HTTP and HTTPS), an
    IP literal (HTTP and HTTPS), domain fronting (allowed name, foreign
    `Host`) and a CONNECT to port 22 are refused.
- **Allowed private services.** Every `private_allow` entry that applies to
  the VM is probed (a range by its first address and port): `ok` when the
  service answers, `warn` when it doesn't (down, nothing listening, or
  dropped outside glovebox), `info` when a silent UDP service can't be
  confirmed.
- **Private network scan.** `nmap` (SYN and UDP, via `sudo` in the guest)
  probes `check_tcp_ports`/`check_udp_ports` on every private address that
  matters: the host's interfaces, the LAN router and devices, other running
  sandboxes, the hosts in `private_allow`, the cloud-metadata IP, and one
  address per `check_private_nets` block. Each service that answers is
  listed with the configuration that allows it (the proxy, `private_dns`, or
  a `private_allow` entry), or as `FAIL: NOT allowed by the configuration`.

It ends with one line per area and `Containment check PASSED/FAILED`. Exit
code: 0 on pass, 1 on any FAIL, 2 on errors (SSH, missing tools, scan
failure). Warnings don't fail the check.

## `squid-denied`

```bash
./glovebox squid-denied sandbox5
```

Lists what Squid refused the VM, from its access log: a 403 means a domain is
missing from the allowlists, a 409 a name/destination mismatch (fronting).

## `delete`

```bash
./glovebox delete sandbox5     # VM, disk and seed files; asks first
```

Only VMs `create` made (with glovebox's metadata); others are left to
`virsh` or virt-manager. The cached cloud image stays for the next `create`.
