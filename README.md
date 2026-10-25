# glovebox

**Spin up hardened KVM sandboxes for AI agents in one command.** glovebox
sets up the host, creates and manages the VMs, and enforces each one's egress
in the host firewall: direct internet or an allowlisted proxy only, never the
host or your LAN. Verifiable, and fully undoable.

[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
![Hosts: Debian, Ubuntu, Arch, CachyOS](https://img.shields.io/badge/hosts-Debian%20%7C%20Ubuntu%20%7C%20Arch%20%7C%20CachyOS-informational)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-informational)

<p align="center">
<img src="assets/network.svg" width="820"
     alt="Network: two kinds of sandbox VM on the bridge br-glovebox behind the host's firewall (nftables plus libvirt clean-traffic, deciding by the VM's pinned IP, fail-closed). A proxy-only VM (sandbox1-99) may reach only the Squid proxy on the host, which lets allowlisted domains out; its direct internet access and DNS are dropped. A direct VM (sandbox100-199) reaches the internet and DNS through NAT. Both are dropped on the way to the host's services, the LAN, other private addresses and other VMs, except the services listed in private_allow. The host reaches every VM over SSH; nothing else (the LAN, containers, VMs on other networks, VPN peers) can open a connection to a VM.">
</p>

Give Claude Code, another agent, or any untrusted code a full Linux VM to
work in, persistent and per project, and keep it away from everything else
you have.

## Why glovebox

- **Egress decided on the host, by firewall.** Each VM is either *direct*
  (internet through NAT) or *proxy-only* (only through a TLS-inspecting
  Squid that lets allowlisted domains out). The mode is set by the VM's
  number in nftables; nothing inside the VM can change it.
- **No way to your network.** The host, the LAN, your router, other VMs,
  VPNs and the cloud metadata IP are all dropped, except services you
  explicitly allow, and nothing out there can open a connection to a
  sandbox. Anti-spoofing pins every VM to its IP and MAC.
- **Hardened VM, with the agent kept from root.** No emulated devices
  beyond a serial console, no nested virtualization, no memory sharing,
  kernel lockdown, and a separate agent account without sudo, apart from
  yours. `check` verifies that QEMU on the host runs unprivileged, under
  seccomp.
- **Easy to run.** One command sets the host up (showing every change
  first), one creates a ready VM from a cloud image in seconds, and `list`,
  `start` and `stop` manage them.
- **Checked, not assumed.** `check` tests containment from inside a VM;
  `host-check` verifies the host, and with `--probe` sends real traffic
  through every firewall on it.
- **Fully undoable.** Every change to the host is recorded; `uninstall`
  puts it back as it was.
- **Plain KVM.** The hypervisor under much of the public cloud, built into
  Linux: no new runtime, orchestrator or vendor in your trust base.

## Quick start

You need a Debian/Ubuntu or Arch-based host (CachyOS included) with
hardware virtualization on, and an SSH key (`ssh-keygen -t ed25519` if you
have none). The defaults need no configuration. Run everything as your
normal user; glovebox calls `sudo` itself.

Before the first `host-setup`, look at the sets in
[`host-setup/nftables/glovebox.conf`](host-setup/nftables/glovebox.conf):
which VM numbers get which mode, and any LAN services to allow. By default
`sandbox1`–`99` are proxy-only and `sandbox100`–`199` direct.

```bash
git clone https://github.com/MiCRoPhoBIC/glovebox.git
cd glovebox

./glovebox host-setup all --dry-run   # read the plan
./glovebox host-setup all             # set the host up (asks once)
./glovebox host-check                 # verify it

./glovebox create sandbox5 --claude            # with Claude Code, for the agent
ssh user@10.248.0.5 cloud-init status --wait   # first boot; it reboots once
./glovebox check sandbox5 --install-tools      # containment, from inside
ssh agent@10.248.0.5                           # work in it as the agent
```

`sandbox5` gets `10.248.0.5` and is proxy-only. Once your proxy-only VMs are
set up, close the provisioning allowlist; see
[Squid allowlists](docs/configuration.md#squid-allowlists).

## Commands

| Command | What it does |
| :-- | :-- |
| `host-setup <part\|all>` | Set the host up: QEMU/KVM and libvirt, the network, the nftables rules, Squid, UFW rules on the bridge. Shows the plan, asks once, records every change. |
| `host-check [--probe]` | Verify the host, now and after a reboot, and what else on it may block the sandboxes. `--probe` sends real traffic, no VM needed. |
| `uninstall` | Undo every host change glovebox recorded (`host-setup`'s, and `create`'s image cache), newest first. |
| `create <name>` | Create a sandbox VM from a cloud image, with its accounts, key, mode and optional provisioning. |
| `list` | All sandboxes with state, IP, mode and accounts. |
| `start <name>` / `stop <name>` | Start or resume one (only with the firewall rules loaded); shut it down cleanly, or `--force`. |
| `check <name>` | Containment and hardening check from inside the VM. |
| `squid-denied <name>` | What the proxy refused a VM, i.e. what its allowlists lack. |
| `delete <name>` | Delete a sandbox VM with its disk and seed files. |

Every command has `--help`.

## Documentation

- [How it works](docs/how-it-works.md): what it does, the network and its
  rules, what it doesn't protect against, the design principles, the
  repository layout and what goes on the host.
- [Host setup](docs/host-setup.md): `host-setup`, `host-check`,
  `uninstall`, and setting the host up by hand.
- [Configuration](docs/configuration.md): the configuration file, egress
  modes, LAN services, Squid allowlists, accounts, extra packages.
- [Usage](docs/usage.md): `create`, `list`/`start`/`stop`, `check`,
  `squid-denied`, `delete`.

## Origin

glovebox started as a fork of Ertuğ Karamatlı's
[kvm-sandbox](https://github.com/ertug/kvm-sandbox); see its author's [blog
post](https://karamatli.com/posts/network-isolated-kvm-sandbox-ai-agents/)
for the original design. The name comes from the lab glovebox: a sealed box
for hazardous material, worked on from outside through built-in gloves, with
its exhaust leaving only through a filter. Here the agent is sealed in a VM,
you work on it over SSH, and its traffic leaves only as the firewall and the
proxy allow.

## License

glovebox is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. It is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE. See [`LICENSE`](LICENSE) for the full text.

Copyright (C) 2026 MiCRoPhoBIC.

glovebox is derived from [kvm-sandbox](https://github.com/ertug/kvm-sandbox),
Copyright (c) 2026 Ertuğ Karamatlı, released under the MIT License. Its
copyright and permission notice are kept in [`LICENSE.MIT`](LICENSE.MIT), as
that license requires, and apply to the parts that come from it. Files
derived from it say so in their headers; the modifications were made by
MiCRoPhoBIC in October 2026.
