# How glovebox works

## What it does

- **Isolates the VM from every private address** via nftables: the host it
  runs on, your LAN, your router, other VMs, VPNs, and the cloud metadata IP,
  except the services you [allow](configuration.md#allow-services-on-the-lan-or-the-host).
  A built-in [containment check](usage.md#check) verifies this by probing every
  private address that matters, from the inside.
- **Two egress modes, decided on the host:** direct internet (NAT'd through
  the host), or only through a TLS-inspecting [Squid](https://www.squid-cache.org/)
  proxy with domain allowlists.
- **Prevents IP/MAC/ARP spoofing** via libvirt's `clean-traffic`
  [nwfilter](https://libvirt.org/formatnwfilter.html), pinned to the VM's IP,
  so forged frames are dropped at L2 before they reach the bridge.
- **Strips the emulated-device surface**, leaving no graphics, video, sound,
  USB, memory balloon, virtio channels, TPM, or CD-ROM, and switching off the
  chipset's HPET timer. The VM boots via UEFI with Secure Boot off (no SMM
  emulation) and only a serial console attached. Device emulation is where
  most VM escape vulnerabilities have lived, like
  [VENOM](https://en.wikipedia.org/wiki/VENOM). Nested virtualization is also
  disabled, as it exercises KVM's most complex code paths, like the one behind
  the [Januscape](https://github.com/V4bel/Januscape) escape. See the comments
  in [`gloveboxlib/manage.py`](../gloveboxlib/manage.py) for details.
- **Keeps the agent away from root in the guest**, which most VM escapes
  start from. The agent gets its own account without sudo or a password,
  apart from your sudo account, so it can't capture your sudo password. The
  guest kernel runs in lockdown (`lockdown=integrity`: no unsigned modules,
  `/dev/mem` or kexec, even for root) with hardened sysctls. The VM shares no
  memory pages with other VMs (KSM side channel), and `check` verifies that
  QEMU on the host runs unprivileged and under its seccomp sandbox.
- **Uses any [cloud image](https://cloud.debian.org/images/cloud/)** (Debian
  13 by default) to create a headless VM, copying its disk from a cached
  download (checks for an update on each run) so each new sandbox spins up in
  seconds. The cache stays for the next `create`; `uninstall` removes it.
- **Applies [cloud-init](https://cloudinit.readthedocs.io/)** to create the
  accounts, install your SSH key, set a console/sudo password, pin a static
  IPv4 address (no DHCP, IPv6 disabled), set up the proxy or DNS, and install
  extra packages.
- **Runs on [KVM](https://en.wikipedia.org/wiki/Kernel-based_Virtual_Machine)**,
  the hypervisor underneath much of the public cloud. It's a full
  virtualization layer built into the Linux kernel, adding no new runtime,
  orchestrator, or vendor to your trust base, with near-native performance.
- **Sets the host up for you** (`host-setup`) on Debian/Ubuntu and
  Arch-based hosts: it shows a plan and changes nothing until you say yes.
  It records every change, so `host-check` can verify the host any time and
  `uninstall` can put it back as it was.

<p align="center">
<img src="../assets/defense-in-depth.svg" width="820"
     alt="Defense in depth: the host holds your credentials and files and runs only terminals, browsers and editor UIs; it guards every VM with the firewall (egress mode by IP, Squid allowlists, private_allow, no inbound connections), clean-traffic anti-spoofing, and an unprivileged, seccomp-confined QEMU (which check verifies) without emulated devices, nested virtualization or page sharing. Inside the glovebox VM (KVM, kernel lockdown, hardened sysctls, IPv4 only) your account has sudo for administration; the agent account has no sudo, no password and no privileged groups, and runs AI agents, MCP servers, editors and dev tools. Untrusted code and its dependencies run one layer deeper, in a rootless container. You reach your account and the agent's over SSH.">
</p>

The innermost layer, a rootless container (e.g. podman) for the untrusted
code an agent runs, is a recommendation: glovebox doesn't set it up.

## How it works

All sandboxes sit on one libvirt bridge (`br-glovebox`, `10.248.0.0/24`;
the host is `10.248.0.254`). The VM name sets its address: `sandbox<n>` gets
`10.248.0.<n>`, and an optional `-<label>` is just for you (`sandbox5-dev` is
`10.248.0.5`).

<p align="center">
<img src="../assets/network.svg" width="820"
     alt="Network: two kinds of sandbox VM on the bridge br-glovebox behind the host's firewall (nftables plus libvirt clean-traffic, deciding by the VM's pinned IP, fail-closed). A proxy-only VM (sandbox1-99) may reach only the Squid proxy on the host, which lets allowlisted domains out; its direct internet access and DNS are dropped. A direct VM (sandbox100-199) reaches the internet and DNS through NAT. Both are dropped on the way to the host's services, the LAN, other private addresses and other VMs, except the services listed in private_allow. The host reaches every VM over SSH; nothing else (the LAN, containers, VMs on other networks, VPN peers) can open a connection to a VM.">
</p>

nftables rules in glovebox's own tables match only traffic from or to that
bridge, so the rest of the host's firewall is left as it is. For each packet
from a sandbox they decide, by its source IP (which `clean-traffic` pins):

| Destination | Allowed when |
| :-- | :-- |
| a private service listed in `private_allow` | the entry's source covers the VM (both modes) |
| a private DNS resolver in `private_dns`, port 53 | the VM is a direct-internet VM |
| the proxy on the host (`PROXY_ADDR:PROXY_PORT`) | the VM is a proxy-only VM |
| anything else private (host, LAN, other VMs, VPNs) | never |
| the internet | the VM is a direct-internet VM |

The other way round, nothing may open a connection *to* a sandbox: not the
LAN (a device that routes the sandbox subnet through your host), not a
container, not a VM on another libvirt network, not a VPN peer. Only the
host itself reaches the VMs (SSH, `check`). To open a VM's service from
elsewhere, tunnel it through the host: `ssh -L 3000:localhost:3000
agent@10.248.0.5`.

Which mode a VM gets depends on its number, through two nftables sets:

| Set | Mode | Default range |
| :-- | :-- | :-- |
| `direct_internet` | direct internet; DNS from `nameservers` | `sandbox100`–`sandbox199` |
| `proxy_internet` | only through the proxy (Squid); no DNS | `sandbox1`–`sandbox99` |

It's fail-closed: a VM in neither set gets nothing, and `create`, `start`
and `check` refuse it. Nothing inside a VM can change its mode; to change
it, recreate the VM with a number from the other range. Proxy-only VMs get
no DNS on purpose: the proxy resolves names, and DNS would be a tunnel
around it.

## What it doesn't protect against

- **The host's other traffic.** Sandboxes need `ip_forward=1`, which lets
  the host forward packets between all its interfaces, not only the
  sandbox bridge (as with libvirt's default NAT network or Docker).
  glovebox filters only `br-glovebox`; if other devices could use your host
  as a gateway between its other networks (a VPN, a second LAN), the host's
  own firewall has to stop that.
- **The proxy is not data-loss prevention.** A proxy-only VM can reach only
  the allowlisted domains, but it can use them as it likes: an agent could
  send data to the Claude API under another API key. The allowlist limits
  where traffic goes, not what it carries.
- **Squid follows DNS.** Squid runs on the host, so glovebox's firewall
  doesn't filter where it connects. Allow only domains whose DNS you trust;
  see the warning in
  [`allowed_domains.txt`](../host-setup/squid/allowed_domains.txt).
- **The firewall must be loaded.** The libvirt network adds no rules of its
  own (`forward mode='open'`), so the bridge is filtered only while
  glovebox's nftables tables are loaded. They load at boot before the
  network and again whenever the distro's `nftables.service` starts,
  restarts or reloads (its `flush ruleset` would wipe them otherwise), and
  `start` and a libvirt hook refuse to start a sandbox without them. Still
  open: `systemctl stop nftables` (which flushes the whole ruleset) or a
  hand-made `nft flush ruleset` removes them while sandboxes run;
  `host-check` reports missing tables.

## Design principles

1. **The host's firewall is left alone.** The host's own nftables ruleset
   and firewall stay as they are. glovebox's rules live in its own
   `glovebox` tables and match only traffic from or to the bridge
   (`br-glovebox`). The one exception: on an active UFW, `host-setup` adds two
   UFW rules scoped to `br-glovebox`, after showing them and getting a yes.
2. **The firewall decides, the guest follows.** A VM's mode is decided on
   the host, by its IP, in the nftables sets. Whatever happens inside the
   VM, it can't leave its mode. The IP is trustworthy because libvirt's
   `clean-traffic` pins each VM to its IP and MAC.
3. **Fail-closed.** A VM in neither set gets no egress, and `create`,
   `start` and `check` refuse it. An IP in both sets is an error and is
   refused too. A missing tool or setting means refusal, not a skipped
   check.
4. **Read-only unless asked.** Only `host-setup` and `uninstall` write to
   the host, and only after showing their plan and getting a yes. The
   other commands read the nftables sets and Squid's files and never change
   them; `start`, `stop` and `delete` change only the VM (`create` also
   caches the cloud image), and `host-check --probe` adds a temporary
   network namespace that it removes again.
5. **No secrets go into the VM.** Only the public certificate
   `sandboxCA.crt` goes into proxy-only VMs. Its key stays on the host.
6. **Checked against reality.** `check` verifies from inside the VM, and
   `host-check --probe` from the bridge, that the setup actually works as
   intended, not just that it's configured.
7. **Everything is undoable.** Every host change glovebox makes is
   recorded with what was there before, and `uninstall` puts it back.

## Repository layout

| Path | What it is |
| :-- | :-- |
| [`glovebox`](../glovebox) | The command: `host-setup`, `host-check`, `uninstall`, `create`, `list`, `start`, `stop`, `check`, `squid-denied`, `delete`. |
| [`glovebox.toml.example`](../glovebox.toml.example) | Every setting with its default and meaning; copy it to `glovebox.toml` and keep only what you change. |
| [`glovebox-packages.txt.example`](../glovebox-packages.txt.example) | Format of the optional extra-package list; copy it to `glovebox-packages.txt`. |
| [`host-setup/libvirt-net/glovebox.xml`](../host-setup/libvirt-net/glovebox.xml) | The libvirt network: bridge and host address. |
| [`host-setup/nftables/glovebox.conf`](../host-setup/nftables/glovebox.conf) | The firewall rules and their sets: `direct_internet`, `proxy_internet`, `private_dns`, `private_allow`. |
| [`host-setup/sysctl/99-glovebox.conf`](../host-setup/sysctl/99-glovebox.conf) | IPv4 forwarding. |
| [`host-setup/squid/`](../host-setup/squid/) | `squid.conf` and the two domain allowlists for proxy-only VMs. |
| [`provision/`](../provision/) | Example `--provision` scripts (Claude Code, a dev environment). |
| [`gloveboxlib/`](../gloveboxlib/) | The implementation. |
| [`docs/`](../docs/) | This documentation. |
| [`SECURITY.md`](../SECURITY.md) | How to report a vulnerability, privately. |
| [`LICENSE`](../LICENSE), [`LICENSE.MIT`](../LICENSE.MIT) | GNU GPL v3 (this project); the MIT License of the original kvm-sandbox. |

What glovebox puts on the host (besides the packages host-setup installs);
`uninstall` removes or restores all of it:

| Host path | From |
| :-- | :-- |
| `/etc/glovebox/nftables.conf`, `/etc/systemd/system/glovebox-nftables.service` | `host-setup/nftables/glovebox.conf` |
| `/etc/libvirt/hooks/qemu.d/glovebox` | `host-setup/libvirt-hook/` |
| `/etc/sysctl.d/99-glovebox.conf` | `host-setup/sysctl/` |
| libvirt network `glovebox` | `host-setup/libvirt-net/` |
| `/etc/squid/squid.conf`, `/etc/squid/*_domains.txt` | `host-setup/squid/` |
| `/etc/squid/ssl_cert/sandboxCA.pem` (key, stays on the host), `sandboxCA.crt` (public, goes into proxy-only VMs) | generated |
| `/var/cache/squid/ssl_db` (the certificates Squid generates) | generated |
| `/etc/systemd/system/squid.service.d/glovebox.conf` | generated |
| two UFW rules on `br-glovebox`, if UFW is active | `host-setup ufw` |
| `/var/lib/glovebox/` (the journal, and the files host-setup replaced) | generated |
| `<image_dir>/base-<image>.qcow2`, the cached cloud image | `create` |
| per VM: `<image_dir>/<name>.qcow2` and the libvirt domain | `create` (removed by `delete`) |

Logs of host-setup and uninstall stay in `logs/` in the glovebox directory.
