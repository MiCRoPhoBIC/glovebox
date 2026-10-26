# Host setup

## Automatic: `host-setup`

`host-setup` does the whole host side, on Debian/Ubuntu (`apt-get`) and
Arch-based hosts (`pacman`). It reads the host's current state, prints every
step with its exact commands (and a diff of every file it replaces), and
changes nothing until you answer yes. `--dry-run` only prints the plan;
re-running it when everything is in place changes nothing.

Run it, like every glovebox command, as your normal user with full sudo
rights (the `sudo` group on Debian/Ubuntu, `wheel` on Arch). glovebox
checks that first, with `sudo -v` (asking for your password once), and
stops before doing anything if sudo is missing or refuses you, saying how
to set it up.

```bash
./glovebox host-setup all --dry-run    # just show what it would do
./glovebox host-setup all              # all parts below, in this order
./glovebox host-setup virt             # QEMU/KVM, libvirt, create's tools
./glovebox host-setup network          # libvirt network + IP forwarding
./glovebox host-setup nftables         # the firewall rules, loaded at boot
./glovebox host-setup nftables --forward-guard     # ...and limit forwarding
./glovebox host-setup nftables --no-forward-guard  # ...or remove that limit
./glovebox host-setup squid            # the proxy, with its CA
./glovebox host-setup ufw              # UFW rules on the bridge, if needed
```

- **virt:** installs QEMU/KVM, libvirt, `virt-install`, the UEFI firmware
  and the tools `create` runs (`qemu-img`, `xorrisofs`, `openssl`, `curl`,
  `ip`, `ping`), and starts libvirt now and at boot (unless it already
  runs, as `libvirtd` or as the modular `virtqemud`). It then checks for
  `/dev/kvm` (hardware virtualization on in the firmware setup), `ebtables`,
  and libvirt's `clean-traffic` filter, which `create` uses against IP
  spoofing. On Arch it also installs `iptables` (the nft variant, which
  provides `ebtables`) and `dnsmasq`, which libvirt lists only as optional.
- **network:** installs the sysctl drop-in that turns IPv4 forwarding on,
  and defines, starts and autostarts the libvirt network. An existing
  network that differs is left alone and reported. Needs libvirt, from
  `virt` in the same or an earlier run. Forwarding is host-wide, so the
  plan says what it means on this host: whether it was on before, the
  other interfaces the host could now route between, and whether the
  host's own firewall filters forwarded traffic; a warning if nothing does
  (see [IP forwarding and
  forward_guard](how-it-works.md#ip-forwarding-and-forward_guard)).
- **nftables:** checks the syntax, installs the rules as
  `/etc/glovebox/nftables.conf`, and loads them now and at boot with its
  own `glovebox-nftables.service`. `/etc/nftables.conf` isn't touched. The
  unit loads the rules again whenever the distro's `nftables.service`
  starts, restarts or reloads, so the `flush ruleset` that Debian's
  `/etc/nftables.conf` starts with can't leave the bridge unfiltered. It
  also installs a libvirt hook, `/etc/libvirt/hooks/qemu.d/glovebox`, that
  refuses to start a sandbox VM while the rules aren't loaded (autostart,
  `virsh`, virt-manager), and restarts libvirt so it finds the hook
  (running VMs keep running). Edit the sets in the repo's file and re-run
  to apply them.
  **forward_guard** (optional): when nothing on the host filters forwarded
  traffic and it isn't on yet, this part explains the situation and asks
  whether to turn it on (a dry run only says it would ask). Turned on, it
  installs `/etc/glovebox/forward-guard.d/forward-guard.conf`, which
  `/etc/glovebox/nftables.conf` includes: the table `ip glovebox_guard`
  drops forwarded IPv4 that neither comes from nor goes to `br-glovebox`.
  It also stops Docker, other libvirt NAT networks and VPN routing on the
  host from forwarding. `--forward-guard` turns it on and `--no-forward-guard`
  removes it, without the question; without either, an existing
  forward_guard is kept.
- **squid:** installs Squid with OpenSSL (`squid-openssl` on Debian), creates
  the CA only if there is none (the VMs trust the existing one; valid
  `proxy_ca_days`, 10 years by default), the
  certificate cache, `squid.conf`, and the two allowlists if missing (existing
  ones are kept, as you edit them in place). A systemd drop-in starts Squid
  after libvirt, since it listens on the bridge address.
- **ufw:** if UFW is active and its policies would drop the sandbox
  traffic, adds the two rules on `br-glovebox` (`ufw route allow in on
  br-glovebox`, and `ufw allow in on br-glovebox to 10.248.0.254 port 3128
  proto tcp`, both with the comment `glovebox`). UFW saves rules in
  `/etc/ufw/user.rules` at once, so they survive reboots. If UFW's sysctl
  file (`IPT_SYSCTL` in `/etc/default/ufw`, usually `/etc/ufw/sysctl.conf`)
  sets `net/ipv4/ip_forward=0`, it comments that line out (with a backup):
  UFW applies the file at every start, after `/etc/sysctl.d/`, and would
  turn forwarding off. Nothing else in UFW is changed.

Before planning, it checks that the files in `host-setup/` agree with
the configuration (bridge, subnet, proxy address and port, CA path) and
stops if they don't.

Every change is recorded, as it is made, in the journal
`/var/lib/glovebox/journal.jsonl` (root-owned, on the host, so it doesn't
depend on the repo). A file that gets replaced is saved first under
`/var/lib/glovebox/backups/`. The plan shows what each step records (`+
journal:`). `create` records the cloud image it caches there too.
`./glovebox uninstall` undoes it all; see [Undoing it](#undoing-it-uninstall).

Every run, including `--dry-run` and a declined plan, is logged to
`logs/host-setup-<date>-<time>.log` in the glovebox directory (git-ignored,
`0600`): the plan, your answer, each step with its commands and their output,
what it recorded, and any error, so you can check later what was done. The
path is printed at the end.

## Checking the host: `host-check`

```bash
./glovebox host-check           # read-only
./glovebox host-check --probe   # also sends real traffic, no VM needed
```

Checks that the host is set up as glovebox expects, now and after a reboot,
and what else on it may get in the way. Exit code 1 on any FAIL.

- **host-setup:** runs host-setup's planning without changing anything;
  every step it would still take is a FAIL (a package, file, unit, the
  network, a UFW rule missing or different).
- **Live state:** `ip_forward`, the bridge and its address; the loaded
  nftables tables compared with `/etc/glovebox/nftables.conf` (the file is
  loaded in a scratch network namespace and both are compared, so a rule or
  set element changed by hand shows); Squid listening on the proxy address,
  `squid -k parse`, the CA's expiry.
- **After a reboot, and the distro's `nftables.service`:** checks that
  `glovebox-nftables.service` follows its start, restart and reload (a
  FAIL when `/etc/nftables.conf` flushes the ruleset and it doesn't), and
  notes that stopping it flushes everything.
- **Other firewalls:** they can't open what glovebox's tables drop (a drop
  in any base chain wins), but they can block what it allows. Reports
  firewalld, Docker's `FORWARD DROP` policy (which drops direct-mode
  traffic), legacy iptables rules (invisible to `nft`), and every other
  nftables chain on the input and forward hooks.
- **IP forwarding beyond the sandboxes:** what the host forwards apart from
  the bridge. ok when its own firewall filters forwarded traffic (the
  chains found are listed) or forward_guard is on; a warning when nothing
  does, naming the interfaces it routes between; and a warning when
  forward_guard is on while bridges or VPN tunnels on the host would route
  through it. The live state also checks that forward_guard's table is
  loaded exactly when its file is there.
- **Journal:** files host-setup wrote that were edited or removed since.
- **`--probe`:** attaches a temporary network namespace to `br-glovebox`
  and, from a free address of each mode (direct, proxy-only, neither),
  tries the internet, DNS, the proxy (an allowlisted domain must work,
  example.com must get a 403), the host and the LAN gateway (blocked,
  unless `private_dns` or `private_allow` allows them for that mode). This goes
  through all the host's firewalls, as a VM's traffic would; libvirt's
  `clean-traffic` doesn't apply to it. The namespace is removed afterwards,
  also on Ctrl+C, and a leftover one at the next run. Inside-the-VM checks
  stay with `check`.

## Undoing it: `uninstall`

```bash
./glovebox uninstall --dry-run   # read the plan
./glovebox uninstall             # run it (asks first)
```

Undoes, newest first, exactly what host-setup (and `create`) recorded and
nothing else: restores the replaced files, removes the files and
directories it created (the CA and the cached cloud image too), puts
services, `ip_forward` and the libvirt network back as they were, deletes
glovebox's nftables tables and the UFW rules it added. Anything that was
already there before is left alone.

- **Sandbox VMs:** it refuses while any exist. Delete them first.
- **libvirt:** if host-setup started `libvirtd`, it asks before putting it
  back, and lists the other libvirt VMs on the host, which need it.
- **forward_guard:** its file and table go with the rest.
- **`ip_forward`:** set back to its value from before host-setup, also
  live. If Docker or another libvirt network started meanwhile, restart
  it afterwards, as it relies on forwarding.
- **A file edited since:** shows the diff and asks. If you say yes, your
  version is kept as `<file>.glovebox-uninstall-<date>-<time>`.
- **Packages:** a separate question, as you may use them for other things by
  now. It removes only the packages that appeared with host-setup's installs
  (dependencies included), and says which packages installed later depend on
  them and which other libvirt VMs exist.
- **What you keep** stays in the journal, so a later uninstall offers it
  again. Once everything is undone, `/var/lib/glovebox` goes too.
- Logged to `logs/uninstall-<date>-<time>.log`, like host-setup.
- Setting the host up by hand (below) isn't recorded, so `uninstall` can't
  undo it.

## By hand

On another distribution, or to do it by hand:

- **Packages** (Debian names): `qemu-system-x86 qemu-utils
  libvirt-daemon-system libvirt-clients virtinst ovmf xorriso nftables curl
  openssl iputils-ping`, plus `squid-openssl` for proxy-only VMs. Python 3.11+,
  standard library only.
- **IP forwarding:** copy `host-setup/sysctl/99-glovebox.conf` to
  `/etc/sysctl.d/` and run `sudo sysctl --system`.
- **Network:** `sudo virsh net-define host-setup/libvirt-net/glovebox.xml`,
  then `net-autostart glovebox` and `net-start glovebox`.
- **Firewall:** check with `sudo nft -c -f host-setup/nftables/glovebox.conf`
  and load it at every boot, before the network (it replaces only its own
  tables). If your `/etc/nftables.conf` flushes the ruleset, reload it
  whenever `nftables.service` starts, restarts or reloads too: the unit
  host-setup installs (`NFT_UNIT_TEXT` in
  [`gloveboxlib/hostsetup.py`](../gloveboxlib/hostsetup.py)) does both.
  Copy `host-setup/libvirt-hook/glovebox` to
  `/etc/libvirt/hooks/qemu.d/` (executable) and restart libvirt, so no
  sandbox starts without the rules. For forward_guard, copy
  `host-setup/nftables/forward-guard.conf` to
  `/etc/glovebox/forward-guard.d/` and reload the rules.
- **UFW** (if active): `sudo ufw route allow in on br-glovebox` and `sudo
  ufw allow in on br-glovebox to 10.248.0.254 port 3128 proto tcp` (UFW
  keeps them across reboots). Make
  sure `/etc/ufw/sysctl.conf` doesn't set `net/ipv4/ip_forward=0` (the
  commented-out default is fine).
- **Squid**, as root, from the glovebox directory:
  ```bash
  D=/etc/squid/ssl_cert
  install -d -o proxy -g proxy -m 0750 $D
  (umask 077; openssl req -new -newkey rsa:4096 -sha256 -days 3650 -nodes -x509 \
    -subj "/CN=sandbox-squid-CA" -keyout $D/sandboxCA.pem -out $D/sandboxCA.pem)
  openssl x509 -in $D/sandboxCA.pem -out $D/sandboxCA.crt   # public, for the guests
  chown proxy:proxy $D/sandboxCA.* && chmod 600 $D/sandboxCA.pem
  rm -rf /var/cache/squid/ssl_db   # certificates signed by an earlier CA, if any
  /usr/lib/squid/security_file_certgen -c -s /var/cache/squid/ssl_db -M 4MB
  chown -R proxy:proxy /var/cache/squid/ssl_db
  cp host-setup/squid/squid.conf host-setup/squid/*_domains.txt /etc/squid/
  squid -k parse && systemctl restart squid
  ```
  Squid listens on the bridge address, so start it after the libvirt
  network (host-setup adds a systemd drop-in for that).
