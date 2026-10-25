# Security policy

glovebox exists to contain untrusted code, so a way around that is the most
important kind of bug it can have.

## Reporting a vulnerability

Please report it privately, not in a public issue: on GitHub, open the
repository's **Security** tab and choose **Report a vulnerability**. Include
what you did, what you expected the sandbox to stop, and what got through;
the output of `./glovebox check <name>` and `./glovebox host-check --probe`
helps.

You'll get an answer as soon as possible. Once a fix is out, the report can
be made public, with credit if you want it.

## What counts

- **Containment:** a sandbox reaching what its egress mode forbids: the
  host, the LAN or other private addresses, other VMs, the internet
  directly from a proxy-only VM, or domains outside the Squid allowlists.
- **Leaving its mode:** anything inside a VM changing which mode it gets,
  or spoofing another VM's address.
- **Host changes:** `host-setup` or `uninstall` changing something they
  didn't show in their plan, or leaving the bridge unfiltered (fail-open).
- **Secrets:** the proxy CA's private key, or anything else from the host,
  ending up in a VM.
- **Checks that lie:** `check` or `host-check` reporting a pass while the
  thing it checks is broken.

Bugs in QEMU, KVM, libvirt, Squid or the guest kernel themselves belong with
those projects; please report it here too if glovebox's setup makes one
easier to exploit.

## Supported versions

Only the latest release gets fixes.
