# ASMove VPN

**Replace your VPN server without replacing everyone's subscription URL.**

[Русский](README.md) · [Getting started](docs/QUICKSTART.md) · [Discussions](https://github.com/almuleev/asmove-vpn/discussions)

Self-hosted VPN monitoring and recovery for a two-server setup. A Russian controller
hosts accounts and subscriptions, tests real HTTPS traffic through Xray, and can
replace a failing foreign VDSina VPS. The VPN endpoint runs 3x-ui/Xray with VLESS
XHTTP/TLS. This is a management system, not a VPN service subscription.

**Preview:** mock-based local tests pass; clean VPS deployment, real automatic
replacement, certificate renewal and end-user clients have not been tested for
this release. Availability from one observer does not represent every network.

## Features

- A user portal, admin controls, account expiry and revocation.
- Stable signed subscriptions, preserved UUIDs and account credentials.
- Two independent HTTPS destinations and direct observer controls.
- Manual replacement or owner-enabled automatic recovery.
- Configurable failure trigger, consecutive failures, duration, cooldown and daily automatic limit.
- Verified recovery archives, exact service identity and intent journals.
- Unknown order responses are reconciled without blindly repeating POST.
- Optional Telegram/ntfy notification queues.

## Start

Rent two clean Ubuntu 24.04 amd64 VPS with public IPv4 and root SSH. The foreign
VPS must use a fixed **VDSina.com USD 0.07/day** plan; create the first VPS manually.
On the Russian controller:

```bash
sudo apt-get update
sudo apt-get install -y git python3 ca-certificates
git clone https://github.com/almuleev/asmove-vpn.git /opt/asmove-src
cd /opt/asmove-src
sudo python3 deploy/setup.py
```

The interactive wizard is currently in Russian. It requests the EU address,
provider-console SSH fingerprint and API token, discovers account-specific IDs,
installs components and verifies VPN traffic. It never rents the initial VPS.
Do not bootstrap an existing installation. See the [beginner guide](docs/QUICKSTART.md).

Automatic recovery is off until explicitly enabled with downtime consent. Defaults:
3 failed cycles spanning at least 180 seconds, 1-hour cooldown and at most 2 automatic
authorizations per rolling 24 hours. Choose failed VPN HTTPS checks alone or require
TCP failure too. Manual replacements retain exact-IP and downtime confirmation.

**Delete first means downtime:** the old VPS is deleted before a new one is ordered.
Provisioning, funding, capacity or API failures can extend the outage indefinitely.
A fresh verified archive is mandatory. A prolonged EU outage may prevent recovery
without manual intervention. Subscription URLs survive EU replacement only while
the controller origin and signing key remain unchanged. Direct URIs must be reimported.

EU cost: USD 0.07/day ($2.10/30 days), checked 2026-11-24 at
[VDSina](https://www.vdsina.com/pricing/standard). Add controller hosting, external
backup storage, traffic overages and applicable fees. No universal bypass guarantee.
Root SSH and provider token are powerful credentials; read the [operations guide](docs/OPERATIONS.md).

## Help and contribute

**Have a question? Write to me — I’m the author of ASMove VPN, and I’ll reply.**
Questions about installation, setup and ideas are always welcome. No Linux
experience is required. [Contact me on GitHub Discussions](https://github.com/almuleev/asmove-vpn/discussions/new).
Discussions are public: please leave out credentials and subscription URLs.

[Ask a question](https://github.com/almuleev/asmove-vpn/discussions),
[report a bug](https://github.com/almuleev/asmove-vpn/issues/new/choose), or
[contribute](CONTRIBUTING.md). Clean-install reports and clearer beginner docs are
particularly welcome. Never post tokens, databases or subscription URLs.
If this project helps, consider giving it a star.

[Validation](docs/VALIDATION.md) · [Roadmap](docs/ROADMAP.md) · [Security](SECURITY.md)

MIT for project code; external components retain their [own licenses](NOTICE.md).
