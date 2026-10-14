# Guarded transparent decoy redirection

This upgrade redirects new attacker connections on the original honeypot port
to the currently active adaptive decoy. Existing connections are not moved.

## Port mappings

| Original port | Active adaptive destination |
| --- | --- |
| SSH 2222 | SSH Admin Server 2224 |
| Web 5000 | Service Discovery 15000 |
| Database 5432 | Finance Database 15432 |
| IoT 8080 | Camera Management 18080 |
| Layered 2222/5000/5432 | 2226/16000/16432 |

Only sources inside `192.168.56.0/24` are eligible. A route is created only
after an attributable decoy activation and is removed when that decoy is no
longer active.

## Install on Ubuntu

```bash
cd ~/cyber-deception

tar -xzf /media/sf_VM-Shared/cyber-deception-transparent-redirect-v1.tar.gz \
  -C ~/cyber-deception

venv/bin/python -m py_compile routing/redirect_manager.py

command -v nft

sudo cp deploy/systemd/cyber-deception-redirect.service \
  /etc/systemd/system/cyber-deception-redirect.service

sudo systemctl daemon-reload
sudo systemctl enable --now cyber-deception-redirect.service
```

If `command -v nft` prints nothing, install the Ubuntu `nftables` package
before starting the service.

## Verify without changing routes

```bash
cd ~/cyber-deception

sudo venv/bin/python routing/redirect_manager.py --once --dry-run

systemctl status cyber-deception-redirect.service --no-pager -l

sudo nft list table inet deception_redirect
```

When Finance Database is active for `192.168.56.103`, the rule should show
source `192.168.56.103`, destination port `5432`, and redirect port `15432`.

## Demonstrate

After a database attack activates Finance Database, run another request from
Kali against the original port `5432`. The new connection will reach the
Finance Database decoy automatically. The attacker never needs to know port
`15432`.

## Disable and remove all redirect rules

```bash
sudo systemctl disable --now cyber-deception-redirect.service
sudo nft delete table inet deception_redirect 2>/dev/null || true
```
