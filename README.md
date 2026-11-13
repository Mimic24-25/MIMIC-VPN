# MIMIC-VPN

Combined HAPP-compatible subscription, generated from the three configured sources.

## One-time setup

1. Open **Settings → Secrets and variables → Actions** in this repository.
2. Select **New repository secret**.
3. Name: `V2HUB_SUB_URL`
4. Value: the full V2Hub subscription URL (keep it secret; do not put it in source code).
5. Save the secret.
6. Open **Actions → Update MIMIC VPN subscription → Run workflow**.

The workflow refreshes the list every 6 hours. It downloads Xray-core and actively tests supported VLESS, VMess, Trojan, and Shadowsocks links by starting a local VPN tunnel and making an HTTPS request through it. Only profiles that return a public exit IP are published. Unsupported protocols/transports and failed tunnels are excluded. If a source fails or no profile passes, the previous file is kept. This is a live test at build time; servers can stop working later.

## HAPP

After the first successful workflow run, use:

`https://raw.githubusercontent.com/Mimic24-25/MIMIC-VPN/main/mimic-vpn.txt`

In HAPP, add this as a subscription URL and set the subscription display name to **MIMIC VPN**. Server labels are generated in Russian from country flags/codes present in source tags. Servers without a recognizable country marker are omitted.

## Security

This repository is public. The generated subscription contains working connection credentials, so anyone with the raw URL can use the listed servers. Do not publish this repository if you do not accept that. The V2Hub source URL is stored as a GitHub Actions secret and is not written into the workflow or generated file.
