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

## Security and privacy limits

- The build now rejects VLESS profiles without TLS/REALITY, VMess without TLS, Trojan without TLS, Shadowsocks profiles that do not use an approved AEAD cipher, and TLS profiles that request insecure certificate validation.
- For TLS profiles, Xray active tests use TLS 1.2–1.3 and normal certificate validation. REALITY is retained as configured by each server.
- The workflow verifies that an HTTPS request can pass through the proxy. This is a connectivity check, **not** a no-logs audit and not proof that a server operator is trustworthy.
- A VPN server operator can still observe the connecting user's public IP, connection times, traffic volume, and destination IPs/domains (depending on DNS and protocol behavior). VPN encryption does not make the operator blind to this metadata. HTTPS protects the contents of HTTPS sessions from the VPN operator, but cannot hide all metadata.
- Do not send passwords, private messages, or other sensitive data over sites/apps that do not use end-to-end encryption or HTTPS. Do not treat unknown free VPN servers as trusted for sensitive activity.
- This repository is public. The generated subscription contains server access credentials, so anyone who knows the raw URL can download and use them. This is inherent to distributing a public HAPP-compatible raw subscription; hiding the URL alone is not access control. The V2Hub source URL remains in the GitHub Actions secret and is not written into the workflow or generated file.
- The subscription aggregator does not collect end-user browsing history or user credentials. It does make test connections from GitHub Actions to candidate VPN servers and public HTTPS test endpoints when building the list.

These checks reduce exposure to plainly unencrypted or misconfigured profiles. They cannot prevent server operators from collecting connection metadata, guarantee no logging, or provide multi-hop anonymity. For sensitive use, the meaningful solution is a personally controlled server or a reputable VPN provider with independently audited privacy practices.

## DNS privacy in HAPP

The generated subscription also includes a HAPP routing profile that configures encrypted DNS-over-HTTPS (DoH): Cloudflare for remote/proxied DNS and Google for domestic DNS, with the DNS hostnames pinned to their documented IP addresses. HAPP imports and activates this profile from the subscription body. The profile is refreshed with the subscription every 6 hours.

DoH encrypts DNS requests between the HAPP client and the selected DNS resolver. It is **not** a second VPN tunnel and does not hide all connection metadata. The DNS resolver can still process the queries it receives; the VPN server can still observe connection metadata and destination IP addresses. This configuration does not make third-party VPN operators trustworthy or guarantee no logs. Users who prefer another DNS provider can change the routing profile in HAPP after import, if the app permits it for their subscription.
