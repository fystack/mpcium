# Mpcium Production Deployment Guide

⚠️ **PRODUCTION DEPLOYMENT ONLY**

This directory contains deployment scripts and configurations for **production deployment** of Mpcium MPC (Multi-Party Computation) nodes using systemd.

**For local development and testing**, please refer to [INSTALLATION.md](../../INSTALLATION.md) instead.

## Overview

Mpcium is a distributed threshold cryptographic system that requires multiple nodes to collaborate for secure operations. This deployment guide covers setting up a **secure, production-ready** MPC cluster with proper security hardening, systemd integration, and operational best practices.

## Prerequisites

### Infrastructure Requirements

- **Minimum 3 nodes** (cloud-based, ARM architecture preferred)
- **Linux** distribution
- **Network connectivity** between all nodes
- **External services**: NATS message broker, Consul service discovery

### Software Dependencies

- **Go 1.27.1** on all nodes
- **Git** for source code management
- **jq** (used by `setup-config.sh verify` to check identity files; without it those checks are silently skipped)
- **systemd v250+** (required for `systemd-creds`)
- **NATS server** with TLS (mTLS client certificates)
- **Consul** for service discovery (HTTPS + ACL token)

### Deployment

All commands assume you are operating as `root`. If you are SSH'd in as a sudo user, use full paths (e.g. `/root/...`) rather than `~`.

Steps marked **(designated node)** are run **once**, on a single node (e.g. `node0`). Steps marked **(all nodes)** are run on every node.

#### Step 1: Install Go (all nodes)

Download Go 1.27.1 (auto-detects `amd64` / `arm64`):

```bash
GO_VERSION=go1.27.1
ARCH=$(dpkg --print-architecture)   # amd64 or arm64
wget "https://go.dev/dl/${GO_VERSION}.linux-${ARCH}.tar.gz"

sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "${GO_VERSION}.linux-${ARCH}.tar.gz"
```

Make Go available system-wide — for root, `sudo`, and every login shell:

```bash
# GOROOT + PATH for all users (including root) in login shells
sudo tee /etc/profile.d/go.sh >/dev/null <<'EOF'
export GOROOT=/usr/local/go
export PATH=$PATH:$GOROOT/bin
EOF
source /etc/profile.d/go.sh

# sudo resets PATH to secure_path, which includes /usr/local/bin
sudo ln -sf -t /usr/local/bin /usr/local/go/bin/go /usr/local/go/bin/gofmt

go version && sudo go version && go env GOROOT   # GOROOT should print /usr/local/go
```

#### Step 2: Install Mpcium and Prepare the Host (all nodes)

```bash
# System packages
sudo apt-get install -y git jq
systemctl --version | head -1   # must be 250 or newer

# Clone and install binaries into /usr/local/bin
cd /root
git clone https://github.com/fystack/mpcium.git
cd /root/mpcium
sudo -E make install

# Create system user and directories
sudo useradd -r -s /bin/false -d /opt/mpcium -c "Mpcium MPC Node" mpcium
sudo mkdir -p /opt/mpcium/identity /etc/mpcium/certs
```

#### Step 3: Generate Peer Configuration (designated node)

`mpcium-cli` reads and writes `peers.json` and `identity/` relative to the **current directory**, so always run it from `/opt/mpcium`:

```bash
cd /opt/mpcium
mpcium-cli generate-peers -n 3
```

Copy `peers.json` to the other nodes **now** — `generate-identity` (Step 9) fails with `peers file peers.json does not exist` if it is missing:

```bash
scp /opt/mpcium/peers.json root@<node1-ip>:/opt/mpcium/
scp /opt/mpcium/peers.json root@<node2-ip>:/opt/mpcium/
```

#### Step 4: Create config.yaml (all nodes)

```bash
cp /root/mpcium/config.prod.yaml.template /etc/mpcium/config.yaml
sudo chown root:mpcium /etc/mpcium/config.yaml
sudo chmod 640 /etc/mpcium/config.yaml
```

Edit `/etc/mpcium/config.yaml` and fill in the fields below. `event_initiator_pubkey` and `chain_code` are filled in Steps 5 and 8.

```yaml
nats:
  url: tls://<nats-host>:4222 # must be tls:// in production
  username: "" # leave empty when NATS authenticates via mTLS
  password: ""
  tls:
    client_cert: "/etc/mpcium/certs/client-cert.pem"
    client_key: "/etc/mpcium/certs/client-key.pem"
    ca_cert: "/etc/mpcium/certs/rootCA.pem"

consul:
  address: https://<consul-host>:8500
  token: "<consul ACL token>"
  ca_cert: "/etc/mpcium/certs/consul-rootCA.pem" # only if Consul is set up with TLS (https://); not in the template

mpc_threshold: 1
environment: production
```

| Field                    | Notes                                                                                   |
| ------------------------ | --------------------------------------------------------------------------------------- |
| `environment`            | Must be `production`. Remove the template's trailing `# ...` comment on this line — `setup-config.sh` does not strip it and will otherwise treat the node as development and skip the TLS checks |
| `nats.url`               | `tls://...` in production                                                               |
| `nats.tls.*`             | Paths to the certificates from Step 6                                                   |
| `consul.address`         | `https://...` in production                                                             |
| `consul.token`           | Consul ACL token (only sent when `environment: production`)                             |
| `consul.ca_cert`         | **Only required if Consul is set up with TLS** (`https://` address signed by a private CA). Omit for plain `http://` Consul. Only used when `environment: production` |
| `mpc_threshold`          | `t` in the t-of-n threshold                                                             |
| `chain_code`             | 64 hex chars, **identical on all nodes** (Step 5)                                      |
| `event_initiator_pubkey` | Public key from Step 8, **identical on all nodes**                                      |
| `badger_password`        | Do **not** set — supplied via systemd credentials (Step 11)                             |

#### Step 5: Set chain_code (designated node, then copy)

`chain_code` is a 32-byte value used for HD wallet key derivation. Generate it once and use the **exact same value** on every node — a mismatch prevents the cluster from working correctly.

```bash
CC=$(openssl rand -hex 32)
sed -i -E "s|^([[:space:]]*chain_code:).*|\1 \"$CC\"|" /etc/mpcium/config.yaml
echo "$CC"
```

Set the same `chain_code` value in `/etc/mpcium/config.yaml` on the other nodes, and back it up in your password manager.

#### Step 6: Install TLS Certificates (all nodes)

Copy the NATS client certificates from your infrastructure/PKI host into `/etc/mpcium/certs/`. The Consul root CA is **only required if Consul is set up with TLS** — skip the last line otherwise:

```bash
scp <pki-dir>/nats/client-cert.pem root@<node-ip>:/etc/mpcium/certs/
scp <pki-dir>/nats/client-key.pem  root@<node-ip>:/etc/mpcium/certs/
scp <pki-dir>/nats/rootCA.pem      root@<node-ip>:/etc/mpcium/certs/
# Only if Consul is set up with TLS
scp <pki-dir>/consul/rootCA.pem    root@<node-ip>:/etc/mpcium/certs/consul-rootCA.pem
```

The service runs as `mpcium`, so these files must be group-readable. `setup-config.sh` does **not** fix permissions on the `certs/` directory:

```bash
sudo chown -R root:mpcium /etc/mpcium/certs
sudo chmod 750 /etc/mpcium/certs
sudo chmod 640 /etc/mpcium/certs/*.pem

# Confirm the service user can read them
for f in /etc/mpcium/certs/*.pem; do sudo -u mpcium test -r "$f" && echo "ok  $f" || echo "FAIL $f"; done
```

#### Step 7: Register Peers to Consul (designated node)

Run from the directory containing `peers.json`. `--environment production` is **required** — without it the Consul token and `consul.ca_cert` are ignored:

```bash
cd /opt/mpcium
mpcium-cli register-peers --config /etc/mpcium/config.yaml --environment production
```

#### Step 8: Generate Event Initiator Key (designated node)

```bash
cd /root
mpcium-cli generate-initiator --encrypt
```

This writes `event_initiator.identity.json` (public) and `event_initiator.key.age` (encrypted private key) to the current directory.

- Copy the `public_key` value from `event_initiator.identity.json` into `event_initiator_pubkey` in `/etc/mpcium/config.yaml` on **all nodes** — the value must be identical everywhere.
- The private key is used by the application that initiates MPC operations, not by the MPC nodes. Move `event_initiator.key.age` off the node to secure storage and keep its passphrase in your password manager.

#### Step 9: Generate Node Identity (each node, on its own server)

Each node generates its own identity locally so the private key never leaves the server. Run from `/opt/mpcium` (output goes to `./identity/`, and `./peers.json` must exist):

```bash
cd /opt/mpcium
mpcium-cli generate-identity --node node0 --encrypt   # node1 on node1, node2 on node2
```

This creates `identity/node0_identity.json` (public) and `identity/node0_private.key.age` (encrypted private key). Save the passphrase in your password manager (e.g. `mpcium-node0-identity-passphrase`) — it is needed in Step 11.

#### Step 10: Distribute Public Identity Files (all nodes)

Each node needs the `*_identity.json` of **every** node, but only **its own** private key:

```bash
# e.g. from node0
scp /opt/mpcium/identity/node0_identity.json root@<node1-ip>:/opt/mpcium/identity/
scp /opt/mpcium/identity/node0_identity.json root@<node2-ip>:/opt/mpcium/identity/
```

⚠️ Never copy `*_private.key` / `*_private.key.age` to other nodes.

Before continuing, double-check on every node that:

- `/opt/mpcium/peers.json` exists
- `/opt/mpcium/identity/` has all `nodeX_identity.json` files plus this node's own private key
- `chain_code` and `event_initiator_pubkey` in `/etc/mpcium/config.yaml` match the other nodes

#### Step 11: Configure Credentials (all nodes)

```bash
cd /root/mpcium/deployments/systemd
./setup-mpcium-cred.sh
```

The script prompts, in order, for:

1. **BadgerDB password** — must be exactly 16, 24 or 32 characters; use a different one per node. Generate it in your password manager first (e.g. `mpcium-node0-database-password`) — if lost, the database cannot be recovered.
2. **"Did you use `generate-identity --encrypt`?"** — answer **`y`** if you followed Step 9. Answering `n` skips the identity credential and the node will fail to decrypt its private key.
3. **Identity passphrase** — the passphrase from Step 9.

It writes `/etc/mpcium/mpcium-db-password.cred` and `/etc/mpcium/mpcium-identity-password.cred`, encrypted with the systemd host secret.

> Note: this script resets `/etc/mpcium` to `root:root 700`, which the `mpcium` user cannot read. Step 12 restores it to `root:mpcium 750` — always run Step 12 afterwards.

#### Step 12: Deploy Service (all nodes)

```bash
sudo ./setup-config.sh
```

Enter this node's name when prompted (e.g. `node0`). It must match a key in `peers.json` exactly — the script does not validate it.

The script fixes ownership of `/opt/mpcium` and `/etc/mpcium`, installs `/etc/systemd/system/mpcium.service` with the encrypted credentials, writes `/opt/mpcium/.env`, and **enables** the service. It does **not** start it.

Check the installed unit has no leftover placeholders (if it does, the matching `.cred` file was missing — re-run Step 11, then `sudo ./setup-config.sh update-creds`):

```bash
grep -c BASE64_BLOB_DATA /etc/systemd/system/mpcium.service   # must print 0
```

Start the service:

```bash
sudo systemctl start mpcium
```

#### Step 13: Verify Deployment (all nodes)

```bash
sudo systemctl status mpcium
journalctl -f -u mpcium
```

Look for: service `active (running)`, the node connecting to NATS and Consul, and discovering its peers — without repeated TLS or identity/signature errors.

## Directory Structure

After deployment, the following directory structure is created:

```
/opt/mpcium/           # Application home (mpcium:mpcium, 750)
├── db/                # BadgerDB storage (auto-created)
├── backups/           # Encrypted backups (auto-created)
├── identity/          # Node identity files
│   ├── node0_identity.json
│   ├── node1_identity.json
│   ├── node2_identity.json
│   └── node{X}_private.key.age  # Current node's encrypted private key only
├── peers.json         # Peer registry
└── .env               # MPCIUM_NODE_NAME (root:mpcium, 640)

/etc/mpcium/                       # Configuration (root:mpcium, 750)
├── config.yaml                    # Main configuration (root:mpcium, 640)
├── mpcium-db-password.cred        # Encrypted BadgerDB password (root:root, 600)
├── mpcium-identity-password.cred  # Encrypted identity passphrase (root:root, 600)
└── certs/                         # TLS certificates (root:mpcium, 750; files 640)
    ├── client-cert.pem
    ├── client-key.pem
    ├── rootCA.pem
    └── consul-rootCA.pem          # only if Consul is set up with TLS
```

### Identity Directory Examples

**Node 0 (unencrypted private key):**
```
/opt/mpcium/identity/
├── node0_identity.json
├── node0_private.key      # This node's private key
├── node1_identity.json
└── node2_identity.json
```
*Generated with:* `mpcium-cli generate-identity --node node0 --config /etc/mpcium/config.yaml`

**Node 1 (encrypted private key):**
```
/opt/mpcium/identity/
├── node0_identity.json
├── node1_identity.json
├── node1_private.key.age  # This node's encrypted private key
└── node2_identity.json
```
*Generated with:* `mpcium-cli generate-identity --node node1 --config /etc/mpcium/config.yaml --encrypt`

## Security Considerations

### File Permissions

- Configuration files are **root-controlled** to prevent tampering
- Application data is **service-owned** for runtime access
- Database encryption is **mandatory** in production

### Network Security

- All inter-node communication uses **Ed25519 signatures**
- Message payloads encrypted with **ECDH key exchange**
- TLS required for NATS connections

### Systemd Security

The service runs with enhanced security:

- **Non-privileged user** (`mpcium`)
- **Read-only** configuration directory
- **Private temp** directory
- **System call filtering**
- **Capability restrictions**

## Monitoring and Maintenance

### Service Management

```bash
# Service status
sudo systemctl status mpcium

# Start/stop/restart
sudo systemctl start mpcium
sudo systemctl stop mpcium
sudo systemctl restart mpcium

# View logs
journalctl -u mpcium
journalctl -f -u mpcium  # Follow logs
```

### Health Checks

The deployment includes Consul-based health monitoring. Check cluster health via your Consul UI.

### Backup Management

BadgerDB automatically creates encrypted backups in `/opt/mpcium/backups/`. Ensure regular backup of:

- Database encryption password
- Node identity files
- Configuration files

## Troubleshooting

### Common Issues

**Service won't start:**

```bash
# Check service logs
journalctl -u mpcium --no-pager

# Verify configuration
sudo ./setup-config.sh verify
```

**Network connectivity:**

- Verify NATS and Consul connectivity
- Check firewall rules between nodes
- Validate TLS certificates

**Known `setup-config.sh` quirks:**

- `verify` / `validate-only` stop at the **first** failed check without printing a summary — fix that item and re-run until it passes.
- "Development environment - TLS validation skipped" on a production node — remove the trailing `# ...` comment from the `environment: production` line in `config.yaml`.
- "CA certificate file not found" with two paths printed — harmless when `consul.ca_cert` is set; the NATS `ca_cert` lookup also matches the Consul one. Confirm both files exist manually.
- "MPCIUM_ENVIRONMENT: unbound variable" — `/etc/mpcium/config.yaml` does not exist yet (Step 4).
- `TLS handshake` / `permission denied` on certs at runtime — the `mpcium` user cannot read files in `/etc/mpcium/certs` (see Step 6).

### Log Analysis

Service logs are available via systemd journal:

```bash
# Recent logs
journalctl -u mpcium -n 100

# Logs since specific time
journalctl -u mpcium --since "1 hour ago"

# Filter by log level
journalctl -u mpcium -p err
```
