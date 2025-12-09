# Mpcium Installation Guide

## Prerequisites

Before starting, ensure you have:

- **Go** 1.23+ installed: [Install Go here](https://go.dev/doc/install)
- **NATS** server running
- **Consul** server running

---

## Clone and Install Mpcium

### Clone the Repository

```bash
git clone https://github.com/fystack/mpcium.git
cd mpcium
```

### Build the Project

With Make:

```bash
make
```

Or with Go:

```bash
go install ./cmd/mpcium
go install ./cmd/mpcium-cli
```

### Available Commands

- `mpcium`: Start an MPCium node
- `mpcium-cli`: CLI utility for peer, identity, and initiator configuration

---

### Set everything up in one go

```bash
chmod +x ./setup.sh
./setup.sh
```

Detailed steps can be found in [SETUP.md](SETUP.md).

---

![All node ready](images/all-node-ready.png)

---

## chain_code setup (REQUIRED)

### What is chain_code?

The `chain_code` is a cryptographic parameter used for Hierarchical Deterministic (HD) wallet functionality. It enables mpcium to derive child keys from a parent key, allowing you to generate multiple wallet addresses from a single master key.

**Important Requirements:**
- **All nodes in your MPC cluster MUST use the identical chain_code value**
- Must be a 32-byte value represented as a 64-character hexadecimal string
- Should be generated once and stored securely
- Without a valid chain_code, mpcium nodes will fail to start

### How to generate and configure

Generate one 32-byte hex chain code and set it in all node configurations:

```bash
# Navigate to your mpcium directory
cd /path/to/mpcium

# Generate a random 32-byte chain code and save it
CC=$(openssl rand -hex 32) && echo "$CC" > .chain_code

# Apply to main config
sed -i -E "s|^([[:space:]]*chain_code:).*|\1 \"$CC\"|" config.yaml

# Apply to all node configs
for n in node0 node1 node2; do
  sed -i -E "s|^([[:space:]]*chain_code:).*|\1 \"$CC\"|" "$n/config.yaml"
done

# Verify it was set correctly
echo "Chain code configured: $CC"
```

**Example config.yaml entry:**
```yaml
chain_code: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
```

Start nodes normally:

```bash
cd node0 && mpcium start -n node0
```

Repeat for `node1` and `node2`. The value must be exactly 64 hex chars (32 bytes).

---

## Production Deployment (High Security)

1. Use production-grade **NATS** and **Consul** clusters.
2. Enable **TLS certificates** on all endpoints.
3. Encrypt all keys:
   ```bash
   mpcium-cli generate-initiator --encrypt
   mpcium-cli generate-identity --node node0 --encrypt
   ```
4. Use `--prompt-credentials` to securely input Badger passwords (avoid hardcoding in `config.yaml`).

---

## Appendix

### Decrypt initiator private key with age

```
age --decrypt -o event_initiator.key event_initiator.key.age
```
