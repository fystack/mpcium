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
. setup.sh
```

Detailed steps can be found in [SETUP.md](SETUP.md).

---

![All node ready](images/all-node-ready.png)

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
