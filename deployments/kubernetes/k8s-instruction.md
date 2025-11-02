# Kubernetes Deployment Guide for Mpcium

This guide provides comprehensive instructions for deploying Mpcium MPC (Multi-Party Computation) nodes on Kubernetes. Mpcium is a distributed threshold cryptographic system that requires multiple nodes to collaborate for secure operations.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Architecture](#architecture)
4. [Pre-Deployment Setup](#pre-deployment-setup)
5. [Kubernetes Configuration](#kubernetes-configuration)
6. [Post-Deployment Verification](#post-deployment-verification)
7. [Monitoring and Operations](#monitoring-and-operations)
8. [Security Considerations](#security-considerations)
9. [Troubleshooting](#troubleshooting)

## Overview

Mpcium uses a t-of-n threshold signature scheme where:

- **n** = total MPC nodes (minimum 3 recommended)
- **t** = minimum nodes required for operations (t ≥ ⌊n/2⌋ + 1)
- Private keys are never fully reconstructed
- Only t nodes needed for signing operations

Each node requires:

- Unique identity (Ed25519 keypair)
- Encrypted BadgerDB storage
- Connection to NATS message broker
- Connection to Consul for service discovery

## Prerequisites

### Infrastructure Requirements

- **Kubernetes cluster** (v1.24+)
- **kubectl** configured to access your cluster
- **Minimum 3 nodes** for production deployment
- **Persistent storage** provisioner (for BadgerDB data)
- **LoadBalancer** or Ingress controller (optional, for external access)

### External Services

You need the following services accessible from your Kubernetes cluster:

- **NATS server** with JetStream enabled

  - URL: `nats://nats-server:4222`
  - Optional: TLS with client certificates
  - Optional: Username/password authentication

- **Consul** for service discovery
  - URL: `http://consul:8500`
  - Used for peer registry and health checks

Both services can be deployed in the same Kubernetes cluster or externally. Example manifests for deploying NATS and Consul are provided in this guide.

### Required Software (for pre-deployment setup)

- **Go 1.25+** (on your local machine for generating identities)
- **mpcium-cli** binary (build from source or download release)
- **age** (for encrypted identity storage) - https://github.com/FiloSottile/age

## Architecture

### Deployment Model

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                        │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   node0-pod  │  │   node1-pod  │  │   node2-pod  │     │
│  │              │  │              │  │              │     │
│  │ - mpcium     │  │ - mpcium     │  │ - mpcium     │     │
│  │ - identity   │  │ - identity   │  │ - identity   │     │
│  │ - badgerdb   │  │ - badgerdb   │  │ - badgerdb   │     │
│  │              │  │              │  │              │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            │                                 │
│         ┌──────────────────┴──────────────────┐             │
│         │                                      │             │
│    ┌────▼─────┐                        ┌──────▼────┐       │
│    │   NATS   │                        │  Consul   │       │
│    │          │                        │           │       │
│    │ JetStream│                        │  KV Store │       │
│    └──────────┘                        └───────────┘       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Pod Structure

Each mpcium pod contains:

- **Container**: `mpcium` - Main application
- **Volumes**:
  - `config` - Configuration file (ConfigMap)
  - `identity` - Node identity files (Secret)
  - `secrets` - Database and identity passwords (Secret)
  - `data` - Persistent storage for BadgerDB and backups (PVC)

## Pre-Deployment Setup

These steps are performed **offline** or on a secure workstation before deploying to Kubernetes.

### Step 1: Build or Download mpcium-cli

```bash
# Clone the repository
git clone https://github.com/fystack/mpcium.git
cd mpcium

# Build the CLI tool
go install ./cmd/mpcium-cli

# Verify installation
mpcium-cli --version
```

### Step 2: Generate Peer Configuration

Generate the peer configuration file that defines all nodes in your MPC cluster:

```bash
# Generate peers.json for 3 nodes
mpcium-cli generate-peers -n 3

# This creates peers.json with structure:
# [
#   {"id": "node0_<random>", "name": "node0"},
#   {"id": "node1_<random>", "name": "node1"},
#   {"id": "node2_<random>", "name": "node2"}
# ]
```

**Important**: Keep this `peers.json` file secure. You'll need it for generating identities and registering peers.

### Step 3: Generate Event Initiator Identity

The event initiator is authorized to trigger MPC operations (keygen, signing, resharing):

```bash
# Generate encrypted initiator identity
mpcium-cli generate-initiator --encrypt

# Output files:
# - initiator_identity.json (public key)
# - initiator_private.key.age (encrypted private key)
```

**Save the decryption password securely** - you'll need it for applications that initiate MPC operations.

Extract the public key:

```bash
cat initiator_identity.json | jq -r '.public_key'
# Example output: 6cdddd50b0e550f285c5e998cb9c9c88224680cd5922307b9c2e3c395f78dabc
```

This public key will be used in the `config.yaml` as `event_initiator_pubkey`.

### Step 4: Generate Node Identities

Generate encrypted identity for each node:

```bash
# For node0
mpcium-cli generate-identity \
  --node node0 \
  --peers ./peers.json \
  --output-dir ./identity/node0 \
  --encrypt

# For node1
mpcium-cli generate-identity \
  --node node1 \
  --peers ./peers.json \
  --output-dir ./identity/node1 \
  --encrypt

# For node2
mpcium-cli generate-identity \
  --node node2 \
  --peers ./peers.json \
  --output-dir ./identity/node2 \
  --encrypt
```

**Save the decryption passwords securely** for each node.

Each identity directory contains:

```
identity/node0/
├── node0_identity.json
├── node0_private.key.age  (encrypted private key)
├── node1_identity.json
└── node2_identity.json
```

### Step 5: Prepare Secrets

You'll need the following secrets for each node:

1. **BadgerDB password** - For encrypting the database
2. **Identity decryption password** - For decrypting the `.age` private key
3. **NATS credentials** (if using authentication)
4. **TLS certificates** (if using TLS)

**Generate a strong BadgerDB password**:

```bash
# Generate a random 32-character password
openssl rand -base64 32
```

Use the same password for all nodes or different passwords per node (your choice).

## Kubernetes Configuration

### Step 1: Create Namespace

Create a dedicated namespace for mpcium:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: mpcium
```

### Step 2: Deploy Supporting Services

Deploy NATS and Consul if not using external services. For production, use the official Helm charts:

- **NATS**: https://github.com/nats-io/k8s
- **Consul**: https://github.com/hashicorp/consul-k8s

### Step 3: Create Secrets

Create secrets for each node containing identity files and passwords:

Command to generate storng Badger password:

```
< /dev/urandom tr -dc 'A-Za-z0-9!@#$^&\*()-\_=+[]{}|;:,.<>?/~' | head -c 32; echo
```

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mpcium-secrets-node0
  namespace: mpcium
type: Opaque
stringData:
  mpcium-db-password.cred: "<badger_password>"
  mpcium-identity-password.cred: "<identity_decrypt_password>"
```

```bash
# Create identity secret from files
kubectl create secret generic mpcium-identity-node0 \
  -n mpcium \
  --from-file=identity/node0/node0_identity.json \
  --from-file=identity/node0/node0_private.key.age \
  --from-file=identity/node0/node1_identity.json \
  --from-file=identity/node0/node2_identity.json
```

Repeat for node1 and node2.

Create a ConfigMap containing the shared `peers.json` file (required by the distroless image at runtime):

```bash
kubectl create configmap mpcium-peers \
  -n mpcium \
  --from-file=peers.json
```

### Step 4: Create ConfigMap

Create a ConfigMap with the shared configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: mpcium-config
  namespace: mpcium
data:
  config.yaml: |
    environment: production
    db_path: /app/data/db
    backup_dir: /app/data/backups
    consul:
      address: consul:8500
    nats:
      url: nats://nats:4222
    mpc_threshold: 2
    event_initiator_pubkey: "<your-initiator-public-key>"
    event_initiator_algorithm: "ed25519"
    backup_enabled: false
    backup_period_seconds: 300
```

### Step 5: Register Peers in Consul

Before deploying pods, register the peer configuration. The `register-peers` command requires a config file with Consul connection details:

```bash
# Port-forward to Consul
kubectl port-forward -n mpcium svc/consul 8500:8500 &

# Create a temporary config file for registration
cat > register-config.yaml <<EOF
consul:
  address: localhost:8500
EOF

# Register peers
mpcium-cli register-peers \
  --peers ./peers.json \
  --config ./register-config.yaml \
  --environment production

# Or set ENVIRONMENT variable
export ENVIRONMENT=production
mpcium-cli register-peers \
  --peers ./peers.json \
  --config ./register-config.yaml
```

### Step 6: Create Persistent Volume Claims

Each node needs persistent storage:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: mpcium-data-node0
  namespace: mpcium
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
```

This stores:

- BadgerDB data
- Backups (`/app/data/backups`)

Repeat for node1 and node2.

### Step 7: Deploy mpcium Nodes

Create a Deployment for each node:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mpcium-node0
  namespace: mpcium
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: mpcium-node0
  template:
    metadata:
      labels:
        app: mpcium-node0
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
      containers:
        - name: mpcium
          image: fystacklabs/mpcium-prod:1.0.0
          args:
            - "start"
            - "--name=node0"
            - "--config=/config.yaml"
            - "--password-file=/app/secrets/mpcium-db-password.cred"
            - "--identity-password-file=/app/secrets/mpcium-identity-password.cred"
            - "--decrypt-private-key"
          volumeMounts:
            - name: config
              mountPath: /config.yaml
              subPath: config.yaml
              readOnly: true
            - name: peers
              mountPath: /app/peers.json
              subPath: peers.json
              readOnly: true
            - name: identity
              mountPath: /app/identity
              readOnly: true
            - name: secrets
              mountPath: /app/secrets
              readOnly: true
            - name: data
              mountPath: /app/data
            - name: tmp
              mountPath: /tmp
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
      volumes:
        - name: config
          configMap:
            name: mpcium-config
        - name: peers
          configMap:
            name: mpcium-peers
        - name: identity
          secret:
            secretName: mpcium-identity-node0
            defaultMode: 0400
        - name: secrets
          secret:
            secretName: mpcium-secrets-node0
            defaultMode: 0400
        - name: data
          persistentVolumeClaim:
            claimName: mpcium-data-node0
        - name: tmp
          emptyDir: {}
```

Duplicate this manifest for `node1`, `node2`, etc., updating:

- Deployment/resource names (`mpcium-nodeX`)
- CLI flag `--name=nodeX`
- Secret and PVC references (`mpcium-identity-nodeX`, `mpcium-secrets-nodeX`, `mpcium-data-nodeX`)
- Labels (`app: mpcium-nodeX`) to keep pods discoverable by node name

Deploy all nodes:

```bash
kubectl apply -f node0-deployment.yaml
kubectl apply -f node1-deployment.yaml
kubectl apply -f node2-deployment.yaml
```

## Post-Deployment Verification

### Step 1: Check Pod Status

```bash
# Check all pods are running
kubectl get pods -n mpcium

# Expected output:
# NAME                             READY   STATUS    RESTARTS   AGE
# mpcium-node0-xxxxxxxxxx-xxxxx    1/1     Running   0          2m
# mpcium-node1-xxxxxxxxxx-xxxxx    1/1     Running   0          2m
# mpcium-node2-xxxxxxxxxx-xxxxx    1/1     Running   0          2m
```

### Step 2: Check Logs

```bash
# Check node0 logs
kubectl logs -n mpcium -l app=mpcium-node0 --tail=50

# Look for:
# - "MPCIUM v0.3.3" banner
# - "Connected to badger kv store"
# - "Loaded peers from consul"
# - "[READY] Node is ready"
# - "Starting consumers"
```

### Step 3: Verify Consul Registration

```bash
# Port-forward to Consul UI
kubectl port-forward -n mpcium svc/consul 8500:8500

# Open http://localhost:8500 in browser
# Navigate to Key/Value and check mpc_peers/
```

### Step 4: Verify NATS Connection

```bash
# Check NATS logs
kubectl logs -n mpcium -l app=nats

# Check mpcium logs for NATS connection
kubectl logs -n mpcium -l app=mpcium-node0 | grep -i nats
```

### Step 5: Test MPC Operations

Use the mpcium client library to test operations:

```bash
# Port-forward to NATS (if needed for external client)
kubectl port-forward -n mpcium svc/nats 4222:4222 &

# Use mpcium-client-ts or mpcium pkg/client to:
# 1. Generate a wallet (keygen operation)
# 2. Sign a message
# 3. Test key resharing
```

See the client library documentation for examples.

## Monitoring and Operations

### Logging

All logs are sent to stdout and collected by Kubernetes:

```bash
# Follow logs for a specific node
kubectl logs -n mpcium -l app=mpcium-node0 -f

# Get logs from all mpcium pods
kubectl logs -n mpcium -l component=mpcium --tail=100

# Filter by log level
kubectl logs -n mpcium -l app=mpcium-node0 | grep ERROR
```

### Metrics (Future Enhancement)

Consider integrating:

- **Prometheus** for metrics collection
- **Grafana** for visualization
- Custom metrics from mpcium application

### Health Checks

**Note**: The mpcium container uses a distroless base image without a shell, so traditional exec probes won't work. Consider one of these approaches:

1. **Add a health endpoint** to the mpcium application (recommended for production)
2. **Use TCP socket probes** if mpcium exposes a port
3. **Remove probes** and rely on restart policy (simple but less robust)

The built-in health server (disabled by default) exposes a single HTTP endpoint at `/health` that reports both liveness and readiness. Enable it by setting in your `config.yaml`:

```yaml
healthcheck:
  enabled: true
  address: "0.0.0.0:8080" # default
```

Sample probes once enabled:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 15
  periodSeconds: 5
```

### Backup Management

BadgerDB backups are automatically created in `/app/data/backups/` on the PVC:

```bash
# List backups
kubectl exec -n mpcium -it <pod-name> -- ls -lh /app/data/backups/

# Copy backup to local machine
kubectl cp mpcium/<pod-name>:/app/data/backups/backup-<timestamp>.bak ./backup.bak

# Restore from backup (if needed)
# Stop the pod, replace data, restart
```

**Recommendation**: Set up automated backup jobs using Kubernetes CronJobs to copy backups to cloud storage (S3, GCS, etc.).

### Scaling and Updates

**Adding new nodes**:

1. Update `peers.json` with new node
2. Generate identity for new node
3. Re-register peers in Consul
4. Create secrets and deployment for new node
5. Update `mpc_threshold` if needed

**Updating mpcium**:

1. Build new Docker image with updated version
2. Update image tag in deployments
3. Perform rolling update:

```bash
kubectl set image deployment/mpcium-node0 \
  -n mpcium \
  mpcium=fystack/mpcium:v0.3.4

# Repeat for other nodes
```

**Note**: For critical updates affecting consensus, consider:

- Coordinated maintenance window
- Key resharing to new node versions if protocol changes

## Security Considerations

### Network Security

- **Namespace isolation**: Run mpcium in dedicated namespace
- **Network policies**: Restrict traffic to only required services
- **TLS encryption**: Enable TLS for NATS connections
- **Message signing**: All inter-node messages are signed with Ed25519

Example NetworkPolicy:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mpcium-network-policy
  namespace: mpcium
spec:
  podSelector:
    matchLabels:
      component: mpcium
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              component: mpcium
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: nats
      ports:
        - protocol: TCP
          port: 4222
    - to:
        - podSelector:
            matchLabels:
              app: consul
      ports:
        - protocol: TCP
          port: 8500
```

### Pod Security

The deployments include security contexts:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

### Secret Management

**Production recommendations**:

1. **Use External Secrets Operator** or **Sealed Secrets**
2. **Encrypt secrets at rest** in etcd
3. **Use RBAC** to restrict access to secrets
4. **Rotate passwords** regularly
5. **Audit secret access**

Example using External Secrets:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: mpcium-secrets-node0
  namespace: mpcium
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: mpcium-secrets-node0
  data:
    - secretKey: mpcium-db-password.cred
      remoteRef:
        key: mpcium/node0/db-password
    - secretKey: mpcium-identity-password.cred
      remoteRef:
        key: mpcium/node0/identity-password
```

### Data Encryption

- **At rest**: BadgerDB uses AES-256 encryption with `badger_password`
- **In transit**: NATS messages encrypted with ECDH + AES
- **Backups**: Encrypted with same key as database

### Access Control

Use Kubernetes RBAC to control access:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mpcium-operator
  namespace: mpcium
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch", "update", "patch"]
```

## Troubleshooting

### Common Issues

#### Pod Not Starting

**Check events**:

```bash
kubectl describe pod -n mpcium <pod-name>
```

**Common causes**:

- Image pull failure - verify image exists
- Secret not found - verify secret creation
- PVC binding failure - check storage class

#### Database Initialization Errors

**Symptoms**: Pod crashes with BadgerDB errors

**Solutions**:

```bash
# Check if BadgerDB is corrupted
kubectl exec -n mpcium -it <pod-name> -- ls -la /data/db/

# Check password is correct
kubectl get secret mpcium-secrets-node0 -n mpcium -o json | \
  jq -r '.data["mpcium-db-password.cred"]' | base64 -d

# If data is corrupted, restore from backup
# 1. Delete the PVC
# 2. Recreate PVC
# 3. Restore backup
# 4. Redeploy pod
```

#### Identity Decryption Errors

**Symptoms**: Pod logs show "Failed to decrypt private key"

**Check**:

```bash
# Verify identity password is correct
kubectl get secret mpcium-secrets-node0 -n mpcium -o json | \
  jq -r '.data["mpcium-identity-password.cred"]' | base64 -d

# Verify .age file is present in identity secret
kubectl get secret mpcium-identity-node0 -n mpcium -o json | \
  jq -r '.data | keys'
```

#### Consul Connection Failures

**Symptoms**: "Failed to load peers from Consul"

**Check**:

```bash
# Verify Consul is running
kubectl get pods -n mpcium -l app=consul

# Test connectivity from pod
kubectl exec -n mpcium -it <pod-name> -- \
  wget -O- http://consul:8500/v1/kv/mpc_peers/

# Verify peers are registered
kubectl port-forward -n mpcium svc/consul 8500:8500
curl http://localhost:8500/v1/kv/mpc_peers/?keys
```

#### NATS Connection Failures

**Symptoms**: "Failed to connect to NATS"

**Check**:

```bash
# Verify NATS is running
kubectl get pods -n mpcium -l app=nats

# Test connectivity
kubectl exec -n mpcium -it <pod-name> -- \
  nc -zv nats 4222

# Check NATS logs
kubectl logs -n mpcium -l app=nats
```

#### Threshold Not Met

**Symptoms**: MPC operations fail with "insufficient participants"

**Verify**:

```bash
# Check how many nodes are ready
kubectl get pods -n mpcium -l component=mpcium

# Check Consul for registered peers
kubectl port-forward -n mpcium svc/consul 8500:8500
# Visit http://localhost:8500/ui/dc1/kv/mpc_ready/

# Ensure mpc_threshold matches your cluster size
kubectl get configmap mpcium-config -n mpcium -o yaml
```

### Debugging Commands

```bash
# Launch an ephemeral debug container (distroless base image has no shell)
kubectl debug -n mpcium <pod-name> -it --image=busybox --target=mpcium

# Check environment variables
kubectl exec -n mpcium <pod-name> -- env | grep -i mpcium

# Inspect data/identity mounts
kubectl exec -n mpcium <pod-name> -- ls -la /app
kubectl exec -n mpcium <pod-name> -- ls -la /app/identity
kubectl exec -n mpcium <pod-name> -- ls -la /app/data

# Verify mpcium binary
kubectl exec -n mpcium <pod-name> -- /app/mpcium version
```

### Log Analysis

```bash
# Get startup logs
kubectl logs -n mpcium <pod-name> --tail=100 | grep -A 10 "MPCIUM"

# Search for errors
kubectl logs -n mpcium <pod-name> --tail=500 | grep -i error

# Check for successful operations
kubectl logs -n mpcium <pod-name> | grep -i "keygen.*success"
kubectl logs -n mpcium <pod-name> | grep -i "signing.*success"

# Export logs for analysis
kubectl logs -n mpcium <pod-name> > node0.log
```

### Recovery Procedures

#### Complete Cluster Restart

```bash
# 1. Stop all nodes
kubectl scale deployment mpcium-node0 --replicas=0 -n mpcium
kubectl scale deployment mpcium-node1 --replicas=0 -n mpcium
kubectl scale deployment mpcium-node2 --replicas=0 -n mpcium

# 2. Wait for shutdown
kubectl wait --for=delete pod -l component=mpcium -n mpcium --timeout=60s

# 3. Start all nodes
kubectl scale deployment mpcium-node0 --replicas=1 -n mpcium
kubectl scale deployment mpcium-node1 --replicas=1 -n mpcium
kubectl scale deployment mpcium-node2 --replicas=1 -n mpcium
```

#### Lost Node Recovery

```bash
# If a node's data is lost but identity is intact:

# 1. Delete the PVC
kubectl delete pvc mpcium-data-node0 -n mpcium

# 2. Recreate PVC (will provision new volume)
kubectl apply -f node0/pvc.yaml

# 3. Restart deployment
kubectl rollout restart deployment/mpcium-node0 -n mpcium

# 4. Node will start fresh (key shares may need resharing)
```

## Additional Resources

- **Mpcium Documentation**: https://github.com/fystack/mpcium
- **Client Library (TypeScript)**: https://github.com/fystack/mpcium-client-ts
- **tss-lib**: https://github.com/bnb-chain/tss-lib
- **NATS JetStream**: https://docs.nats.io/nats-concepts/jetstream
- **Consul**: https://www.consul.io/docs

## Support

For issues and questions:

- GitHub Issues: https://github.com/fystack/mpcium/issues
- Community: [Add your community channel]

---

**Version**: 0.3.3
**Last Updated**: November 2, 2025
**Maintainer**: FyStack Team
