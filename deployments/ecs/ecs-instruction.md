# ECS Fargate Deployment Guide for Mpcium

Reference guide for deploying Mpcium MPC nodes on AWS ECS Fargate. Infrastructure is expected to be provisioned via Terraform. This document covers the application-specific setup, secrets preparation, task definition structure, and operational notes a devops engineer needs.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Pre-Deployment Setup](#pre-deployment-setup)
4. [AWS Resources Required](#aws-resources-required)
5. [Secrets and Configuration](#secrets-and-configuration)
6. [Task Definition Reference](#task-definition-reference)
7. [IAM Policies Reference](#iam-policies-reference)
8. [Production Config Template](#production-config-template)
9. [Post-Deployment Verification](#post-deployment-verification)
10. [Troubleshooting](#troubleshooting)
11. [Security Checklist](#security-checklist)

## Overview

Mpcium uses a t-of-n threshold signature scheme where:

- **n** = total MPC nodes (minimum 3 recommended)
- **t** = minimum nodes required for operations (t >= floor(n/2) + 1)
- Private keys are never fully reconstructed
- Only t nodes needed for signing operations

Each ECS task runs a single mpcium node with:

- Unique identity (Ed25519 keypair)
- Encrypted BadgerDB storage on EFS
- Connection to NATS message broker
- Connection to Consul for service discovery

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         AWS VPC                                   │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    ECS Cluster                               │ │
│  │                                                              │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │ │
│  │  │  Task: node0 │  │  Task: node1 │  │  Task: node2 │     │ │
│  │  │              │  │              │  │              │     │ │
│  │  │ init-secrets │  │ init-secrets │  │ init-secrets │     │ │
│  │  │ init-config  │  │ init-config  │  │ init-config  │     │ │
│  │  │ mpcium       │  │ mpcium       │  │ mpcium       │     │ │
│  │  │   ▼ EFS      │  │   ▼ EFS      │  │   ▼ EFS      │     │ │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │ │
│  │         │                  │                  │              │ │
│  └─────────┼──────────────────┼──────────────────┼──────────────┘ │
│            │                  │                  │                 │
│            └──────────────────┼──────────────────┘                 │
│                               │                                    │
│         ┌─────────────────────┤                                    │
│         │                     │                                    │
│    ┌────▼─────┐        ┌─────▼─────┐                             │
│    │   NATS   │        │  Consul   │                             │
│    │ JetStream│        │  KV Store │                             │
│    └──────────┘        └───────────┘                             │
│                                                                   │
│  ┌──────────┐  ┌──────────────────┐  ┌──────────┐               │
│  │   EFS    │  │ Secrets Manager  │  │    S3    │               │
│  │ /data/   │  │ passwords        │  │ config   │               │
│  └──────────┘  └──────────────────┘  └──────────┘               │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### Task Structure

Each ECS task contains three containers:

1. **init-secrets** — Pulls passwords from AWS Secrets Manager, writes to `/secrets/` volume
2. **init-config** — Downloads config.yaml, peers.json, and identity files from S3
3. **mpcium** — Main application container (distroless, no shell)

## Pre-Deployment Setup

> **IMPORTANT**: All `mpcium-cli` commands below generate sensitive key material (private keys, passwords, identity files). Run these on a **secure, ephemeral workstation** — not on your laptop or a shared machine. Use a dedicated EC2 instance (e.g., a temporary `t3.micro` in a private subnet) or an air-gapped machine. Wipe the workstation after uploading outputs to Secrets Manager and S3.

### Step 1: Build mpcium-cli

```bash
git clone https://github.com/fystack/mpcium.git
cd mpcium
go install ./cmd/mpcium-cli
```

### Step 2: Generate Peer Configuration

```bash
mpcium-cli generate-peers -n 3

# Output: peers.json
# [
#   {"id": "node0_<random>", "name": "node0"},
#   {"id": "node1_<random>", "name": "node1"},
#   {"id": "node2_<random>", "name": "node2"}
# ]
```

### Step 3: Generate Event Initiator Identity

```bash
mpcium-cli generate-initiator --encrypt

# Save the decryption password securely
# Extract public key for config:
cat initiator_identity.json | jq -r '.public_key'
```

### Step 4: Generate Node Identities

```bash
for node in node0 node1 node2; do
  mpcium-cli generate-identity \
    --node "$node" \
    --peers ./peers.json \
    --output-dir ./identity/"$node" \
    --encrypt
  echo "Save the password for $node securely!"
done
```

Each identity directory contains:

```
identity/node0/
├── node0_identity.json
├── node0_private.key.age  (encrypted private key)
├── node1_identity.json
└── node2_identity.json
```

### Step 5: Generate Chain Code

```bash
CHAIN_CODE=$(openssl rand -hex 32)
echo "Chain code: $CHAIN_CODE"
```

### Step 6: Generate BadgerDB Passwords

```bash
for node in node0 node1 node2; do
  PASSWORD=$(< /dev/urandom tr -dc 'A-Za-z0-9!@#$' | head -c 16; echo)
  echo "$node BadgerDB password: $PASSWORD"
done
```

### Step 7: Peers Registration

Peers are automatically synced to Consul on node startup when the `--peers` flag is provided. No separate registration step is needed — see the `--peers=/config/peers.json` flag in the task definition command below.

## AWS Resources Required

The following resources should be provisioned via Terraform. This section documents the application-specific requirements.

### ECR

- Repository: `mpcium`
- Push the image built from the project root `Dockerfile`

### EFS

- Encrypted at rest
- Mount targets in each subnet where ECS tasks run
- **One access point per node** with POSIX UID/GID set to `65532` (matches distroless `nonroot` user)
  - node0: root directory `/node0`, owner 65532:65532, permissions 0755
  - node1: root directory `/node1`, owner 65532:65532, permissions 0755
  - node2: root directory `/node2`, owner 65532:65532, permissions 0755

Each node's EFS directory stores:
- `db/<NODE_NAME>/` — BadgerDB database (encrypted at rest with AES-256 via BadgerDB password)

EFS is multi-AZ durable. Enable **AWS Backup** on the EFS file system for full volume snapshots. The application-level backup (`backup_enabled: true`) provides additional granular encrypted `.enc` files for quick logical recovery.

### Secrets Manager

Per-node secrets (plaintext strings, not JSON):

| Secret name | Content |
|-------------|---------|
| `mpcium/<NODE_NAME>/db-password` | BadgerDB password from Step 6 |
| `mpcium/<NODE_NAME>/identity-password` | Identity decryption password from Step 4 |

### S3

Config bucket (public access blocked). Structure:

```
s3://<BUCKET>/mpcium/
├── peers.json                          # shared across all nodes
├── node0/
│   ├── config.yaml                     # from Production Config Template
│   └── identity/                       # all files from identity/node0/
│       ├── node0_identity.json
│       ├── node0_private.key.age
│       ├── node1_identity.json
│       └── node2_identity.json
├── node1/
│   ├── config.yaml
│   └── identity/
│       └── ...
└── node2/
    ├── config.yaml
    └── identity/
        └── ...
```

Optionally include TLS certs under `s3://<BUCKET>/mpcium/certs/` if using mTLS for NATS.

### CloudWatch Logs

- Log group: `/ecs/mpcium`
- Recommended retention: 30 days

### ECS

- Cluster with Fargate capacity provider
- One service per node, `desired_count = 1`
- Deployment config: `maximum_percent = 100`, `minimum_healthy_percent = 0` (ensures only one instance per node — important for BadgerDB lock files on EFS)
- Private subnets, no public IP

### Security Groups

| Rule | Port | Target |
|------|------|--------|
| Egress to NATS | 4222 | NATS server |
| Egress to Consul | 8500 | Consul server |
| Egress to EFS | 2049 | EFS mount targets |
| Egress to S3 | 443 | S3 VPC endpoint or NAT |
| Egress to Secrets Manager | 443 | Secrets Manager VPC endpoint or NAT |
| Egress to ECR | 443 | ECR VPC endpoint or NAT |

## Secrets and Configuration

### How Secrets Flow

```
Secrets Manager                    S3
  ├── db-password         ├── config.yaml
  └── identity-password   ├── peers.json
         │                └── identity/*.age, *.json
         ▼                         ▼
   ┌─────────────┐         ┌─────────────┐
   │ init-secrets │         │ init-config  │
   │ → /secrets/  │         │ → /config/   │
   │              │         │ → /identity/ │
   └──────┬───────┘         └──────┬───────┘
          │     shared volumes     │
          └──────────┬─────────────┘
                     ▼
              ┌─────────────┐
              │   mpcium     │
              │ /app/secrets │ (read-only)
              │ /config      │ (read-only)
              │ /app/identity│ (read-only)
              │ /app/data    │ (EFS, read-write)
              └──────────────┘
```

The main container is distroless (no shell), so all secrets must be pre-written to files by the init containers.

## Task Definition Reference

Template task definition for a single mpcium node. Replace all `<PLACEHOLDER>` values.

| Placeholder | Description |
|-------------|-------------|
| `<AWS_ACCOUNT_ID>` | AWS account ID |
| `<AWS_REGION>` | AWS region (e.g., `us-east-1`) |
| `<NODE_NAME>` | Node name (`node0`, `node1`, `node2`) |
| `<IMAGE_TAG>` | Docker image tag (e.g., `v0.3.3`) |
| `<S3_BUCKET>` | S3 bucket for config files |
| `<EFS_FILE_SYSTEM_ID>` | EFS file system ID |
| `<EFS_ACCESS_POINT_ID>` | EFS access point ID for this node |
| `<SECRETS_MANAGER_DB_PASSWORD_ARN>` | Secrets Manager secret name for BadgerDB password |
| `<SECRETS_MANAGER_IDENTITY_PASSWORD_ARN>` | Secrets Manager secret name for identity password |

```json
{
  "family": "mpcium-node",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::<AWS_ACCOUNT_ID>:role/mpcium-ecs-execution-role",
  "taskRoleArn": "arn:aws:iam::<AWS_ACCOUNT_ID>:role/mpcium-ecs-task-role",
  "containerDefinitions": [
    {
      "name": "init-secrets",
      "image": "amazon/aws-cli:latest",
      "essential": false,
      "entryPoint": ["sh", "-c"],
      "command": [
        "aws secretsmanager get-secret-value --secret-id <SECRETS_MANAGER_DB_PASSWORD_ARN> --query SecretString --output text > /secrets/mpcium-db-password.cred && aws secretsmanager get-secret-value --secret-id <SECRETS_MANAGER_IDENTITY_PASSWORD_ARN> --query SecretString --output text > /secrets/mpcium-identity-password.cred && chmod 400 /secrets/*.cred"
      ],
      "mountPoints": [
        {
          "sourceVolume": "secrets",
          "containerPath": "/secrets"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/mpcium",
          "awslogs-region": "<AWS_REGION>",
          "awslogs-stream-prefix": "init-secrets"
        }
      }
    },
    {
      "name": "init-config",
      "image": "amazon/aws-cli:latest",
      "essential": false,
      "entryPoint": ["sh", "-c"],
      "command": [
        "aws s3 cp s3://<S3_BUCKET>/mpcium/<NODE_NAME>/config.yaml /config/config.yaml && aws s3 cp s3://<S3_BUCKET>/mpcium/peers.json /config/peers.json && aws s3 cp s3://<S3_BUCKET>/mpcium/<NODE_NAME>/identity/ /identity/ --recursive && chmod 400 /identity/*.age && chmod 444 /identity/*.json /config/config.yaml /config/peers.json"
      ],
      "mountPoints": [
        {
          "sourceVolume": "config",
          "containerPath": "/config"
        },
        {
          "sourceVolume": "identity",
          "containerPath": "/identity"
        }
      ],
      "dependsOn": [
        {
          "containerName": "init-secrets",
          "condition": "SUCCESS"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/mpcium",
          "awslogs-region": "<AWS_REGION>",
          "awslogs-stream-prefix": "init-config"
        }
      }
    },
    {
      "name": "mpcium",
      "image": "<AWS_ACCOUNT_ID>.dkr.ecr.<AWS_REGION>.amazonaws.com/mpcium:<IMAGE_TAG>",
      "essential": true,
      "command": [
        "start",
        "--name=<NODE_NAME>",
        "--config=/config/config.yaml",
        "--password-file=/app/secrets/mpcium-db-password.cred",
        "--identity-password-file=/app/secrets/mpcium-identity-password.cred",
        "--decrypt-private-key",
        "--peers=/config/peers.json"
      ],
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "secrets",
          "containerPath": "/app/secrets",
          "readOnly": true
        },
        {
          "sourceVolume": "config",
          "containerPath": "/config",
          "readOnly": true
        },
        {
          "sourceVolume": "identity",
          "containerPath": "/app/identity",
          "readOnly": true
        },
        {
          "sourceVolume": "data",
          "containerPath": "/app/data"
        }
      ],
      "dependsOn": [
        {
          "containerName": "init-secrets",
          "condition": "SUCCESS"
        },
        {
          "containerName": "init-config",
          "condition": "SUCCESS"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -q --spider http://localhost:8080/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      },
      "linuxParameters": {
        "initProcessEnabled": true
      },
      "user": "65532:65532",
      "readonlyRootFilesystem": true,
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/mpcium",
          "awslogs-region": "<AWS_REGION>",
          "awslogs-stream-prefix": "mpcium"
        }
      },
      "stopTimeout": 10
    }
  ],
  "volumes": [
    {
      "name": "secrets",
      "host": {}
    },
    {
      "name": "config",
      "host": {}
    },
    {
      "name": "identity",
      "host": {}
    },
    {
      "name": "data",
      "efsVolumeConfiguration": {
        "fileSystemId": "<EFS_FILE_SYSTEM_ID>",
        "rootDirectory": "/",
        "transitEncryption": "ENABLED",
        "authorizationConfig": {
          "accessPointId": "<EFS_ACCESS_POINT_ID>",
          "iam": "ENABLED"
        }
      }
    }
  ],
  "tags": [
    {
      "key": "Project",
      "value": "mpcium"
    },
    {
      "key": "Component",
      "value": "mpc-node"
    }
  ]
}
```

### Volume Mount Summary

| Volume | Init-secrets | Init-config | Mpcium (main) | Persistent |
|--------|:---:|:---:|:---:|:---:|
| `secrets` (`/secrets/` → `/app/secrets/`) | write | - | read-only | No (ephemeral) |
| `config` (`/config/`) | - | write | read-only | No (ephemeral) |
| `identity` (`/identity/` → `/app/identity/`) | - | write | read-only | No (ephemeral) |
| `data` (`/app/data/`) | - | - | read-write | Yes (EFS) |

### Runtime File Paths (per node)

| File | Container Path | Source |
|------|---------------|--------|
| Config | `/config/config.yaml` | S3 → `config` volume |
| Peers | `/config/peers.json` | S3 → `config` volume |
| Identity files | `/app/identity/*.json, *.age` | S3 → `identity` volume |
| DB password | `/app/secrets/mpcium-db-password.cred` | Secrets Manager → `secrets` volume |
| Identity password | `/app/secrets/mpcium-identity-password.cred` | Secrets Manager → `secrets` volume |
| BadgerDB data | `/app/data/db/<NODE_NAME>/` | EFS (`data` volume) |
| Backups | `/app/data/backups/` | EFS (`data` volume) |

EFS directory structure per node's access point:

```
/  (EFS access point root = /<NODE_NAME> on the filesystem)
├── db/
│   └── <NODE_NAME>/    ← BadgerDB encrypted data
└── backups/            ← encrypted .enc backup files
```

## IAM Policies Reference

### Execution Role

- Attach managed policy: `arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy`
- Trust principal: `ecs-tasks.amazonaws.com`
- Additional permissions for CloudWatch log group `/ecs/mpcium`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:CreateLogGroup"
      ],
      "Resource": "arn:aws:logs:<AWS_REGION>:<AWS_ACCOUNT_ID>:log-group:/ecs/mpcium:*"
    }
  ]
}
```

### Task Role

- Trust principal: `ecs-tasks.amazonaws.com`
- Permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SecretsManagerRead",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": ["arn:aws:secretsmanager:<AWS_REGION>:<AWS_ACCOUNT_ID>:secret:mpcium/*"]
    },
    {
      "Sid": "S3ReadConfig",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::<S3_BUCKET>",
        "arn:aws:s3:::<S3_BUCKET>/mpcium/*"
      ]
    },
    {
      "Sid": "EFSMount",
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientWrite",
        "elasticfilesystem:ClientRootAccess"
      ],
      "Resource": "arn:aws:elasticfilesystem:<AWS_REGION>:<AWS_ACCOUNT_ID>:file-system/<EFS_FILE_SYSTEM_ID>"
    }
  ]
}
```

## Production Config Template

Create a `config.yaml` for each node. Replace all `<PLACEHOLDER>` values.

```yaml
environment: production

# BadgerDB storage paths (mounted via EFS)
db_path: /app/data/db
backup_dir: /app/data/backups

# Consul service discovery
consul:
  address: <CONSUL_ADDRESS>:8500

# NATS messaging (TLS required in production)
nats:
  url: nats://<NATS_ADDRESS>:4222
  username: <NATS_USERNAME>
  password: <NATS_PASSWORD>
  tls:
    client_cert: /config/certs/client-cert.pem
    client_key: /config/certs/client-key.pem
    ca_cert: /config/certs/rootCA.pem

# MPC threshold (t-of-n, where t >= floor(n/2) + 1)
mpc_threshold: 2

# Event initiator public key (Ed25519 hex)
event_initiator_pubkey: <EVENT_INITIATOR_PUBKEY>
event_initiator_algorithm: ed25519

# Chain code (32-byte hex, 64 characters)
chain_code: <CHAIN_CODE_HEX>

# Backup settings
# Application-level: writes encrypted .enc files to backup_dir for granular recovery.
# Volume-level: enable AWS Backup on the EFS file system for full snapshots.
backup_enabled: true
backup_period_seconds: 300

# Health check (required for ECS health monitoring)
healthcheck:
  enabled: true
  address: "0.0.0.0:8080"
```

## Post-Deployment Verification

### Expected Log Sequence

After tasks start, the mpcium container logs should show (in order):

1. `MPCIUM v0.3.3` banner
2. `Connected to badger kv store`
3. `Loaded peers from consul`
4. `[READY] Node is ready`
5. `Starting consumers`

### Health Check

The task definition health check hits `GET /health` on port 8080. Tasks should report `HEALTHY` within 60 seconds of starting (configured via `startPeriod`).

### Functional Test

Use the mpcium client library to verify operations:

1. **Wallet generation** (keygen)
2. **Message signing**
3. **Key resharing**

See https://github.com/fystack/mpcium-client-ts.

## Troubleshooting

### Init Container Failures

**Symptom**: Task stops with init container exit code != 0. Check CloudWatch logs under `init-secrets` or `init-config` stream prefixes.

**Common causes**:
- Task role missing Secrets Manager or S3 permissions
- Secret name mismatch (init-secrets uses the secret name in the `aws secretsmanager get-secret-value` command)
- S3 path does not exist or identity files were not uploaded

### Task Stuck in PROVISIONING

**Common causes**:
- EFS mount target not available in the task's subnet
- Security group does not allow NFS traffic (port 2049) to EFS
- Image pull failure — check ECR permissions and image tag

### Database Errors

- **Wrong password**: Secrets Manager value does not match the password used when the database was first initialized. BadgerDB encrypts at rest — the password cannot be changed after creation.
- **Permission denied on EFS**: Access point POSIX UID/GID must be 65532.
- **Corrupted data**: Delete the node's EFS directory and restart. Key shares will need resharing from other nodes.

### Identity Decryption Errors

**Symptom**: Logs show "Failed to decrypt private key"

- Identity password in Secrets Manager does not match the password used during `generate-identity --encrypt`
- The `.age` file was corrupted during S3 upload (verify checksums)

### NATS/Consul Connection Failures

- Security groups must allow egress to NATS (4222) and Consul (8500)
- If using TLS for NATS, verify cert files are uploaded to S3 and downloaded by init-config

### Health Check Failures

- `healthcheck.enabled` must be `true` in config.yaml
- `healthcheck.address` must be `0.0.0.0:8080` (not `localhost`)
- If the node takes longer to initialize, increase `startPeriod` in the task definition

## Security Checklist

- [ ] Tasks run in private subnets with no public IP
- [ ] Security groups use minimal egress rules (NATS 4222, Consul 8500, NFS 2049, HTTPS 443)
- [ ] EFS encrypted at rest with transit encryption enabled
- [ ] Passwords stored in Secrets Manager, never in task definitions, S3, or environment variables
- [ ] S3 bucket has public access blocked
- [ ] IAM follows least-privilege — task role scoped to `mpcium/*` secrets, specific S3 bucket, and specific EFS filesystem
- [ ] Container runs as nonroot (UID 65532), read-only root filesystem
- [ ] NATS uses mTLS with client certificates in production
- [ ] Consul ACLs enabled to restrict KV access
- [ ] CloudWatch log retention policy set
- [ ] BadgerDB encrypted at rest with AES-256
- [ ] All inter-node messages signed with Ed25519 and encrypted with ECDH + AES

---

**Version**: 0.3.3
**Last Updated**: March 2, 2026
**Maintainer**: FyStack Team
