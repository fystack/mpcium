# Embedded Cosigner Runtime Notes

When attaching the cosigner runtime to an existing `mpcium` node, the node config must include a `cosigner:` block. Without this block, or when `enabled` is false, the embedded cosigner runtime is not started.

Minimal config:

```yaml
cosigner:
  enabled: true
  orchestrator_id: "cosigner-orch-01"
  orchestrator_public_key_hex: "<ed25519-public-key-hex>"
```

The embedded runtime reuses values from the parent `mpcium` node:

- `participant_id`: supplied from the node ID
- `identity_private_key`: supplied from the node identity private key
- `nats`: supplied from the existing `mpcium` NATS connection

`data_dir` is optional. If omitted or blank, it defaults to:

```text
<db_path>/<node_name>/cosigner
```

Optional fields with defaults:

```yaml
cosigner:
  max_active_sessions: 5
  presence_interval: 5s
  tick_interval: 100ms
```

There is no need to add the cosigner to `peers.json`, create a separate cosigner identity, or configure a separate NATS connection when running it embedded in a node.
