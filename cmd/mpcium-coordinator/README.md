# Mpcium Coordinator MVP

This runtime implements the v1 control-plane coordinator from `docs/architecture/external-cosigner-runtime.md`.

It owns:

- NATS request-reply intake on `mpc.v1.request.keygen`, `mpc.v1.request.sign`, and `mpc.v1.request.reshare`
- optional plaintext gRPC client orchestration API for `Keygen`, `Sign`, and `WaitSessionResult`
- pinned participant validation
- session lifecycle state
- signed control fan-out to `mpc.v1.peer.<peerId>.control`
- participant event intake from `mpc.v1.session.<sessionId>.event`
- terminal result publishing to `mpc.v1.session.<sessionId>.result`

It does not implement relay, MQTT mailboxing, p2p MPC packet routing, gRPC participant transport, or legacy `mpc.*` subjects. NATS is still required for cosigner presence, control fan-out, participant session events, and result publishing.

## Run

```sh
go run ./cmd/mpcium-coordinator/main.go -c coordinator.config.yaml
```

The runtime config includes:

- `nats.url`: NATS server used for participant transport.
- `grpc.enabled`: enables the client orchestration API.
- `grpc.listen_addr`: plaintext gRPC listen address.
- `grpc.poll_interval`: result wait polling interval.
- `coordinator.id`, `coordinator.private_key_hex`, and `coordinator.snapshot_dir`.

Each operation has its own request shape. The operation comes from the NATS subject, so a sign request to `mpc.v1.request.sign` looks like:

```json
{
  "request_id": "req_123",
  "ttl_sec": 120,
  "threshold": 2,
  "participants": [
    { "peer_id": "peer-node-01", "transport": "nats" },
    { "peer_id": "peer-node-02", "transport": "nats" }
  ],
  "wallet_id": "wallet_123",
  "key_type": "secp256k1",
  "tx_id": "tx_456",
  "tx_hash": "0xabc"
}
```

For keygen, send `wallet_id`, `threshold`, and the full keygen participant set to `mpc.v1.request.keygen`. `key_type` is optional; when omitted, participants should generate both `secp256k1` and `ed25519` for that wallet/session. For sign, send exactly the participants selected for this signing session; MVP validation requires `len(participants) == threshold`.

Internal `nats` participants must publish online presence before requests are accepted:

```json
{
  "v": 1,
  "type": "peer.presence",
  "peer_id": "peer-node-01",
  "status": "online",
  "transport": "nats",
  "last_seen_at": "2026-04-16T10:00:00Z"
}
```

Publish it to `mpc.v1.peer.peer-node-01.presence`.
