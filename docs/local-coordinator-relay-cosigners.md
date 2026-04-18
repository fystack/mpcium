# Local Coordinator, Relay, NATS Node, and MQTT Cosigner

This guide runs a local mixed transport setup:

- 1 NATS server
- 1 coordinator
- 1 relay that bridges NATS and MQTT
- 1 MPCium cosigner node over NATS: `peer-node-01`
- 1 cosigner over MQTT: `peer-node-02`

The sample configs used by this guide are already in the repository:

- `coordinator.config.yaml`
- `relay.config.yaml`
- `cosigner.config.yaml`
- `cosigner2.config.yaml`

## Prerequisites

Install and start a local NATS server on `127.0.0.1:4222`.

```sh
nats-server
```

The relay listens on MQTT port `1883`. Make sure nothing else is using that port.

## Local SDK Replace

This repository imports the SDK as:

```go
github.com/fystack/mpcium-sdk
```

For local development, keep the SDK repository next to this repository:

```txt
work/
  mpcium/
  sdk/
```

Then make sure `go.mod` contains this replace directive:

```go
replace github.com/fystack/mpcium-sdk => ../sdk
```

You can check it with:

```sh
grep 'github.com/fystack/mpcium-sdk => ../sdk' go.mod
```

If the SDK is somewhere else, update the replace path:

```sh
go mod edit -replace github.com/fystack/mpcium-sdk=/absolute/path/to/sdk
go mod tidy
```

## Config Overview

`cosigner.config.yaml` runs `peer-node-01` through NATS:

```yaml
relay_provider: nats
node_id: peer-node-01
nats:
  url: "nats://127.0.0.1:4222"
```

`cosigner2.config.yaml` runs `peer-node-02` through MQTT:

```yaml
relay_provider: mqtt
node_id: peer-node-02
mqtt:
  broker: tcp://127.0.0.1:1883
  client_id: peer-node-02
  username: peer-node-02
  password: peer-node-02
```

## MQTT Credentials

Create `relay.credentials` in the repository root:

```txt
mobile-sample-01:mobile-sample-01
peer-node-02:peer-node-02
```

The relay reads this file from `relay.config.yaml`:

```yaml
relay:
  mqtt:
    username_password_file: ./relay.credentials
```

Each line is:

```txt
username:password
```

The relay requires the MQTT username to match the MQTT client ID. For `cosigner2.config.yaml`, all three values are `peer-node-02`:

```yaml
mqtt:
  client_id: peer-node-02
  username: peer-node-02
  password: peer-node-02
```

If the mobile sample connects through MQTT as `mobile-sample-01`, it must use:

```txt
client_id: mobile-sample-01
username: mobile-sample-01
password: mobile-sample-01
```

## Run Order

Open one terminal per process.

### 1. Coordinator

```sh
go run ./cmd/mpcium-coordinator/main.go -c coordinator.config.yaml
```

Expected logs include coordinator request, presence, and session event subscriptions.

### 2. Relay

```sh
go run ./cmd/mpcium-relay/main.go -c relay.config.yaml
```

Expected logs include:

```txt
relay subscribed NATS filter
relay subscribed MQTT filter
relay runtime started
```

### 3. NATS Cosigner Node

```sh
go run ./cmd/mpcium-cosigner/main.go -c cosigner.config.yaml
```

Expected logs include:

```txt
cosigner runtime started node_id=peer-node-01
relay nats subscribe subject=mpc.v1.peer.peer-node-01.control
```

### 4. MQTT Cosigner

```sh
go run ./cmd/mpcium-cosigner/main.go -c cosigner2.config.yaml
```

Expected logs include:

```txt
cosigner runtime started node_id=peer-node-02
relay mqtt subscribe subject=mpc.v1.peer.peer-node-02.control topic=mpc/v1/peer/peer-node-02/control
```

The relay should also log that `peer-node-02` connected.

## Wait for Presence

The coordinator keeps presence in memory. After starting or restarting the coordinator, relay, or MQTT cosigner, wait a few seconds before sending a keygen request.

Each online participant must publish presence before the coordinator accepts a session. If you send a request too early, the coordinator can reject it with:

```txt
coordinator rejected request (UNAVAILABLE): participant "peer-node-02" is offline
```

That means the session has not started yet. Wait for the cosigner heartbeat, then retry.

## Run Keygen

After both cosigners are online, run:

```sh
go run ./examples/coordinatorclient-keygen
```

Expected output:

```txt
protocol=ECDSA key_id=wallet_... session_id=sess_... wait_seconds=...
public_key_hex=...
protocol=EdDSA key_id=wallet_... session_id=sess_... wait_seconds=...
public_key_hex=...
```

## Troubleshooting

If `peer-node-02` is offline:

- Confirm the relay is running on `127.0.0.1:1883`.
- Confirm `cosigner2.config.yaml` uses `client_id`, `username`, and `password` set to `peer-node-02`.
- Confirm `relay.credentials` contains `peer-node-02:peer-node-02`.
- Restart the MQTT cosigner and wait for presence before retrying keygen.

If `peer-node-01` is offline:

- Confirm the NATS cosigner is running with `cosigner.config.yaml`.
- Confirm it can connect to `nats://127.0.0.1:4222`.
- Restart the NATS cosigner and wait for presence before retrying keygen.

If the relay starts but MQTT traffic does not reach NATS:

- Confirm `relay.config.yaml` uses `relay.bridge.nats_prefix: mpc.v1`.
- Confirm `relay.config.yaml` uses `relay.bridge.mqtt_prefix: mpc/v1`.
- Confirm the MQTT cosigner subscribes to `mpc/v1/peer/peer-node-02/control`.

If keygen hangs after the request is accepted:

- Check both cosigner logs for `cosigner received session start`.
- Check relay logs for `NATS->MQTT` and `MQTT->NATS` bridge logs.
- Make sure every participant in `examples/coordinatorclient-keygen/main.go` is running and online.
