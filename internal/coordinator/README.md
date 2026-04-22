# Coordinator Package

This package implements the control-plane coordinator for the new MPC runtime.

It is responsible for:

- request intake through NATS subjects or the gRPC client orchestration API (`keygen`, `sign`, `reshare`)
- session creation and lifecycle state transitions
- participant readiness and key exchange gating
- control message fan-out to participants
- participant event handling
- terminal result publishing
- timeout/abort handling

It is not responsible for:

- MPC cryptographic round computation
- relay mailbox behavior implementation
- decrypting participant-to-participant MPC packets

## Main Responsibilities

1. Accept operation requests over NATS:
   - `mpc.v1.request.keygen`
   - `mpc.v1.request.sign`
   - `mpc.v1.request.reshare`
   or over the gRPC `CoordinatorOrchestration` service for client orchestration.
2. Validate request shape and participant constraints.
3. Create a new `session_id` and initial session state.
4. Fan out `session.start` control messages to each selected participant.
5. Track participant events and advance session phases.
6. Publish terminal result on `mpc.v1.session.<sessionId>.result`.

## Runtime Components

- `Coordinator`:
  core orchestration logic and state machine.
- `NATSRuntime`:
  wiring from subjects to coordinator handlers.
- `GRPCRuntime`:
  optional plaintext client API for submitting keygen/sign requests and waiting for terminal session results.
- `MemorySessionStore`:
  in-memory session state.
- `AtomicFileSnapshotStore`:
  optional JSON snapshots for session persistence across restarts.
- `InMemoryPresenceView`:
  online/offline view used during request validation.
- `NATSControlPublisher` / `NATSResultPublisher`:
  delivery adapters for control and result messages.

The gRPC API is client-facing only. Participant control fan-out, participant session events, presence, and result publishing still use NATS/relay transport.

## Request Models

The operation is determined by subject. Each operation has its own request struct:

- `KeygenRequest`
- `SignRequest`
- `ReshareRequest`

Validation rules:

- keygen: `threshold + 1 <= len(participants)`
- sign: `len(participants) == threshold`
- reshare: validate `new_threshold` and `new_participants` consistency
- `key_type`:
  - keygen: optional; empty means default key types (`secp256k1`, `ed25519`)
  - sign: required
  - reshare: required

## Session Lifecycle

States:

- `created`
- `waiting_participants`
- `key_exchange`
- `active_mpc`
- `completed` / `failed` / `expired`

State flow:

1. `created`:
   session object allocated.
2. `waiting_participants`:
   wait until all selected participants report `peer.joined` and `peer.ready`.
3. `key_exchange`:
   coordinator fans out `key_exchange.begin`, then waits for `peer.key_exchange_done` from all participants.
4. `active_mpc`:
   coordinator fans out `mpc.begin`, then waits for terminal participant events.
5. terminal:
   - `completed` when all participants emit `session.completed` with identical `result_hash`
   - `failed` on participant/session failure or hash mismatch
   - `expired` when TTL passes

## Control and Event Flow

Request intake:

1. client publishes request to one of:
   - `mpc.v1.request.keygen`
   - `mpc.v1.request.sign`
   - `mpc.v1.request.reshare`
2. coordinator validates request and participant availability.
3. coordinator returns accept/reject response via NATS request-reply.

Session control:

1. coordinator publishes `session.start` to each participant control inbox:
   - `mpc.v1.peer.<peerId>.control`
2. participants report events on:
   - `mpc.v1.session.<sessionId>.event`
3. coordinator transitions session via `advance(...)` and emits:
   - `key_exchange.begin`
   - `mpc.begin`
   - `session.abort` (when failing/expiring)

Result publishing:

- terminal result is published to:
  - `mpc.v1.session.<sessionId>.result`

## Important Internal Functions

- `HandleRequest(...)`:
  parse op-specific request, validate, create session, send `session.start`.
- `HandleSessionEvent(...)`:
  process participant event and update participant/session state.
- `advance(...)`:
  state machine transition logic from readiness -> key exchange -> active MPC -> completed.
- `failSession(...)`:
  terminal failure handling and abort broadcast.
- `expireSession(...)`:
  TTL terminal handling and abort broadcast.

## Notes for Embedders

- coordinator is currently singleton-oriented.
- snapshots are best-effort persistence, not distributed consensus.
- event signature verification is pluggable but currently permissive by default.
- this package is internal control-plane logic; transport and participant runtimes integrate around it.
