# Mpcium Security Model

## Core Security Principles

Mpcium implements a threshold signature scheme with industry-standard security practices to protect cryptographic operations:

1. **Distributed Trust**: No single entity possesses complete private keys
2. **Threshold Cryptography**: Requires t-out-of-n nodes to participate in signing operations
3. **End-to-End Verification**: All communications are signed and verified
4. **Defense in Depth**: Multiple layers of encryption and verification

## Identity and Authentication

### Node Identity Management

- **Ed25519 Keypairs**: Each node possesses a unique Ed25519 keypair for identity
- **Identity Generation**: Secure identity creation with the `generate-identity` command:
  ```
  go run cmd/mpcium-cli/main.go generate-identity --node=node0 --peers=peers.json --encrypt
  ```
- **Metadata Tracking**: Each identity includes creation information, machine details, and timestamps
- **Identity Verification**: All operations require cryptographic proof of identity

### Message Authentication

Every message in the Mpcium network undergoes rigorous verification:

```go
// Messages are signed before transmission
signature, err := s.identityStore.SignMessage(&tssMsg)
if err != nil {
    s.ErrCh <- fmt.Errorf("failed to sign message: %w", err)
    return
}
tssMsg.Signature = signature

// Messages are verified upon receipt
if !s.verifyMessageSignature(message) {
    return fmt.Errorf("invalid message signature")
}
```

- **Deterministic Signatures**: Messages are canonicalized before signing to ensure consistency
- **Party ID Verification**: TSS protocol ensures all participating nodes have valid identities
- **Signature Verification**: All inbound messages undergo signature verification before processing

## Encryption Technologies

### Private Key Encryption

Private keys are protected using multiple mechanisms:

1. **Age Encryption**:

   - State-of-the-art file encryption tool based on X25519
   - Scrypt key derivation for password-based encryption
   - Authenticated encryption ensuring tamper resistance

   ```
   # Decrypt private key for use
   age --decrypt -o event_initiator.key event_initiator.key.age
   ```

2. **Password Requirements**:
   - Generated with high entropy:
     ```
     < /dev/urandom tr -dc 'A-Za-z0-9!@#$^&\*()-\_=+[]{}|;:,.<>?/~' | head -c 16; echo
     ```
   - Users are prompted for passwords via secure input methods that don't echo to screen

### Local Storage Encryption

All node-local sensitive data is encrypted:

```go
// BadgerDB with mandatory encryption
	badgerKv, err := kvstore.NewBadgerKVStore(
		dbPath,
		[]byte(viper.GetString("badger_password")),
	)
```

- **Error on Missing Key**: The system refuses to start if encryption keys aren't provided
- **Encrypted Index**: Both data and metadata are encrypted
- **ZSTD Compression**: Data is compressed before encryption for efficiency

## Network Security

### TLS Implementation

All production communications use TLS:

```yaml
nats:
  url: tls://127.0.0.1:4222 # Required TLS for production
  username: ""
  password: ""

consul:
  address: https://consul.example.com # Required HTTPS for production
```

- **Certificate Verification**: Consul and NATS connections verify server certificates
- **Mutual TLS**: Both client and server authenticate each other
- **Strong Cipher Suites**: Only modern, secure cipher suites are used

### Secure Messaging Architecture

The NATS messaging infrastructure provides:

- **Topic Isolation**: Each session uses unique topics
- **Direct Messaging**: Point-to-point secure communications
- **JetStream Durability**: Critical messages persist with encryption
- **Queue Management**: Distributed queue processing with authentication

## Threshold Signature Protocol Security

### Multi-Party Computation

The threshold signature implementation includes:

- **Key Resharing**: Support for key rotation while maintaining the same public key
- **Threshold Flexibility**: Configurable threshold based on security requirements
- **Protocol Verification**: Messages include round and protocol verification

### Session Security

Each signing or key generation session implements:

- **Session Isolation**: Unique identifiers prevent cross-session interference
- **Timeout Handling**: Sessions expire if not completed within a timeframe
- **Error Propagation**: Secure error handling to prevent information leakage
- **Round Verification**: Each protocol round validates expected inputs

## Operational Security

### Node Distribution

- Deploy nodes across different:
  - Cloud providers
  - Geographic regions
  - Network segments
  - Administrative domains

### Key Management

- **Separate Key Material**: Store encrypted keys separately from passwords
- **Hardware Security**: Consider HSM integration for production deployments
- **Key Rotation**: Establish regular key rotation procedures
- **Backup Security**: Maintain secure, encrypted backups of all key material

### Network Hardening

- **Firewall Rules**: Restrict communication to only necessary ports
- **IP Whitelisting**: Limit connections to known IP addresses
- **DDoS Protection**: Implement DDoS mitigation for public-facing components
- **Network Monitoring**: Monitor for unusual traffic patterns

### Continuous Security

- **Dependency Scanning**: Regularly scan and update dependencies
- **Penetration Testing**: Conduct regular security assessments
- **Audit Logging**: Maintain comprehensive audit logs of all operations
- **Incident Response**: Develop and test security incident response procedures

