# Taurus CMP Example

This example demonstrates how to use Taurus CMP (Cryptographic Multi-Party) protocol for key generation in MPCium.


## Running the Example

1. **Start your MPCium nodes** (see main README for setup instructions)

2. **Run the Taurus example**:
   ```bash
   cd examples/taurus
   go run main.go
   ```

## What This Example Does

1. **Connects to NATS** using your configuration
2. **Generates a new wallet ID** for the demonstration
3. **Triggers key generation** for all protocols (ECDSA, EdDSA, Taurus CMP)
4. **Shows the results** including Taurus CMP public key information

## Key Features Demonstrated

- **Taurus CMP Key Generation**: Creates threshold keys using the Taurus protocol
- **Result Handling**: Shows how to receive and process Taurus CMP results
- **Integration**: Demonstrates how Taurus CMP works alongside other protocols

## Expected Output

```
Generated wallet ID: 12345678-1234-1234-1234-123456789012
Step 1: Generating Taurus CMP keys...
Wallet creation request sent for 12345678-1234-1234-1234-123456789012
Waiting for key generation to complete...
Note: This generates keys for all protocols (ECDSA, EdDSA, Taurus CMP)
Taurus CMP key generated successfully
   Public key size: 64 bytes
```

## Next Steps

- Use the generated wallet ID for signing operations
- Try resharing the keys to refresh the key shares
- Explore the other examples for signing and resharing with different protocols

## Configuration

This example uses the same configuration as your MPCium nodes. Make sure:
- Your `config.yaml` is properly configured
- Your `event_initiator.key` exists
- Your MPCium nodes are running and ready
