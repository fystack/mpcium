#!/bin/bash

# E2E Test Identity Setup Script
# This script sets up identities for testing with separate test database paths
set -e

# Cross-platform sed in-place function
# macOS requires backup extension, Linux doesn't
sed_inplace() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "$@"
    else
        # Linux and others
        sed -i "$@"
    fi
}

# Number of test nodes
NUM_NODES=3
BASE_DIR="$(pwd)"
TEST_DB_PATH="$BASE_DIR/test_db"

echo "🚀 Setting up E2E Test Node Identities..."

# Generate random password for badger encryption
echo "🔐 Generating random password for badger encryption..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    BADGER_PASSWORD=$(openssl rand -hex 16)
else
    # Linux and others
    BADGER_PASSWORD=$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c 32)
fi
if [ ${#BADGER_PASSWORD} -ne 32 ]; then
    echo "❌ Generated Badger password must be exactly 32 bytes, got ${#BADGER_PASSWORD}"
    exit 1
fi
echo "✅ Generated password: $BADGER_PASSWORD"

# Generate chain_code (32-byte hex value, 64 hex characters)
echo "🔐 Generating chain_code (32-byte hex)..."
CHAIN_CODE=$(openssl rand -hex 32)
echo "✅ Generated chain_code: $CHAIN_CODE"

# Generate config.test.yaml from template
echo "📝 Generating config.test.yaml from template..."
if [ ! -f "config.test.yaml.template" ]; then
    echo "❌ Template file config.test.yaml.template not found"
    exit 1
fi

# Create a temporary config with placeholder values (will be updated later with real pubkey)
TEMP_PUBKEY="0000000000000000000000000000000000000000000000000000000000000000"

# Escape special characters in password for sed
ESCAPED_PASSWORD=$(printf '%s\n' "$BADGER_PASSWORD" | sed 's/[[\.*^$()+?{|]/\\&/g')

sed -e "s/{{\.BadgerPassword}}/$ESCAPED_PASSWORD/g" \
    -e "s/{{\.EventInitiatorPubkey}}/$TEMP_PUBKEY/g" \
    -e "s/{{\.CKDChainCode}}/$CHAIN_CODE/g" \
    config.test.yaml.template > config.test.yaml

echo "✅ Generated config.test.yaml from template"

# Clean up any existing test data
echo "🧹 Cleaning up existing test data..."
rm -rf "$TEST_DB_PATH"
rm -rf "$BASE_DIR"/test_node*

# Create test node directories
echo "📁 Creating test node directories..."
# Generate UUIDs for the nodes
NODE0_UUID=$(uuidgen)
NODE1_UUID=$(uuidgen)
NODE2_UUID=$(uuidgen)

for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "$BASE_DIR/test_node$i/identity"
    cp "$BASE_DIR/config.test.yaml" "$BASE_DIR/test_node$i/config.yaml"
    
    # Create peers.json with proper UUIDs
    cat > "$BASE_DIR/test_node$i/peers.json" << EOF
{
  "test_node0": "$NODE0_UUID",
  "test_node1": "$NODE1_UUID",
  "test_node2": "$NODE2_UUID"
}
EOF
done

# Generate identity for each test node
echo "🔑 Generating identities for each test node..."
for i in $(seq 0 $((NUM_NODES-1))); do
    echo "📝 Generating identity for test_node$i..."
    cd "$BASE_DIR/test_node$i"
    
    # Generate identity using mpcium-cli
    mpcium-cli generate-identity --node "test_node$i"
    
    cd - > /dev/null
done

# Distribute identity files to all test nodes
echo "🔄 Distributing identity files across test nodes..."
for i in $(seq 0 $((NUM_NODES-1))); do
    for j in $(seq 0 $((NUM_NODES-1))); do
        if [ $i != $j ]; then
            echo "📋 Copying test_node${i}_identity.json to test_node$j..."
            cp "$BASE_DIR/test_node$i/identity/test_node${i}_identity.json" "$BASE_DIR/test_node$j/identity/"
        fi
    done
done

# Generate test event initiator
echo "🔐 Generating test event initiator..."
cd "$BASE_DIR"
mpcium-cli generate-initiator --node-name test_event_initiator --output-dir . --overwrite

# Extract the public key from the generated identity
if [ -f "test_event_initiator.identity.json" ]; then
    PUBKEY=$(cat test_event_initiator.identity.json | jq -r '.public_key')
    echo "📝 Updating config files with event initiator public key and password..."
    
    # Update all test node config files with the actual public key, password, and chain_code
    for i in $(seq 0 $((NUM_NODES-1))); do
        # Update public key using sed with | as delimiter (safer than /)
        sed_inplace "s|event_initiator_pubkey:.*|event_initiator_pubkey: $PUBKEY|g" "$BASE_DIR/test_node$i/config.yaml"
        # Update password using sed with | as delimiter and escaped password
        sed_inplace "s|badger_password:.*|badger_password: $ESCAPED_PASSWORD|g" "$BASE_DIR/test_node$i/config.yaml"
        # Update chain_code
        if grep -q '^\s*chain_code:' "$BASE_DIR/test_node$i/config.yaml"; then
            sed_inplace "s|chain_code:.*|chain_code: \"$CHAIN_CODE\"|g" "$BASE_DIR/test_node$i/config.yaml"
        else
            printf '\nchain_code: "%s"\n' "$CHAIN_CODE" >> "$BASE_DIR/test_node$i/config.yaml"
        fi
    done
    
    # Also update the main config.test.yaml
    sed_inplace "s|event_initiator_pubkey:.*|event_initiator_pubkey: $PUBKEY|g" "$BASE_DIR/config.test.yaml"
    sed_inplace "s|badger_password:.*|badger_password: $ESCAPED_PASSWORD|g" "$BASE_DIR/config.test.yaml"
    # Update chain_code in config.test.yaml if it was replaced with placeholder
    if grep -q '{{\.CKDChainCode}}' "$BASE_DIR/config.test.yaml" 2>/dev/null; then
        sed_inplace "s|{{\.CKDChainCode}}|$CHAIN_CODE|g" "$BASE_DIR/config.test.yaml"
    elif grep -q '^\s*chain_code:' "$BASE_DIR/config.test.yaml"; then
        sed_inplace "s|chain_code:.*|chain_code: \"$CHAIN_CODE\"|g" "$BASE_DIR/config.test.yaml"
    else
        printf '\nchain_code: "%s"\n' "$CHAIN_CODE" >> "$BASE_DIR/config.test.yaml"
    fi
    
    echo "✅ Event initiator public key updated: $PUBKEY"
    echo "✅ Badger password updated: $BADGER_PASSWORD"
    echo "✅ Chain code updated: $CHAIN_CODE"
else
    echo "❌ Failed to generate event initiator identity"
    exit 1
fi

cd - > /dev/null

echo "✨ E2E Test identities setup complete!"
echo
echo "📂 Created test folder structure:"
echo "├── test_node0"
echo "│   ├── config.yaml"
echo "│   ├── identity/"
echo "│   └── peers.json"
echo "├── test_node1"
echo "│   ├── config.yaml"
echo "│   ├── identity/"
echo "│   └── peers.json"
echo "└── test_node2"
echo "    ├── config.yaml"
echo "    ├── identity/"
echo "    └── peers.json"
echo
echo "✅ Test nodes are ready for E2E testing!" 
