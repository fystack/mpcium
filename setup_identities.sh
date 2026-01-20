#!/bin/bash
set -euo pipefail

# Number of nodes to create (default is 3)
NUM_NODES=3

echo "🚀 Setting up Node Identities..."

# Preconditions
command -v mpcium-cli >/dev/null 2>&1 || { echo "❌ mpcium-cli not found in PATH"; exit 1; }
[ -f config.yaml ] || { echo "❌ config.yaml not found in repo root"; exit 1; }

# Check if peers.json exists, if not provide helpful instructions
if [ ! -f peers.json ]; then
    echo "❌ peers.json not found in repo root"
    echo ""
    echo "📝 Please generate peers.json first by running:"
    echo "   mpcium-cli generate-peers -n $NUM_NODES"
    echo ""
    echo "This will create a peers.json file with $NUM_NODES peer nodes."
    exit 1
fi

# Create node directories and copy config files
echo "📁 Creating node directories..."
for i in $(seq 0 $((NUM_NODES-1))); do
    mkdir -p "node$i/identity"
    if [ ! -f "node$i/config.yaml" ]; then
        cp config.yaml "node$i/"
    fi
    if [ ! -f "node$i/peers.json" ]; then
        cp peers.json "node$i/"
    fi
done

# Generate identity for each node
echo "🔑 Generating identities for each node..."
for i in $(seq 0 $((NUM_NODES-1))); do
    echo "📝 Generating identity for node$i..."
    ( cd "node$i" && mpcium-cli generate-identity --node "node$i" )
done

# Generate a single chain_code if not present and set it in configs
if [ ! -f .chain_code ]; then
    echo "🔐 Generating chain_code (32-byte hex) ..."
    CC=$(openssl rand -hex 32)
    echo "$CC" > .chain_code
else
    CC=$(cat .chain_code)
fi

if [ -z "$CC" ]; then
    echo "❌ Failed to determine chain_code"
    exit 1
fi

echo "📝 Setting chain_code in root config.yaml ..."
if grep -q '^\s*chain_code:' config.yaml; then
    if [[ "${OSTYPE:-}" == darwin* ]]; then
        sed -i '' -E "s|^([[:space:]]*chain_code:).*|\\1 \"$CC\"|" config.yaml
    else
        sed -i -E "s|^([[:space:]]*chain_code:).*|\1 \"$CC\"|" config.yaml
    fi
else
    printf '\nchain_code: "%s"\n' "$CC" >> config.yaml
fi

echo "📦 Distributing chain_code to node configs ..."
for i in $(seq 0 $((NUM_NODES-1))); do
    if grep -q '^\s*chain_code:' "node$i/config.yaml"; then
        if [[ "${OSTYPE:-}" == darwin* ]]; then
            sed -i '' -E "s|^([[:space:]]*chain_code:).*|\\1 \"$CC\"|" config.yaml
        else
            sed -i -E "s|^([[:space:]]*chain_code:).*|\1 \"$CC\"|" config.yaml
        fi
    else
        printf '\nchain_code: "%s"\n' "$CC" >> "node$i/config.yaml"
    fi
done

# Distribute event_initiator_pubkey to all node configs
if [ -f "event_initiator.identity.json" ]; then
    INITIATOR_PUBKEY=$(grep -o '"public_key": *"[^"]*"' event_initiator.identity.json | cut -d '"' -f4)
    if [ -n "${INITIATOR_PUBKEY}" ]; then
        echo "📦 Distributing event_initiator_pubkey to node configs ..."
        for i in $(seq 0 $((NUM_NODES-1))); do
            if grep -q '^\s*event_initiator_pubkey:' "node$i/config.yaml"; then
                if [[ "${OSTYPE:-}" == darwin* ]]; then
                    sed -i '' -E "s|^([[:space:]]*event_initiator_pubkey:).*|\1 \"${INITIATOR_PUBKEY}\"|" "node$i/config.yaml"
                else
                    sed -i -E "s|^([[:space:]]*event_initiator_pubkey:).*|\1 \"${INITIATOR_PUBKEY}\"|" "node$i/config.yaml"
                fi
            fi
        done
    fi
fi

# Distribute identity files to all nodes
echo "🔄 Distributing identity files across nodes..."
for i in $(seq 0 $((NUM_NODES-1))); do
    src="node$i/identity/node${i}_identity.json"
    [ -f "$src" ] || { echo "❌ Missing identity file for node$i at $src"; exit 1; }
    for j in $(seq 0 $((NUM_NODES-1))); do
        if [ $i != $j ]; then
            mkdir -p "node$j/identity"
            echo "📋 Copying node${i}_identity.json to node$j..."
            cp -f "$src" "node$j/identity/"
        fi
    done
done

echo "✨ Node identities setup complete!"
echo
echo "📂 Created folder structure:"
echo "├── node0"
echo "│   ├── config.yaml"
echo "│   ├── identity/"
echo "│   └── peers.json"
echo "├── node1"
echo "│   ├── config.yaml"
echo "│   ├── identity/"
echo "│   └── peers.json"
echo "└── node2"
echo "    ├── config.yaml"
echo "    ├── identity/"
echo "    └── peers.json"
echo
echo "✅ You can now start your nodes with:"
echo "cd node0 && mpcium start -n node0"
echo "cd node1 && mpcium start -n node1"
echo "cd node2 && mpcium start -n node2" 
