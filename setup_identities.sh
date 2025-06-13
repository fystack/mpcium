#!/bin/bash

# Number of nodes to create (default is 3)
NUM_NODES=3

echo "🚀 Setting up Node Identities..."

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
    cd "node$i"
    mpcium-cli generate-identity --node "node$i"
    cd ..
done

# Distribute identity files to all nodes
echo "🔄 Distributing identity files across nodes..."
for i in $(seq 0 $((NUM_NODES-1))); do
    for j in $(seq 0 $((NUM_NODES-1))); do
        if [ $i != $j ]; then
            echo "📋 Copying node${i}_identity.json to node$j..."
            cp "node$i/identity/node${i}_identity.json" "node$j/identity/"
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