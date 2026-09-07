export PATH="$(go env GOPATH)/bin:$PATH"

NUM_NODES=3

make build

echo "🚀 Start the services..."
docker compose up -d
sleep 3

echo "🚀 Generating peers..."
mpcium-cli generate-peers -n $NUM_NODES

echo "📝 Copying config.yaml.template to config.yaml"
cp config.yaml.template config.yaml

echo "🚀 Registering peers to Consul..."
mpcium-cli register-peers

./setup_initiator.sh
./setup_identities.sh