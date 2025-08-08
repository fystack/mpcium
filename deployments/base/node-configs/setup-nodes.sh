#!/bin/bash

# ==================================================================================
# MPCIUM Node Configuration Setup Script
# 
# This script automates the entire node setup process based on INSTALLATION.md
# Starting from "Generate Peer Configuration" section
# ==================================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Configuration variables
NUM_NODES=${NUM_NODES:-3}
MPC_THRESHOLD=${MPC_THRESHOLD:-2}
ENVIRONMENT=${ENVIRONMENT:-development}
BASE_DIR=${BASE_DIR:-$SCRIPT_DIR}
ENCRYPT_KEYS=${ENCRYPT_KEYS:-false}
NATS_URL=${NATS_URL:-"nats://127.0.0.1:4222"}
CONSUL_ADDRESS=${CONSUL_ADDRESS:-"localhost:8500"}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Utility functions
generate_strong_password() {
    # Generate a 32-byte password for BadgerDB
    # Generate more base64 data to ensure we have enough characters after filtering
    while true; do
        password=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-32)
        if [ ${#password} -eq 32 ]; then
            echo "$password"
            break
        fi
    done
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if mpcium-cli is available
    if ! command -v mpcium-cli &> /dev/null; then
        log_error "mpcium-cli not found. Please install it first:"
        log_error "  cd $PROJECT_ROOT"
        log_error "  go install ./cmd/mpcium-cli"
        exit 1
    fi
    
    # Check if required tools are available
    for tool in openssl jq; do
        if ! command -v $tool &> /dev/null; then
            log_error "$tool is required but not installed."
            exit 1
        fi
    done
    
    log_success "Prerequisites check passed"
}

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════════╗"
    echo "║                        MPCIUM Node Configuration Setup                           ║"
    echo "║                                                                                  ║"
    echo "║  This script will generate all necessary configuration files for MPCIUM nodes   ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
}

select_deployment_type() {
    log_info "Select deployment type:"
    echo "  1) Bare-metal deployment (localhost)"
    echo "  2) Docker deployment (docker-compose services)"
    echo
    
    while true; do
        read -p "Enter your choice (1 or 2): " choice
        case $choice in
            1)
                log_info "Selected: Bare-metal deployment"
                NATS_URL="nats://127.0.0.1:4222"
                CONSUL_ADDRESS="localhost:8500"
                DEPLOYMENT_TYPE="bare-metal"
                break
                ;;
            2)
                log_info "Selected: Docker deployment"
                NATS_URL="nats://nats-server:4222"
                CONSUL_ADDRESS="consul:8500"
                DEPLOYMENT_TYPE="docker"
                break
                ;;
            *)
                log_error "Invalid choice. Please enter 1 or 2."
                ;;
        esac
    done
    
    echo
    log_info "Configuration:"
    echo "  - Deployment type: $DEPLOYMENT_TYPE"
    echo "  - Number of nodes: $NUM_NODES"
    echo "  - MPC Threshold: $MPC_THRESHOLD"
    echo "  - Environment: $ENVIRONMENT"
    echo "  - Encrypt keys: $ENCRYPT_KEYS"
    echo "  - NATS URL: $NATS_URL"
    echo "  - Consul Address: $CONSUL_ADDRESS"
    echo "  - Base directory: $BASE_DIR"
    echo
}

cleanup_existing_setup() {
    log_info "Cleaning up existing setup..."
    
    # Remove existing node directories
    for i in $(seq 0 $(($NUM_NODES - 1))); do
        if [ -d "$BASE_DIR/node$i" ]; then
            log_warning "Removing existing node$i directory"
            rm -rf "$BASE_DIR/node$i"
        fi
    done
    
    # Remove existing files
    for file in peers.json event_initiator.identity.json event_initiator.key event_initiator.key.age config.yaml; do
        if [ -f "$BASE_DIR/$file" ]; then
            log_warning "Removing existing $file"
            rm -f "$BASE_DIR/$file"
        fi
    done
    
    log_success "Cleanup completed"
}

generate_peer_configuration() {
    log_info "Generating peer configuration..."
    
    cd "$BASE_DIR"
    
    # Generate peers.json
    mpcium-cli generate-peers -n $NUM_NODES -o peers.json
    
    if [ ! -f "peers.json" ]; then
        log_error "Failed to generate peers.json"
        exit 1
    fi
    
    log_success "Generated peers.json with $NUM_NODES nodes"
    
    # Display generated peers
    log_info "Generated peer IDs:"
    jq -r 'to_entries[] | "  \(.key): \(.value)"' peers.json
}

generate_config_yaml() {
    log_info "Creating config.yaml..."
    
    # Generate strong password
    BADGER_PASSWORD=$(generate_strong_password)
    
    # Create config.yaml
    cat > "$BASE_DIR/config.yaml" << EOF
nats:
  url: $NATS_URL

consul:
  address: $CONSUL_ADDRESS

mpc_threshold: $MPC_THRESHOLD
environment: $ENVIRONMENT
badger_password: "$BADGER_PASSWORD"
event_initiator_pubkey: "PLACEHOLDER_WILL_BE_UPDATED"
max_concurrent_keygen: 2
db_path: "."  
backup_enabled: true
backup_period_seconds: 300 # 5 minutes
backup_dir: backups
EOF
    
    log_success "Created config.yaml"
    log_info "Generated BadgerDB password: $BADGER_PASSWORD"
    log_warning "Please store this password securely! You'll need it to access your data."
}

generate_event_initiator() {
    log_info "Generating event initiator..."
    
    cd "$BASE_DIR"
    
    # Generate event initiator
    if [ "$ENCRYPT_KEYS" = "true" ]; then
        mpcium-cli generate-initiator --encrypt
        log_success "Generated encrypted event initiator"
    else
        mpcium-cli generate-initiator
        log_success "Generated unencrypted event initiator"
    fi
    
    # Extract public key from identity file
    if [ -f "event_initiator.identity.json" ]; then
        INITIATOR_PUBKEY=$(jq -r '.public_key' event_initiator.identity.json)
        
        # Update config.yaml with the initiator public key
        sed -i "s/event_initiator_pubkey: \"PLACEHOLDER_WILL_BE_UPDATED\"/event_initiator_pubkey: \"$INITIATOR_PUBKEY\"/" config.yaml
        
        log_success "Updated config.yaml with event initiator public key"
        log_info "Event initiator public key: $INITIATOR_PUBKEY"
    else
        log_error "Failed to find event_initiator.identity.json"
        exit 1
    fi
}

create_node_directories() {
    log_info "Creating node directories..."
    
    for i in $(seq 0 $(($NUM_NODES - 1))); do
        NODE_DIR="$BASE_DIR/node$i"
        mkdir -p "$NODE_DIR/identity"
        
        # Copy config files to each node
        cp "$BASE_DIR/config.yaml" "$NODE_DIR/"
        cp "$BASE_DIR/peers.json" "$NODE_DIR/"
        
        log_success "Created node$i directory"
    done
}

generate_node_identities() {
    log_info "Generating node identities..."
    
    for i in $(seq 0 $(($NUM_NODES - 1))); do
        NODE_NAME="node$i"
        NODE_DIR="$BASE_DIR/$NODE_NAME"
        
        cd "$NODE_DIR"
        
        log_info "Generating identity for $NODE_NAME..."
        
        if [ "$ENCRYPT_KEYS" = "true" ]; then
            mpcium-cli generate-identity --node "$NODE_NAME" --encrypt
        else
            mpcium-cli generate-identity --node "$NODE_NAME"
        fi
        
        log_success "Generated identity for $NODE_NAME"
    done
    
    cd "$BASE_DIR"
}

distribute_identity_files() {
    log_info "Distributing identity files to all nodes..."
    
    # Collect all identity files
    for i in $(seq 0 $(($NUM_NODES - 1))); do
        SOURCE_NODE="node$i"
        IDENTITY_FILE="$BASE_DIR/$SOURCE_NODE/identity/${SOURCE_NODE}_identity.json"
        
        if [ ! -f "$IDENTITY_FILE" ]; then
            log_error "Identity file not found: $IDENTITY_FILE"
            exit 1
        fi
        
        # Distribute to all other nodes
        for j in $(seq 0 $(($NUM_NODES - 1))); do
            if [ $i -ne $j ]; then
                TARGET_NODE="node$j"
                TARGET_DIR="$BASE_DIR/$TARGET_NODE/identity"
                
                cp "$IDENTITY_FILE" "$TARGET_DIR/"
                log_info "Copied ${SOURCE_NODE}_identity.json to $TARGET_NODE"
            fi
        done
    done
    
    log_success "Identity files distributed to all nodes"
}
fix_file_permissions() {
    log_info "Fixing file permissions for Docker compatibility..."
    
    cd "$BASE_DIR"
    
    # Fix permissions for all identity files
    for i in $(seq 0 $(($NUM_NODES - 1))); do
        NODE_DIR="node$i"
        if [ -d "$NODE_DIR/identity" ]; then
            log_info "Fixing permissions for $NODE_DIR/identity/*"
            chmod -R 644 "$NODE_DIR/identity/"*
            log_success "Fixed permissions for $NODE_DIR"
        fi
    done
    
    # Also fix permissions for event initiator files
    if [ -f "event_initiator.identity.json" ]; then
        chmod 644 event_initiator.identity.json
        log_info "Fixed permissions for event_initiator.identity.json"
    fi
    
    if [ -f "event_initiator.key" ]; then
        chmod 644 event_initiator.key
        log_info "Fixed permissions for event_initiator.key"
    fi
    
    if [ -f "event_initiator.key.age" ]; then
        chmod 644 event_initiator.key.age
        log_info "Fixed permissions for event_initiator.key.age"
    fi
    
    log_success "File permissions fixed for Docker compatibility"
}
print_summary() {
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                            🎉 SETUP COMPLETE! 🎉                                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    log_success "MPCIUM cluster configuration completed successfully!"
    echo
    log_info "📁 Generated files:"
    echo "  ├── config.yaml (cluster configuration)"
    echo "  ├── peers.json (peer ID mappings)"
    echo "  ├── event_initiator.identity.json (initiator public key)"
    if [ "$ENCRYPT_KEYS" = "true" ]; then
        echo "  ├── event_initiator.key.age (encrypted private key)"
    else
        echo "  ├── event_initiator.key (private key)"
    fi
    for i in $(seq 0 $(($NUM_NODES - 1))); do
        echo "  └── node$i/ (node configuration)"
        echo "      ├── config.yaml"
        echo "      ├── peers.json"
        echo "      └── identity/ (identity files)"
    done
    echo
    log_info "🚀 Next steps:"
    if [ "$DEPLOYMENT_TYPE" = "docker" ]; then
        echo "  1. Start Docker infrastructure: cd ../mpcium && docker-compose up -d"
        echo "  2. Register peers: mpcium-cli register-peers"
        echo "  3. Check logs: docker-compose logs -f mpcium0"
    else
        echo "  1. Start NATS and Consul infrastructure"
        echo "  2. Register peers: mpcium-cli register-peers"
        echo "  3. Start nodes manually: cd node0 && mpcium start --name node0"
    fi
    echo
    log_warning "🔐 Important: Store the BadgerDB password securely!"
    echo "   Password: $(grep badger_password config.yaml | cut -d'"' -f2)"
    echo
}

# ==================================================================================
# MAIN EXECUTION
# ==================================================================================

main() {
    print_banner
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--nodes)
                NUM_NODES="$2"
                shift 2
                ;;
            -t|--threshold)
                MPC_THRESHOLD="$2"
                shift 2
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --encrypt)
                ENCRYPT_KEYS=true
                shift
                ;;
            --nats-url)
                NATS_URL="$2"
                shift 2
                ;;
            --consul-address)
                CONSUL_ADDRESS="$2"
                shift 2
                ;;
            -d|--directory)
                BASE_DIR="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo
                echo "Options:"
                echo "  -n, --nodes NUM_NODES          Number of nodes to generate (default: 3)"
                echo "  -t, --threshold THRESHOLD      MPC threshold (default: 2)"
                echo "  -e, --environment ENV          Environment (development/production, default: development)"
                echo "      --encrypt                  Encrypt private keys with Age"
                echo "      --nats-url URL             NATS server URL (default: nats://127.0.0.1:4222)"
                echo "      --consul-address ADDR      Consul address (default: localhost:8500)"
                echo "  -d, --directory DIR            Base directory for setup (default: script directory)"
                echo "  -h, --help                     Show this help message"
                echo
                echo "Examples:"
                echo "  $0                             # Basic setup with interactive deployment type selection"
                echo "  $0 -n 5 -t 3 --encrypt        # 5 nodes with threshold 3, encrypted keys"
                echo "  $0 -e production --encrypt     # Production setup with encryption"
                echo
                echo "Deployment Types:"
                echo "  1) Bare-metal: Uses localhost for NATS (127.0.0.1:4222) and Consul (localhost:8500)"
                echo "  2) Docker: Uses service names for NATS (nats:4222) and Consul (consul:8500)"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Validate threshold
    if [ $MPC_THRESHOLD -ge $NUM_NODES ]; then
        log_error "MPC threshold ($MPC_THRESHOLD) must be less than number of nodes ($NUM_NODES)"
        exit 1
    fi
    
    # Create base directory if it doesn't exist
    mkdir -p "$BASE_DIR"
    cd "$BASE_DIR"
    
    # Execute setup steps
    check_prerequisites
    select_deployment_type
    cleanup_existing_setup
    generate_peer_configuration
    generate_config_yaml
    generate_event_initiator
    create_node_directories
    generate_node_identities
    distribute_identity_files
    fix_file_permissions
    print_summary
}

# Run main function with all arguments
main "$@"