#!/bin/bash
set -euo pipefail

# Configuration setup script for Mpcium
# This script sets up Mpcium configuration and systemd service (without starting)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MPCIUM_HOME="/opt/mpcium"
SERVICE_NAME="mpcium"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Function to validate that a value is not empty
validate_input() {
    local input="$1"
    local name="$2"
    
    if [[ -z "$input" ]]; then
        log_error "$name cannot be empty"
        return 1
    fi
    return 0
}

# Function to prompt for input with validation
prompt_input() {
    local prompt="$1"
    local var_name="$2"
    local example="$3"
    local input=""
    
    while true; do
        echo -e "${BLUE}[PROMPT]${NC} $prompt"
        if [[ -n "$example" ]]; then
            echo -e "  ${YELLOW}$example${NC}"
        fi
        read -p "> " input
        echo
        
        if validate_input "$input" "$(echo $prompt | sed 's/://')"; then
            eval "$var_name='$input'"
            break
        fi
    done
}

# Function to prompt for secret with validation
prompt_secret() {
    local name="$1"
    local var_name="$2"
    local secret=""
    
    while true; do
        echo -e "${BLUE}[PROMPT]${NC} Enter $name:"
        read -sp "> " secret
        echo
        
        if validate_input "$secret" "$name"; then
            eval "$var_name='$secret'"
            break
        fi
    done
}

# Function to prompt for secret with optional empty value
prompt_secret_optional() {
    local name="$1"
    local var_name="$2"
    local secret=""
    
    echo -e "${BLUE}[PROMPT]${NC} Enter $name (press Enter to leave empty):"
    read -sp "> " secret
    echo
    
    if [[ -z "$secret" ]]; then
        log_warn "⚠️  $name left empty"
    fi
    
    eval "$var_name='$secret'"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}


# Prompt for MPCIUM_NODE_NAME if not provided
setup_node_name() {
    log_step "Setting up node name..."
    
    local node_name=""
    prompt_input "Enter MPCIUM_NODE_NAME:" "node_name" "Examples: node0, node1, node2, node3,.."
    
    # Store the node name for later use
    MPCIUM_NODE_NAME="$node_name"
    log_info "Node name set to: $MPCIUM_NODE_NAME"
}

# Check for installed binaries in /usr/local/bin
check_binaries() {
    log_step "Checking for installed binaries in /usr/local/bin..."
    
    # Check if binaries are installed in /usr/local/bin
    if [[ -f "/usr/local/bin/mpcium" ]] && [[ -f "/usr/local/bin/mpcium-cli" ]]; then
        log_info "Found installed binaries in /usr/local/bin"
        return 0
    fi
    
    log_error "Binaries not found in /usr/local/bin. Please run 'make install' first."
    exit 1
}

# Ensure configuration exists
ensure_configuration() {
    log_step "Ensuring configuration exists..."
    
    # Create directory structure
    log_info "Creating directory structure..."
    mkdir -p "$MPCIUM_HOME"
    mkdir -p "/etc/mpcium"
    
    # Note: Binaries are expected to be installed in /usr/local/bin via 'go install'
    
    # Check for configuration file - require user to create it first
    if [[ -f "/etc/mpcium/config.yaml" ]]; then
        log_info "Config file found at /etc/mpcium/config.yaml"
    else
        log_error "Config file not found at /etc/mpcium/config.yaml"
        log_error "Please create the config file before running this script:"
        if [[ "$MPCIUM_ENVIRONMENT" == "development" ]]; then
            log_error "  1. Copy the template: sudo cp config.yaml.template /etc/mpcium/config.yaml"
        else
            log_error "  1. Copy the template: sudo cp config.prod.yaml.template /etc/mpcium/config.yaml"
        fi
        log_error "  2. Edit the configuration: sudo vim /etc/mpcium/config.yaml"
        log_error "  3. Run this script again"
        exit 1
    fi
    
    # Set proper ownership and permissions for /etc/mpcium directory and config file
    # Note: This will be called after create_user() so mpcium group will exist
    
    log_info "Configuration validation complete"
}

# Create system user
create_user() {
    log_step "Creating system user..."
    
    if ! id "mpcium" &>/dev/null; then
        useradd -r -s /bin/false -d "$MPCIUM_HOME" -c "Mpcium MPC Node" mpcium
        log_info "Created mpcium user and group"
    else
        log_info "User mpcium already exists"
    fi
    
    # Ensure group exists (in case user was created differently)
    if ! getent group mpcium >/dev/null; then
        groupadd -r mpcium
        usermod -g mpcium mpcium
        log_info "Created mpcium group and added user to it"
    fi
    
    # Set proper ownership for /opt/mpcium
    chown -R mpcium:mpcium "$MPCIUM_HOME"
    chmod 750 "$MPCIUM_HOME"
    
    # Set proper ownership and permissions for /etc/mpcium
    if [[ -d "/etc/mpcium" ]]; then
        chown root:mpcium "/etc/mpcium"
        chmod 750 "/etc/mpcium"
        log_info "/etc/mpcium directory permissions set (root:mpcium 750)"
        
        # Set permissions for config file if it exists
        if [[ -f "/etc/mpcium/config.yaml" ]]; then
            chown root:mpcium "/etc/mpcium/config.yaml"
            chmod 640 "/etc/mpcium/config.yaml"
            log_info "Config file permissions set (root:mpcium 640)"
        fi
    fi
}

# Check if current node uses encrypted identity
check_encrypted_identity() {
    local current_node_name="$MPCIUM_NODE_NAME"
    local identity_dir="$MPCIUM_HOME/identity"
    local encrypted_key_file="$identity_dir/${current_node_name}_private.key.age"
    local plain_key_file="$identity_dir/${current_node_name}_private.key"
    
    if [[ -f "$encrypted_key_file" ]]; then
        log_info "Detected encrypted identity file: ${current_node_name}_private.key.age"
        return 0  # true - encrypted
    elif [[ -f "$plain_key_file" ]]; then
        log_info "Detected plain identity file: ${current_node_name}_private.key"
        return 1  # false - not encrypted
    else
        log_warn "No identity file found for node: $current_node_name"
        return 1  # false - assume not encrypted
    fi
}

# Update service credentials (merged from update-service-credentials.sh)
update_service_credentials() {
    log_step "Updating service credentials..."
    
    local CRED_FILE="/etc/mpcium/mpcium-db-password.cred"
    local IDENTITY_CRED_FILE="/etc/mpcium/mpcium-identity-password.cred"
    local SERVICE_TEMPLATE="$SCRIPT_DIR/mpcium.service"
    local TARGET_SERVICE="/etc/systemd/system/mpcium.service"

    if [[ ! -f "$SERVICE_TEMPLATE" ]]; then
        log_error "Service template not found: $SERVICE_TEMPLATE"
        exit 1
    fi

    # Copy template to target location first
    log_info "Copying service template to systemd location: $TARGET_SERVICE"
    cp "$SERVICE_TEMPLATE" "$TARGET_SERVICE"

    # Handle database password credential
    if [[ -f "$CRED_FILE" ]]; then
        log_info "Reading database credential file: $CRED_FILE"
        # Flatten to single line (remove newlines, spaces)
        CRED_BLOB=$(tr -d '\n\r ' < "$CRED_FILE")

        if [[ -z "$CRED_BLOB" ]]; then
            log_error "Credential file is empty: $CRED_FILE"
            exit 1
        fi

        log_info "Injecting database credential into target service file: $TARGET_SERVICE"
        # Replace placeholder with raw base64 (no escaping) in the target file
        sed -i "s|DB_PASSWORD_BASE64_BLOB_DATA|$CRED_BLOB|g" "$TARGET_SERVICE"

        unset CRED_BLOB
        log_info "Database credential injected successfully"
    else
        log_warn "Database credential file not found: $CRED_FILE"
        log_warn "Service file left with database credential placeholder"
    fi

    # Check if encrypted identity is used and handle identity password credential
    if check_encrypted_identity; then
        log_info "Encrypted identity detected - processing identity password credential"
        
        if [[ -f "$IDENTITY_CRED_FILE" ]]; then
            log_info "Reading identity credential file: $IDENTITY_CRED_FILE"
            # Flatten to single line (remove newlines, spaces)
            IDENTITY_CRED_BLOB=$(tr -d '\n\r ' < "$IDENTITY_CRED_FILE")

            if [[ -z "$IDENTITY_CRED_BLOB" ]]; then
                log_error "Identity credential file is empty: $IDENTITY_CRED_FILE"
                exit 1
            fi

            log_info "Injecting identity credential into target service file: $TARGET_SERVICE"
            # Replace placeholder with raw base64 (no escaping) in the target file
            sed -i "s|IDENTITY_PASSWORD_BASE64_BLOB_DATA|$IDENTITY_CRED_BLOB|g" "$TARGET_SERVICE"
            # Enable identity password flag and decrypt flag in ExecStart
            sed -i "s|--password-file=%d/mpcium-db-password.cred|--password-file=%d/mpcium-db-password.cred --identity-password-file=%d/mpcium-identity-password.cred --decrypt-private-key|g" "$TARGET_SERVICE"

            unset IDENTITY_CRED_BLOB
            log_info "Identity credential injected successfully"
        else
            log_error "Encrypted identity detected but credential file not found: $IDENTITY_CRED_FILE"
            log_error "Please run setup-mpcium-cred.sh first to generate identity password credential"
            exit 1
        fi
    else
        log_info "Plain text identity detected - removing identity password placeholders"
        # Remove the entire identity password credential line completely
        sed -i "/SetCredentialEncrypted=mpcium-identity-password.cred:/d" "$TARGET_SERVICE"
        # Also clean up any remaining placeholder remnants (just in case)
        sed -i "s|IDENTITY_PASSWORD_BASE64_BLOB_DATA||g" "$TARGET_SERVICE"
        # Ensure ExecStart doesn't have the identity password flag or decrypt flag (shouldn't be there anyway, but just in case)
        sed -i "s| --identity-password-file=%d/mpcium-identity-password.cred --decrypt-private-key||g" "$TARGET_SERVICE"
        log_info "Identity password placeholders and flags removed successfully"
    fi

    chmod 644 "$TARGET_SERVICE"
    log_info "Reloading systemd daemon"
    systemctl daemon-reload

    log_info "Service configuration updated successfully"
}

# Install systemd service
install_systemd_service() {
    log_step "Installing systemd service..."
    
    if [[ ! -f "$SCRIPT_DIR/mpcium.service" ]]; then
        log_error "Service file not found: $SCRIPT_DIR/mpcium.service"
        exit 1
    fi
    
    # Copy template to /etc and update credentials
    update_service_credentials
    
    # Enable service (but don't start yet)
    systemctl enable "$SERVICE_NAME"
    
    log_info "Systemd service installed and enabled"
}

# Check environment and print current mode
check_environment() {
    log_step "Checking environment configuration..."
    
    local config_file="/etc/mpcium/config.yaml"
    
    if [[ ! -f "$config_file" ]]; then
        log_error "Config file not found at $config_file - the configuration file doesn't exist yet"
        return 1
    fi
    
    # Extract environment from config.yaml
    local environment=$(grep "^environment:" "$config_file" | sed 's/environment: *//g' | sed 's/"//g' | sed "s/'//g")
    
    if [[ -z "$environment" ]]; then
        environment="development" # default
        log_warn "Environment not specified in config.yaml, defaulting to development"
    fi
    
    log_info "Current environment: $environment"
    
    # If production, check NATS TLS configuration
    if [[ "$environment" == "production" ]]; then
        log_step "Production environment detected - validating NATS TLS configuration..."
        
        local nats_url=$(grep -A 10 "^nats:" "$config_file" | grep "url:" | sed 's/.*url: *//g' | sed 's/"//g' | sed "s/'//g")
        
        # Check if URL uses TLS
        if [[ ! "$nats_url" =~ ^tls:// ]]; then
            log_warn "⚠️  NATS URL should use TLS in production (tls://...), found: $nats_url"
        fi
        
        # Check for TLS certificate configuration
        local client_cert=$(grep -A 20 "^nats:" "$config_file" | grep "client_cert:" | sed 's/.*client_cert: *//g' | sed 's/"//g' | sed "s/'//g")
        local client_key=$(grep -A 20 "^nats:" "$config_file" | grep "client_key:" | sed 's/.*client_key: *//g' | sed 's/"//g' | sed "s/'//g")
        local ca_cert=$(grep -A 20 "^nats:" "$config_file" | grep "ca_cert:" | sed 's/.*ca_cert: *//g' | sed 's/"//g' | sed "s/'//g")
        
        if [[ -z "$client_cert" ]] || [[ -z "$client_key" ]] || [[ -z "$ca_cert" ]]; then
            log_error "❌ PRODUCTION SECURITY WARNING: NATS TLS certificates are not configured!"
            log_error "   Required configuration missing in nats.tls section:"
            [[ -z "$client_cert" ]] && log_error "   - client_cert: path to client certificate"
            [[ -z "$client_key" ]] && log_error "   - client_key: path to client private key"
            [[ -z "$ca_cert" ]] && log_error "   - ca_cert: path to CA certificate"
            log_error "   Please configure TLS certificates before running in production!"
            return 1
        else
            log_info "✓ NATS TLS configuration found:"
            log_info "  - client_cert: $client_cert"
            log_info "  - client_key: $client_key"  
            log_info "  - ca_cert: $ca_cert"
            
            # Optionally check if certificate files exist
            local missing_certs=0
            [[ ! -f "$client_cert" ]] && log_warn "  ⚠️  Client certificate file not found: $client_cert" && ((missing_certs++))
            [[ ! -f "$client_key" ]] && log_warn "  ⚠️  Client key file not found: $client_key" && ((missing_certs++))
            [[ ! -f "$ca_cert" ]] && log_warn "  ⚠️  CA certificate file not found: $ca_cert" && ((missing_certs++))
            
            if [[ $missing_certs -gt 0 ]]; then
                log_warn "  ⚠️  $missing_certs certificate file(s) not found - ensure they are available before starting the service"
            fi
        fi
    else
        log_info "Development environment - TLS validation skipped"
    fi
}

# Validate config.yaml has all required credentials
validate_config_credentials() {
    log_step "Validating configuration credentials..."
    
    local config_file="${1:-/etc/mpcium/config.yaml}"
    local errors=0
    
    if [[ ! -f "$config_file" ]]; then
        log_error "Config file not found at $config_file - the configuration file doesn't exist yet"
        return 1
    fi
    
    log_info "Validating config file: $config_file"
    
    # Note: badger_password is provided via systemd credentials, not config.yaml
    log_info "[i] badger_password will be provided via systemd credentials"
    
    # Check for required event_initiator_pubkey
    if ! grep -q "^event_initiator_pubkey:" "$config_file" || grep -q "^event_initiator_pubkey: *$" "$config_file" || grep -q '^event_initiator_pubkey: ""' "$config_file"; then
        log_error "❌ event_initiator_pubkey not configured in config.yaml"
        ((errors++))
    else
        log_info "✓ event_initiator_pubkey configured"
    fi

    # Check for required chain_code
    if ! grep -q "^chain_code:" "$config_file" || grep -q "^chain_code: *$" "$config_file" || grep -q '^chain_code: ""' "$config_file"; then
        log_error "❌ chain_code not configured in config.yaml"
        log_error "   Generate with: openssl rand -hex 32"
        log_error "   All nodes MUST use the same chain_code value"
        ((errors++))
    else
        # Validate chain_code is 64 hex characters (32 bytes)
        local chain_code=$(grep "^chain_code:" "$config_file" | sed 's/chain_code: *//g' | sed 's/"//g' | sed "s/'//g" | sed 's/#.*//g' | sed 's/ *$//g')
        if [[ ${#chain_code} -ne 64 ]]; then
            log_error "❌ chain_code must be 64 hex characters (32 bytes), got ${#chain_code} characters"
            log_error "   Generate with: openssl rand -hex 32"
            ((errors++))
        elif ! [[ "$chain_code" =~ ^[0-9a-fA-F]{64}$ ]]; then
            log_error "❌ chain_code must be hexadecimal (0-9, a-f), got invalid characters"
            ((errors++))
        else
            log_info "✓ chain_code configured (${#chain_code} hex chars)"
        fi
    fi
    
    # Check for NATS configuration
    local nats_url=$(grep -A 10 "^nats:" "$config_file" | grep "url:" | sed 's/.*url: *//g' | sed 's/"//g' | sed "s/'//g" | sed 's/#.*//g' | sed 's/ *$//g')
    if [[ -z "$nats_url" ]]; then
        log_error "❌ nats.url not configured in config.yaml"
        ((errors++))
    else
        log_info "✓ nats.url configured: $nats_url"
        
        # If NATS URL uses TLS, validate TLS certificate configuration
        if [[ "$nats_url" =~ ^tls:// ]]; then
            log_info "[TLS] TLS URL detected, validating certificate configuration..."
            
            local client_cert=$(grep -A 20 "^nats:" "$config_file" | grep -A 10 "tls:" | grep "client_cert:" | sed 's/.*client_cert: *//g' | sed 's/"//g' | sed "s/'//g" | sed 's/#.*//g' | sed 's/ *$//g')
            local client_key=$(grep -A 20 "^nats:" "$config_file" | grep -A 10 "tls:" | grep "client_key:" | sed 's/.*client_key: *//g' | sed 's/"//g' | sed "s/'//g" | sed 's/#.*//g' | sed 's/ *$//g')
            local ca_cert=$(grep -A 20 "^nats:" "$config_file" | grep -A 10 "tls:" | grep "ca_cert:" | sed 's/.*ca_cert: *//g' | sed 's/"//g' | sed "s/'//g" | sed 's/#.*//g' | sed 's/ *$//g')
            
            local tls_errors=0
            
            if [[ -z "$client_cert" ]]; then
                log_error "❌ nats.tls.client_cert not configured (required for TLS URL)"
                ((errors++))
                ((tls_errors++))
            else
                log_info "✓ nats.tls.client_cert configured: $client_cert"
            fi
            
            if [[ -z "$client_key" ]]; then
                log_error "❌ nats.tls.client_key not configured (required for TLS URL)"
                ((errors++))
                ((tls_errors++))
            else
                log_info "✓ nats.tls.client_key configured: $client_key"
            fi
            
            if [[ -z "$ca_cert" ]]; then
                log_error "❌ nats.tls.ca_cert not configured (required for TLS URL)"
                ((errors++))
                ((tls_errors++))
            else
                log_info "✓ nats.tls.ca_cert configured: $ca_cert"
            fi
            
            if [[ $tls_errors -eq 0 ]]; then
                log_info "[OK] All NATS TLS certificates configured"
            fi
        else
            log_warn "[!] NATS URL is not using TLS (consider using tls:// for production)"
        fi
    fi
    
    # Check for Consul configuration
    local consul_address=$(grep -A 10 "^consul:" "$config_file" | grep "address:" | sed 's/.*address: *//g' | sed 's/"//g' | sed "s/'//g" | sed 's/#.*//g' | sed 's/ *$//g')
    if [[ -z "$consul_address" ]]; then
        log_error "❌ consul.address not configured in config.yaml"
        ((errors++))
    else
        log_info "✓ consul.address configured: $consul_address"
        
        # If Consul address uses HTTPS, validate token configuration
        if [[ "$consul_address" =~ ^https:// ]]; then
            log_info "[HTTPS] HTTPS address detected, validating token configuration..."
            
            local consul_token=$(grep -A 10 "^consul:" "$config_file" | grep "token:" | sed 's/.*token: *//g' | sed 's/"//g' | sed "s/'//g" | sed 's/#.*//g' | sed 's/ *$//g')
            
            if [[ -z "$consul_token" ]]; then
                log_error "❌ consul.token not configured (required for HTTPS address)"
                ((errors++))
            else
                log_info "✓ consul.token configured"
            fi
        else
            log_warn "[!] Consul address is not using HTTPS (consider using https:// for production)"
            
            # Still check if token is configured for non-HTTPS (optional but recommended)
            local consul_token=$(grep -A 10 "^consul:" "$config_file" | grep "token:" | sed 's/.*token: *//g' | sed 's/"//g' | sed "s/'//g" | sed 's/#.*//g' | sed 's/ *$//g')
            if [[ -n "$consul_token" ]]; then
                log_info "✓ consul.token configured"
            else
                log_warn "[!] consul.token not configured (recommended for security)"
            fi
        fi
    fi
    
    # Validate required credentials are present
    if [[ $errors -gt 0 ]]; then
        log_error "❌ Configuration validation failed with $errors error(s)"
        log_error "Please configure the missing values in $config_file before proceeding"
        return 1
    fi
    
    log_info "[OK] All required credentials configured in config.yaml"
    return 0
}

# Setup environment file (simplified)
setup_environment_file() {
    log_step "Setting up environment file..."
    
    local env_file="$MPCIUM_HOME/.env"
    
    # Check environment configuration and validate production settings
    if ! check_environment; then
        log_error "Environment validation failed. Please fix configuration issues before proceeding."
        return 1
    fi
    
    # Validate config.yaml has all required credentials
    if ! validate_config_credentials; then
        log_error "Configuration validation failed. Please fix configuration issues before proceeding."
        return 1
    fi
    
    log_info "Creating environment file..."
    cat > "$env_file" << EOF
# Mpcium Environment Variables
# Generated on $(date)
# Note: All credentials are now configured in /etc/mpcium/config.yaml
MPCIUM_NODE_NAME=${MPCIUM_NODE_NAME}
EOF

    # Secure the environment file - only root can read/write, service user can read
    chown root:mpcium "$env_file"
    chmod 640 "$env_file"
    log_info "Environment file created at: $env_file"
    
    log_info "Environment file setup complete"
}

# Verify deployment structure
verify_deployment() {
    log_step "Verifying deployment structure..."
    
    local errors=0
    
    # Check required directories
    # Note: backups and db directories are created at runtime
    local required_dirs=("identity")
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "$MPCIUM_HOME/$dir" ]]; then
            log_error "Missing required directory: $MPCIUM_HOME/$dir"
            ((errors++))
        else
            log_info "✓ Directory exists: $dir"
        fi
    done
    
    # Check required files
    # config.yaml is in /etc/mpcium/, others are in $MPCIUM_HOME
    if [[ ! -f "/etc/mpcium/config.yaml" ]]; then
        log_error "Missing required file: /etc/mpcium/config.yaml"
        ((errors++))
    else
        log_info "✓ File exists: config.yaml"
    fi
    
    local required_files=(".env" "peers.json")
    for file in "${required_files[@]}"; do
        if [[ ! -f "$MPCIUM_HOME/$file" ]]; then
            log_error "Missing required file: $MPCIUM_HOME/$file"
            ((errors++))
        else
            log_info "✓ File exists: $file"
        fi
    done
    
    # Check binaries
    local required_binaries=("mpcium" "mpcium-cli")
    for binary in "${required_binaries[@]}"; do
        if [[ ! -f "/usr/local/bin/$binary" ]] || [[ ! -x "/usr/local/bin/$binary" ]]; then
            log_error "Missing or non-executable binary: /usr/local/bin/$binary"
            ((errors++))
        else
            log_info "✓ Binary exists and executable: $binary"
        fi
    done
    
    # Check peers.json and identity files
    if [[ -f "$MPCIUM_HOME/peers.json" ]]; then
        # Parse peers.json to get node names
        local node_names
        if command -v jq >/dev/null; then
            node_names=$(jq -r 'keys[]' "$MPCIUM_HOME/peers.json" 2>/dev/null)
            if [[ $? -eq 0 ]] && [[ -n "$node_names" ]]; then
                log_info "Found peer nodes in peers.json:"
                
                while IFS= read -r node_name; do
                    log_info "  - Checking identity files for: $node_name"
                    
                    # Check identity JSON file
                    local identity_file="$MPCIUM_HOME/identity/${node_name}_identity.json"
                    if [[ ! -f "$identity_file" ]]; then
                        log_error "Missing identity file: $identity_file"
                        ((errors++))
                    else
                        log_info "    ✓ Identity file exists: ${node_name}_identity.json"
                    fi
                    ``
                    # Check private key file only for current node
                    # Other nodes' private keys should NOT be present for security reasons
                    local current_node_name_from_env
                    if [[ -f "$MPCIUM_HOME/.env" ]]; then
                        current_node_name_from_env=$(grep "^MPCIUM_NODE_NAME=" "$MPCIUM_HOME/.env" | cut -d'=' -f2 | tr -d '"'"'"' ')
                    fi
                    
                    if [[ "$node_name" == "$current_node_name_from_env" ]]; then
                        # This is the current node - private key is required
                        local private_key_plain="$MPCIUM_HOME/identity/${node_name}_private.key"
                        local private_key_encrypted="$MPCIUM_HOME/identity/${node_name}_private.key.age"
                        
                        if [[ -f "$private_key_plain" ]]; then
                            log_info "    ✓ Private key file exists: ${node_name}_private.key"
                        elif [[ -f "$private_key_encrypted" ]]; then
                            log_info "    ✓ Encrypted private key file exists: ${node_name}_private.key.age"
                        else
                            log_error "Missing private key file for current node $node_name (expected either ${node_name}_private.key or ${node_name}_private.key.age)"
                            ((errors++))
                        fi
                    else
                        # This is a peer node - private key should NOT be present
                        local private_key_plain="$MPCIUM_HOME/identity/${node_name}_private.key"
                        local private_key_encrypted="$MPCIUM_HOME/identity/${node_name}_private.key.age"
                        
                        if [[ -f "$private_key_plain" ]] || [[ -f "$private_key_encrypted" ]]; then
                            log_warn "    ⚠ Private key found for peer node $node_name (security risk - should only have current node's private key)"
                        else
                            log_info "    ✓ No private key for peer node $node_name (correct for security)"
                        fi
                    fi
                done <<< "$node_names"
            else
                log_warn "Could not parse peers.json - skipping identity file checks"
            fi
        else
            log_warn "jq not available - skipping peers.json parsing and identity file checks"
        fi
    fi
    
    # Check current node's private key based on environment variable
    if [[ -f "$MPCIUM_HOME/.env" ]]; then
        local current_node_name
        current_node_name=$(grep "^MPCIUM_NODE_NAME=" "$MPCIUM_HOME/.env" | cut -d'=' -f2 | tr -d '"'"'"' ')
        
        if [[ -n "$current_node_name" ]]; then
            log_info "Current node from .env: $current_node_name"
            
            local current_private_key_plain="$MPCIUM_HOME/identity/${current_node_name}_private.key"
            local current_private_key_encrypted="$MPCIUM_HOME/identity/${current_node_name}_private.key.age"
            
            if [[ -f "$current_private_key_plain" ]]; then
                log_info "✓ Current node private key exists: ${current_node_name}_private.key"
            elif [[ -f "$current_private_key_encrypted" ]]; then
                log_info "✓ Current node encrypted private key exists: ${current_node_name}_private.key.age"
            else
                log_error "Current node missing private key file (expected either ${current_node_name}_private.key or ${current_node_name}_private.key.age)"
                ((errors++))
            fi
        else
            log_warn "MPCIUM_NODE_NAME not found in .env file"
        fi
    fi
    
    # Summary
    if [[ $errors -eq 0 ]]; then
        log_info "✅ Deployment structure verification passed!"
        return 0
    else
        log_error "❌ Deployment structure verification failed with $errors error(s)"
        return 1
    fi
}

# Show manual start instructions
show_manual_start_instructions() {
    echo
    log_info "Configuration setup completed successfully!"
    echo
    log_info "To start the service manually, run:"
    echo -e "  ${GREEN}sudo systemctl start $SERVICE_NAME${NC}"
    echo
    log_info "Other useful commands:"
    log_info "  Check status: sudo systemctl status $SERVICE_NAME"
    log_info "  View logs: sudo journalctl -u $SERVICE_NAME -f"
    log_info "  Stop service: sudo systemctl stop $SERVICE_NAME"
    log_info "  Restart service: sudo systemctl restart $SERVICE_NAME"
}

# Main configuration setup function
main() {
    log_info "Starting Mpcium configuration setup..."
    
    check_root
    setup_node_name
    check_binaries
    ensure_configuration  
    create_user
    install_systemd_service
    setup_environment_file
    
    # Run configuration verification
    log_step "Running configuration verification..."
    if verify_deployment; then
        show_manual_start_instructions
    else
        echo
        log_error "Configuration verification failed. Please fix the issues above before starting the service."
        log_info "You can run '$0 verify' again to check configuration."
        exit 1
    fi
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "validate-only")
        validate_config_credentials
        ;;
    "validate-config")
        log_info "Config file validation utility"
        echo
        
        config_path=""
        while true; do
            echo -e "${BLUE}[PROMPT]${NC} Enter path to config.yaml file to validate:"
            echo -e "  ${YELLOW}Examples:${NC}"
            echo -e "    /etc/mpcium/config.yaml"
            echo -e "    ./config.yaml"
            echo -e "    ./config.prod.yaml.template"
            read -p "> " config_path
            echo
            
            if [[ -z "$config_path" ]]; then
                log_error "Path cannot be empty. Please try again."
                continue
            fi
            
            if [[ ! -f "$config_path" ]]; then
                log_error "File not found: $config_path. Please try again."
                continue
            fi
            
            break
        done
        
        log_info "Validating config file: $config_path"
        echo
        
        if validate_config_credentials "$config_path"; then
            echo
            log_info "[SUCCESS] Config validation completed successfully!"
            log_info "The config file is properly configured."
        else
            echo
            log_error "[FAIL] Config validation failed!"
            log_error "Please fix the configuration issues above."
            exit 1
        fi
        ;;
    "update-creds")
        check_root
        update_service_credentials
        ;;
    "verify")
        verify_deployment
        ;;
    "status")
        systemctl status "$SERVICE_NAME" --no-pager -l
        ;;
    "logs")
        journalctl -u "$SERVICE_NAME" -f
        ;;
    "help"|"--help"|"-h")
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  deploy          Full configuration setup (default)"
        echo "  validate-only   Validate /etc/mpcium/config.yaml credentials only"
        echo "  validate-config Validate any config file (prompts for path)"
        echo "  update-creds    Update service credentials only"
        echo "  verify          Verify configuration and files"
        echo "  status          Show service status"
        echo "  logs            Follow service logs"
        echo "  help            Show this help"
        ;;
    *)
        log_error "Unknown command: $1"
        log_info "Use '$0 help' for available commands"
        exit 1
        ;;
esac
