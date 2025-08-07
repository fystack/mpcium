#!/bin/bash

# Function to decrypt secrets
decrypt_secret() {
    gpg --pinentry-mode loopback --passphrase "$1" -d "$2" 2>/dev/null
}

# Prompt for PASS value
read -sp "Enter the PASS value: " PASS
echo

# Set up environment variables
export GPG_TTY=$(tty)

# Decrypt secrets
NATS_PASSWORD=$(decrypt_secret "$PASS" ~/.password-store/apex-nats-password.gpg)
CONSUL_PASSWORD=$(decrypt_secret "$PASS" ~/.password-store/apex-consul-password.gpg)
CONSUL_TOKEN=$(decrypt_secret "$PASS" ~/.password-store/apex-consul-token.gpg)
BADGER_PASSWORD=$(decrypt_secret "$PASS" ~/.password-store/mpcium-badger-password.gpg)

# Prompt for command
read -p "Enter the command to execute: " user_command

# Execute the command with environment variables
env NATS_PASSWORD="$NATS_PASSWORD" \
    CONSUL_PASSWORD="$CONSUL_PASSWORD" \
    CONSUL_TOKEN="$CONSUL_TOKEN" \
    BADGER_PASSWORD="$BADGER_PASSWORD" \
    ENVIRONMENT=production \
    $user_command

# Clear sensitive variables
unset PASS NATS_PASSWORD CONSUL_PASSWORD CONSUL_TOKEN BADGER_PASSWORD
