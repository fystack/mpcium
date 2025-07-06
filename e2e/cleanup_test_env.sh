#!/bin/bash

# cleanup_test_env.sh - Comprehensive cleanup script for MPC test environment

set -e

echo "=== MPC Test Environment Cleanup ==="

# Function to kill MPC processes
kill_mpc_processes() {
    echo "Checking for existing MPC processes..."
    
    # Find all mpcium processes
    PIDS=$(pgrep -f "mpcium" || true)
    
    if [ -z "$PIDS" ]; then
        echo "No existing MPC processes found"
        return
    fi
    
    echo "Found MPC processes: $PIDS"
    echo "Force killing all processes..."
    
    # Force kill all processes immediately
    for pid in $PIDS; do
        echo "Killing process $pid"
        if kill -KILL "$pid" 2>/dev/null; then
            echo "Successfully killed process $pid"
        else
            echo "Failed to kill process $pid (may already be dead)"
        fi
    done
    
    echo "MPC process cleanup completed"
}

# Function to stop Docker containers
stop_docker_containers() {
    echo "Stopping Docker containers..."
    
    if [ -f "docker-compose.test.yaml" ]; then
        docker compose -f docker-compose.test.yaml down -v --remove-orphans || true
        echo "Docker containers stopped"
    else
        echo "No docker-compose.test.yaml found, skipping Docker cleanup"
    fi
}

# Function to clean up test artifacts
cleanup_test_artifacts() {
    echo "Cleaning up test artifacts..."
    
    # Remove test node directories
    for i in {0..2}; do
        if [ -d "test_node$i" ]; then
            rm -rf "test_node$i"
            echo "Removed test_node$i directory"
        fi
    done
    
    # Remove log files
    rm -f *.log
    echo "Removed log files"
    
    # Remove any test database files
    rm -rf test_db/ || true
    
    echo "Test artifacts cleanup completed"
}

# Main cleanup sequence
main() {
    echo "Starting comprehensive test environment cleanup..."
    
    kill_mpc_processes
    stop_docker_containers
    cleanup_test_artifacts
    
    echo "=== Cleanup completed ==="
}

# Run main function
main "$@" 
