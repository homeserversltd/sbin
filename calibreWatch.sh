#!/bin/bash

# ============================================================================
# CALIBRE WEB WATCH SCRIPT
# ============================================================================
# Self-contained script that manages a systemd service for monitoring
# a watch directory and automatically adding books to Calibre Web database
#
# Usage: calibreWatch.sh [install|uninstall|status|start|stop|restart]
# Default: install (if no arguments provided)

set -u  # Exit on undefined variables

# Configuration
WATCH_DIR="/mnt/nas/books/upload"
CALIBRE_LIBRARY="/mnt/nas/books"
SERVICE_NAME="calibre-watch"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_NAME="calibreWatch.sh"
SCRIPT_PATH="/usr/local/sbin/${SCRIPT_NAME}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check if calibredb is available and install if needed
check_calibredb() {
    if ! command -v calibredb &> /dev/null; then
        log_info "calibredb command not found. Installing calibre-bin..."
        
        # Update package list
        log_info "Updating package list..."
        if ! apt update; then
            log_error "Failed to update package list"
            exit 1
        fi
        
        # Install calibre-bin
        log_info "Installing calibre-bin..."
        if apt install -y calibre-bin; then
            log_success "calibre-bin installed successfully"
        else
            log_error "Failed to install calibre-bin"
            exit 1
        fi
        
        # Verify installation
        if ! command -v calibredb &> /dev/null; then
            log_error "calibredb still not available after installation"
            exit 1
        fi
    else
        log_info "calibredb is already available"
    fi
}

# Check if watch directory exists and is writable
check_watch_directory() {
    if [[ ! -d "$WATCH_DIR" ]]; then
        log_info "Creating watch directory: $WATCH_DIR"
        mkdir -p "$WATCH_DIR"
        chown calibre:calibre "$WATCH_DIR"
        chmod 755 "$WATCH_DIR"
    fi
    
    if [[ ! -w "$WATCH_DIR" ]]; then
        log_error "Watch directory $WATCH_DIR is not writable"
        exit 1
    fi
}

# Check if Calibre library exists
check_calibre_library() {
    if [[ ! -d "$CALIBRE_LIBRARY" ]]; then
        log_error "Calibre library directory $CALIBRE_LIBRARY does not exist"
        exit 1
    fi
    
    if [[ ! -f "$CALIBRE_LIBRARY/metadata.db" ]]; then
        log_error "Calibre metadata.db not found in $CALIBRE_LIBRARY"
        exit 1
    fi
}

# Create the systemd service file
create_systemd_service() {
    log_info "Creating systemd service file: $SERVICE_FILE"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Calibre Web Watch Directory Monitor
After=network.target calibre-web.service
Wants=calibre-web.service

[Service]
Type=simple
User=calibre
Group=calibre
WorkingDirectory=$WATCH_DIR
ExecStart=/bin/bash -c 'while true; do if [ "\$(ls -A $WATCH_DIR 2>/dev/null)" ]; then calibredb add -r "$WATCH_DIR" --library-path="$CALIBRE_LIBRARY" --duplicates && rm -f "$WATCH_DIR"/*; fi; sleep 30; done'
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$WATCH_DIR $CALIBRE_LIBRARY

[Install]
WantedBy=multi-user.target
EOF

    if [[ $? -eq 0 ]]; then
        log_success "Systemd service file created successfully"
    else
        log_error "Failed to create systemd service file"
        exit 1
    fi
}

# Install the service
install_service() {
    log_info "Installing Calibre Web watch service..."
    
    # Check if service already exists
    if [[ -f "$SERVICE_FILE" ]]; then
        log_warning "Service already exists. Use 'restart' or 'uninstall' first if needed."
        log_info "Current service status:"
        systemctl status "$SERVICE_NAME" --no-pager
        return 0
    fi
    
    # Check prerequisites
    check_calibredb
    check_watch_directory
    check_calibre_library
    
    # Create service file
    create_systemd_service
    
    # Reload systemd
    log_info "Reloading systemd daemon..."
    systemctl daemon-reload
    
    # Enable the service
    log_info "Enabling $SERVICE_NAME service..."
    systemctl enable "$SERVICE_NAME"
    
    if [[ $? -eq 0 ]]; then
        log_success "Service enabled successfully"
    else
        log_error "Failed to enable service"
        exit 1
    fi
    
    # Start the service
    log_info "Starting $SERVICE_NAME service..."
    systemctl start "$SERVICE_NAME"
    
    if [[ $? -eq 0 ]]; then
        log_success "Service started successfully"
    else
        log_error "Failed to start service"
        exit 1
    fi
    
    log_success "Calibre Web watch service installed and started"
    log_info "Watch directory: $WATCH_DIR"
    log_info "Calibre library: $CALIBRE_LIBRARY"
    log_info "Service status: systemctl status $SERVICE_NAME"
    log_info "To add books: Copy files to $WATCH_DIR"
}

# Uninstall the service
uninstall_service() {
    log_info "Uninstalling Calibre Web watch service..."
    
    # Stop and disable the service
    systemctl stop "$SERVICE_NAME" 2>/dev/null
    systemctl disable "$SERVICE_NAME" 2>/dev/null
    
    # Remove service file
    if [[ -f "$SERVICE_FILE" ]]; then
        rm -f "$SERVICE_FILE"
        log_success "Service file removed"
    fi
    
    # Reload systemd
    systemctl daemon-reload
    
    log_success "Calibre Web watch service uninstalled"
}

# Check service status
check_status() {
    if [[ -f "$SERVICE_FILE" ]]; then
        log_info "Service file exists: $SERVICE_FILE"
        systemctl status "$SERVICE_NAME" --no-pager
    else
        log_warning "Service file not found: $SERVICE_FILE"
        log_info "Run 'calibreWatch.sh install' to install the service"
    fi
}

# Start the service
start_service() {
    if [[ -f "$SERVICE_FILE" ]]; then
        log_info "Starting $SERVICE_NAME service..."
        systemctl start "$SERVICE_NAME"
        if [[ $? -eq 0 ]]; then
            log_success "Service started successfully"
        else
            log_error "Failed to start service"
            exit 1
        fi
    else
        log_error "Service not installed. Run 'calibreWatch.sh install' first"
        exit 1
    fi
}

# Stop the service
stop_service() {
    if [[ -f "$SERVICE_FILE" ]]; then
        log_info "Stopping $SERVICE_NAME service..."
        systemctl stop "$SERVICE_NAME"
        if [[ $? -eq 0 ]]; then
            log_success "Service stopped successfully"
        else
            log_error "Failed to stop service"
            exit 1
        fi
    else
        log_error "Service not installed"
        exit 1
    fi
}

# Restart the service
restart_service() {
    if [[ -f "$SERVICE_FILE" ]]; then
        log_info "Restarting $SERVICE_NAME service..."
        systemctl restart "$SERVICE_NAME"
        if [[ $? -eq 0 ]]; then
            log_success "Service restarted successfully"
        else
            log_error "Failed to restart service"
            exit 1
        fi
    else
        log_error "Service not installed. Run 'calibreWatch.sh install' first"
        exit 1
    fi
}

# Show usage information
show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  install   - Install and start the Calibre Web watch service (default)"
    echo "  uninstall - Remove the Calibre Web watch service"
    echo "  status    - Show service status"
    echo "  start     - Start the service"
    echo "  stop      - Stop the service"
    echo "  restart   - Restart the service"
    echo "  help      - Show this help message"
    echo ""
    echo "Configuration:"
    echo "  Watch directory: $WATCH_DIR"
    echo "  Calibre library: $CALIBRE_LIBRARY"
    echo "  Service name: $SERVICE_NAME"
}

# Main script logic
main() {
    # Check if running as root
    check_root
    
    # Get command (default to install)
    local command="${1:-install}"
    
    case "$command" in
        install)
            install_service
            ;;
        uninstall)
            uninstall_service
            ;;
        status)
            check_status
            ;;
        start)
            start_service
            ;;
        stop)
            stop_service
            ;;
        restart)
            restart_service
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
