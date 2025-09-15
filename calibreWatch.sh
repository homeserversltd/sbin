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
WATCH_DIR="/mnt/nas/books/upload/"
CALIBRE_LIBRARY="/mnt/nas/books"
SERVICE_NAME="calibre-watch"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_NAME="calibreWatch.sh"
SCRIPT_PATH="/usr/local/sbin/${SCRIPT_NAME}"

# Version tracking for self-update detection
VERSION_FILE="/usr/local/sbin/VERSION"
SERVICE_VERSION_FILE="/etc/systemd/system/${SERVICE_NAME}.version"

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
        log_info "Watch directory does not exist. Creating: $WATCH_DIR"
        if mkdir -p "$WATCH_DIR"; then
            log_success "Created watch directory: $WATCH_DIR"
        else
            log_error "Failed to create watch directory: $WATCH_DIR"
            exit 1
        fi
        
        # Set proper ownership and permissions
        if chown calibre:calibre "$WATCH_DIR"; then
            log_info "Set ownership to calibre:calibre"
        else
            log_warning "Failed to set ownership (may need to run as root)"
        fi
        
        if chmod 755 "$WATCH_DIR"; then
            log_info "Set permissions to 755"
        else
            log_warning "Failed to set permissions"
        fi
    else
        log_info "Watch directory exists: $WATCH_DIR"
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

# Validate book file type
validate_book_file() {
    local file="$1"
    local extension="${file##*.}"
    case "$extension" in
        epub|pdf|mobi|azw|azw3|txt|rtf|doc|docx|html|htm|lit|prc|pdb|fb2|djvu|djv|chm|tcr|ps|pdb|pml|rb|rtf2|snb|tcr|txtz|zip|cbz|cb7|cbr|cbt)
            return 0
            ;;
        *)
            log_warning "Skipping unsupported file type: $extension"
            return 1
            ;;
    esac
}

# Check if book already exists in library
check_duplicate() {
    local file="$1"
    local filename=$(basename "$file")
    if calibredb list --library-path="$CALIBRE_LIBRARY" --fields=formats | grep -q "$filename"; then
        log_info "Book already exists in library: $filename"
        return 0
    fi
    return 1
}

# Create the systemd service file
create_systemd_service() {
    log_info "Creating systemd service file: $SERVICE_FILE"
    
    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Calibre Web Watch Directory Monitor
After=network.target calibre-web.service
Wants=calibre-web.service
Requires=calibre-web.service

[Service]
Type=simple
User=calibre
Group=calibre
WorkingDirectory=/mnt/nas/books/upload/
ExecStart=/bin/bash -c 'while true; do if [ "\$(ls -A /mnt/nas/books/upload/ 2>/dev/null)" ]; then echo "[$(date)] Processing books in batches of 10..."; count=0; for book in /mnt/nas/books/upload/*; do if [ -f "$book" ]; then filename=$(basename "$book"); if echo "$filename" | grep -q "\.pdf$"; then echo "[$(date)] Adding: $filename"; if calibredb list --library-path="/mnt/nas/books" --fields=formats | grep -q "$filename"; then echo "[$(date)] Skipping duplicate: $filename"; rm -f "$book"; else calibredb add "$book" --library-path="/mnt/nas/books" --duplicates && rm -f "$book" || echo "[$(date)] Failed to add: $filename"; fi; count=$((count+1)); if [ $count -ge 10 ]; then echo "[$(date)] Processed 10 books, pausing..."; sleep 5; count=0; fi; else echo "[$(date)] Skipping unsupported format: $filename"; rm -f "$book"; fi; fi; done; echo "[$(date)] Batch processing complete"; fi; sleep 60; done'
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/mnt/nas/books/upload/ /mnt/nas/books

[Install]
WantedBy=multi-user.target
EOF

    if [[ $? -eq 0 ]]; then
        log_success "Systemd service file created successfully"
        # Save current version to service version file
        if [[ -f "$VERSION_FILE" ]]; then
            cp "$VERSION_FILE" "$SERVICE_VERSION_FILE"
            log_info "Service version tracked: $(cat "$VERSION_FILE")"
        fi
    else
        log_error "Failed to create systemd service file"
        exit 1
    fi
}

# Install the service
install_service() {
    log_info "Installing Calibre Web watch service..."
    
    # Check if service already exists and if version needs updating
    if [[ -f "$SERVICE_FILE" ]]; then
        log_info "Service already exists. Checking for version updates..."
        if check_and_update_service; then
            log_info "Service updated successfully"
            return 0
        else
            log_warning "Service exists but update check failed. Use 'restart' or 'uninstall' first if needed."
            log_info "Current service status:"
            systemctl status "$SERVICE_NAME" --no-pager
            return 0
        fi
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
    log_info "To check for updates: $0 update"
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

# Check if script version has changed and update service if needed
check_and_update_service() {
    if [[ ! -f "$VERSION_FILE" ]]; then
        log_warning "Version file not found: $VERSION_FILE"
        return 0
    fi
    
    local current_version
    current_version=$(cat "$VERSION_FILE")
    
    if [[ ! -f "$SERVICE_VERSION_FILE" ]]; then
        log_info "No service version file found, service needs to be created"
        return 1
    fi
    
    local service_version
    service_version=$(cat "$SERVICE_VERSION_FILE")
    
    if [[ "$current_version" != "$service_version" ]]; then
        log_info "Script version changed from $service_version to $current_version"
        log_info "Updating systemd service..."
        
        # Stop service if running
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log_info "Stopping service for update..."
            systemctl stop "$SERVICE_NAME"
        fi
        
        # Recreate service file
        create_systemd_service
        
        # Reload systemd daemon
        log_info "Reloading systemd daemon..."
        systemctl daemon-reload
        
        # Restart service if it was enabled
        if systemctl is-enabled --quiet "$SERVICE_NAME"; then
            log_info "Starting updated service..."
            systemctl start "$SERVICE_NAME"
            if [[ $? -eq 0 ]]; then
                log_success "Service updated and restarted successfully"
            else
                log_error "Failed to start updated service"
                return 1
            fi
        fi
        
        return 0
    else
        log_info "Script version unchanged: $current_version"
        return 0
    fi
}

# Force update service file regardless of version
force_update_service() {
    log_info "Force updating systemd service file..."
    
    # Stop service if running
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Stopping service for update..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    # Recreate service file
    create_systemd_service
    
    # Reload systemd daemon
    log_info "Reloading systemd daemon..."
    systemctl daemon-reload
    
    # Restart service if it was enabled
    if systemctl is-enabled --quiet "$SERVICE_NAME"; then
        log_info "Starting updated service..."
        systemctl start "$SERVICE_NAME"
        if [[ $? -eq 0 ]]; then
            log_success "Service force updated and restarted successfully"
        else
            log_error "Failed to start updated service"
            return 1
        fi
    else
        log_warning "Service is not enabled, not starting automatically"
    fi
    
    return 0
}

# Dry run mode - show what would be processed without actually doing it
dry_run_mode() {
    log_info "DRY RUN MODE - No files will be processed"
    log_info "Watch directory: $WATCH_DIR"
    log_info "Calibre library: $CALIBRE_LIBRARY"
    
    # Check and create watch directory if needed
    check_watch_directory
    
    local files_found=0
    local valid_files=0
    local duplicate_files=0
    local invalid_files=0
    
    for book in "$WATCH_DIR"/*; do
        if [[ -f "$book" ]]; then
            ((files_found++))
            local filename=$(basename "$book")
            log_info "Found file: $filename"
            
            if validate_book_file "$book"; then
                if check_duplicate "$book"; then
                    log_info "  -> Would skip (duplicate in library)"
                    ((duplicate_files++))
                else
                    log_info "  -> Would add to library"
                    ((valid_files++))
                fi
            else
                log_info "  -> Would skip (unsupported format)"
                ((invalid_files++))
            fi
        fi
    done
    
    if [[ $files_found -eq 0 ]]; then
        log_info "No files found in watch directory"
    else
        log_info "Dry run summary:"
        log_info "  Total files found: $files_found"
        log_info "  Would process: $valid_files"
        log_info "  Would skip (duplicates): $duplicate_files"
        log_info "  Would skip (invalid format): $invalid_files"
    fi
    
    return 0
}

# Show usage information
show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  install      - Install and start the Calibre Web watch service (default)"
    echo "  uninstall    - Remove the Calibre Web watch service"
    echo "  status       - Show service status"
    echo "  start        - Start the service"
    echo "  stop         - Stop the service"
    echo "  restart      - Restart the service"
    echo "  update       - Check for script version changes and update service if needed"
    echo "  force-update - Force update the service file regardless of version"
    echo "  dry-run      - Show what files would be processed without actually processing them"
    echo "  help         - Show this help message"
    echo ""
    echo "Update Usage:"
    echo "  $0 update    - Check VERSION file and update service if script was updated"
    echo ""
    echo "Configuration:"
    echo "  Watch directory: $WATCH_DIR"
    echo "  Calibre library: $CALIBRE_LIBRARY"
    echo "  Service name: $SERVICE_NAME"
    echo "  Version file: $VERSION_FILE"
    echo ""
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
        update)
            check_and_update_service
            ;;
        force-update)
            force_update_service
            ;;
        dry-run)
            dry_run_mode
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
