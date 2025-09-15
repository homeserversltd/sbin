#!/bin/bash

# ============================================================================
# CALIBRE FEEDER CRAWLER SCRIPT
# ============================================================================
# Feeder crawler that prowls the /books directory for new files, validates them,
# creates hardlinks to the upload directory, and tracks processed files.
# Works in conjunction with calibreWatch.sh (the data cruncher)
#
# Usage: calibreFeeder.sh [sync-now|cron|status|help]
# Default: sync-now (if no arguments provided)

set -u  # Exit on undefined variables

# Configuration
BOOKS_DIR="/mnt/nas/books"
UPLOAD_DIR="/mnt/nas/books/upload/"
TRACKING_FILE="/var/lib/calibre-feeder/processed_files.txt"
SERVICE_NAME="calibre-feeder"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SCRIPT_NAME="calibreFeeder.sh"
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

# Initialize tracking system
init_tracking() {
    local tracking_dir=$(dirname "$TRACKING_FILE")
    if [[ ! -d "$tracking_dir" ]]; then
        log_info "Creating tracking directory: $tracking_dir"
        mkdir -p "$tracking_dir"
    fi
    
    if [[ ! -f "$TRACKING_FILE" ]]; then
        log_info "Creating tracking file: $TRACKING_FILE"
        touch "$TRACKING_FILE"
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
            return 1
            ;;
    esac
}

# Get file hash for tracking
get_file_hash() {
    local file="$1"
    sha256sum "$file" 2>/dev/null | cut -d' ' -f1
}

# Check if file has been processed (by hash)
is_file_processed() {
    local file="$1"
    local file_hash=$(get_file_hash "$file")
    
    if [[ -z "$file_hash" ]]; then
        log_warning "Could not calculate hash for: $file"
        return 1
    fi
    
    if [[ -f "$TRACKING_FILE" ]] && grep -q "^$file_hash:" "$TRACKING_FILE"; then
        return 0
    fi
    return 1
}

# Mark file as processed (by hash)
mark_file_processed() {
    local file="$1"
    local file_hash=$(get_file_hash "$file")
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local filename=$(basename "$file")
    
    if [[ -z "$file_hash" ]]; then
        log_error "Could not calculate hash for: $file"
        return 1
    fi
    
    # Add to tracking file (hash:filename:timestamp:path)
    echo "$file_hash:$filename:$timestamp:$file" >> "$TRACKING_FILE"
    log_info "Marked as processed: $filename (hash: ${file_hash:0:8}...)"
}

# Get processing stats from tracking file
get_processing_stats() {
    if [[ ! -f "$TRACKING_FILE" ]]; then
        echo "0:0:0"
        return
    fi
    
    local total_processed=$(wc -l < "$TRACKING_FILE")
    local unique_hashes=$(cut -d: -f1 "$TRACKING_FILE" | sort -u | wc -l)
    local duplicate_entries=$((total_processed - unique_hashes))
    
    echo "$total_processed:$unique_hashes:$duplicate_entries"
}

# Show processing statistics
show_stats() {
    local stats=$(get_processing_stats)
    local total_processed=$(echo "$stats" | cut -d: -f1)
    local unique_hashes=$(echo "$stats" | cut -d: -f2)
    local duplicate_entries=$(echo "$stats" | cut -d: -f3)
    
    log_info "Processing Statistics:"
    log_info "  Total files processed: $total_processed"
    log_info "  Unique file hashes: $unique_hashes"
    log_info "  Duplicate entries: $duplicate_entries"
    
    if [[ $duplicate_entries -gt 0 ]]; then
        log_info "  (Duplicates indicate files were moved/renamed but already processed)"
    fi
}

# Create hardlink to upload directory
create_hardlink() {
    local source_file="$1"
    local filename=$(basename "$source_file")
    local target_file="$UPLOAD_DIR/$filename"
    
    # Check if target already exists
    if [[ -f "$target_file" ]]; then
        log_warning "File already exists in upload directory: $filename"
        return 1
    fi
    
    # Create hardlink
    if ln "$source_file" "$target_file" 2>/dev/null; then
        log_success "Created hardlink: $filename"
        return 0
    else
        log_error "Failed to create hardlink for: $filename"
        return 1
    fi
}

# Crawl books directory for new files
crawl_books_directory() {
    log_info "Crawling books directory: $BOOKS_DIR"
    
    if [[ ! -d "$BOOKS_DIR" ]]; then
        log_error "Books directory does not exist: $BOOKS_DIR"
        return 1
    fi
    
    local files_found=0
    local files_processed=0
    local files_skipped=0
    local files_invalid=0
    
    # Find all files recursively, excluding Calibre's internal structure
    while IFS= read -r -d '' file; do
        ((files_found++))
        local filename=$(basename "$file")
        
        # Skip Calibre internal files and directories
        if [[ "$file" =~ /(metadata\.db|\.calibre|cover\.jpg|\.opf)$ ]] || [[ -d "$file" ]]; then
            continue
        fi
        
        # Check if already processed
        if is_file_processed "$file"; then
            log_info "Already processed: $filename"
            ((files_skipped++))
            continue
        fi
        
        # Validate file type
        if ! validate_book_file "$file"; then
            log_warning "Skipping unsupported format: $filename"
            ((files_invalid++))
            continue
        fi
        
        # Create hardlink to upload directory
        if create_hardlink "$file"; then
            mark_file_processed "$file"
            ((files_processed++))
        else
            log_error "Failed to process: $filename"
        fi
        
    done < <(find "$BOOKS_DIR" -type f -print0 2>/dev/null)
    
    log_info "Crawl summary:"
    log_info "  Total files found: $files_found"
    log_info "  New files processed: $files_processed"
    log_info "  Files skipped (already processed): $files_skipped"
    log_info "  Files skipped (invalid format): $files_invalid"
    
    # Show overall processing statistics
    show_stats
    
    return 0
}

# Create the systemd service file for cron job
create_systemd_service() {
    log_info "Creating systemd service file: $SERVICE_FILE"
    
    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Calibre Feeder Crawler - Daily Book Discovery
After=network.target

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/local/sbin/calibreFeeder.sh cron
StandardOutput=journal
StandardError=journal

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
    log_info "Installing Calibre Feeder service..."
    
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
    
    # Initialize tracking system
    init_tracking
    
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
    
    log_success "Calibre Feeder service installed"
    log_info "Books directory: $BOOKS_DIR"
    log_info "Upload directory: $UPLOAD_DIR"
    log_info "Tracking file: $TRACKING_FILE"
    log_info "To run now: $0 sync-now"
    log_info "To schedule daily: systemctl enable $SERVICE_NAME.timer"
}

# Uninstall the service
uninstall_service() {
    log_info "Uninstalling Calibre Feeder service..."
    
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
    
    log_success "Calibre Feeder service uninstalled"
}

# Check service status
check_status() {
    if [[ -f "$SERVICE_FILE" ]]; then
        log_info "Service file exists: $SERVICE_FILE"
        systemctl status "$SERVICE_NAME" --no-pager
    else
        log_warning "Service file not found: $SERVICE_FILE"
        log_info "Run 'calibreFeeder.sh install' to install the service"
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
        
        # Recreate service file
        create_systemd_service
        
        # Reload systemd daemon
        log_info "Reloading systemd daemon..."
        systemctl daemon-reload
        
        return 0
    else
        log_info "Script version unchanged: $current_version"
        return 0
    fi
}

# Force update service file regardless of version
force_update_service() {
    log_info "Force updating systemd service file..."
    
    # Recreate service file
    create_systemd_service
    
    # Reload systemd daemon
    log_info "Reloading systemd daemon..."
    systemctl daemon-reload
    
    log_success "Service force updated successfully"
    return 0
}

# Show usage information
show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  sync-now     - Crawl books directory and process new files immediately"
    echo "  cron         - Run crawler (for systemd service)"
    echo "  install      - Install the feeder service"
    echo "  uninstall    - Remove the feeder service"
    echo "  status       - Show service status"
    echo "  stats        - Show processing statistics"
    echo "  update       - Check for script version changes and update service if needed"
    echo "  force-update - Force update the service file regardless of version"
    echo "  help         - Show this help message"
    echo ""
    echo "Configuration:"
    echo "  Books directory: $BOOKS_DIR"
    echo "  Upload directory: $UPLOAD_DIR"
    echo "  Tracking file: $TRACKING_FILE"
    echo "  Service name: $SERVICE_NAME"
    echo ""
    echo "This feeder crawler works with calibreWatch.sh to automatically"
    echo "discover and process new books in a two-part system."
}

# Main script logic
main() {
    # Check if running as root
    check_root
    
    # Get command (default to sync-now)
    local command="${1:-sync-now}"
    
    case "$command" in
        sync-now)
            init_tracking
            crawl_books_directory
            ;;
        cron)
            init_tracking
            crawl_books_directory
            ;;
        install)
            install_service
            ;;
        uninstall)
            uninstall_service
            ;;
        status)
            check_status
            ;;
        stats)
            show_stats
            ;;
        update)
            check_and_update_service
            ;;
        force-update)
            force_update_service
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
