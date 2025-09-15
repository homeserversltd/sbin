#!/bin/bash

# ============================================================================
# CALIBRE MONOLITHIC SYSTEM
# ============================================================================
# Combined script that manages the complete Calibre book processing system:
# - Feeder: Discovers new books and creates hardlinks to upload directory
# - Watcher: Monitors upload directory and adds books to Calibre library
# - System: Orchestrates both components with unified management
#
# Usage: calibreMonolith.sh [COMMAND] [COMPONENT]
# Commands: install, uninstall, status, start, stop, restart, sync-now, stats, help
# Components: feeder, watcher, system (default: system)

set -u  # Exit on undefined variables

# Configuration
BOOKS_DIR="/mnt/nas/books"
UPLOAD_DIR="/mnt/nas/books/upload/"
BACKUP_DIR="/mnt/nas/books/backup"
TRACKING_FILE="/var/lib/calibre-feeder/processed_files.txt"
CALIBRE_LIBRARY="/mnt/nas/books"

# Service names
FEEDER_SERVICE="calibre-feeder"
WATCHER_SERVICE="calibre-watch"
SYSTEM_NAME="calibre-system"

# Service files
FEEDER_SERVICE_FILE="/etc/systemd/system/${FEEDER_SERVICE}.service"
WATCHER_SERVICE_FILE="/etc/systemd/system/${WATCHER_SERVICE}.service"
FEEDER_TIMER_FILE="/etc/systemd/system/${FEEDER_SERVICE}.timer"

# Version tracking
VERSION_FILE="/usr/local/sbin/VERSION"
FEEDER_VERSION_FILE="/etc/systemd/system/${FEEDER_SERVICE}.version"
WATCHER_VERSION_FILE="/etc/systemd/system/${WATCHER_SERVICE}.version"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# ============================================================================
# FEEDER FUNCTIONS
# ============================================================================

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

# Initialize backup directory
init_backup_directory() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        log_info "Creating backup directory: $BACKUP_DIR"
        mkdir -p "$BACKUP_DIR"
    fi
    
    if [[ ! -w "$BACKUP_DIR" ]]; then
        log_error "Backup directory $BACKUP_DIR is not writable"
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
            return 1
            ;;
    esac
}

# Get file hash for tracking
get_file_hash() {
    local file="$1"
    sha256sum "$file" 2>/dev/null | cut -d' ' -f1
}

# Check if file has been processed
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

# Mark file as processed
mark_file_processed() {
    local file="$1"
    local file_hash=$(get_file_hash "$file")
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local filename=$(basename "$file")
    
    if [[ -z "$file_hash" ]]; then
        log_error "Could not calculate hash for: $file"
        return 1
    fi
    
    echo "$file_hash:$filename:$timestamp:$file" >> "$TRACKING_FILE"
    log_info "Marked as processed: $filename (hash: ${file_hash:0:8}...)"
}

# Move file to backup preserving directory structure
move_to_backup() {
    local source_file="$1"
    local relative_path="${source_file#$BOOKS_DIR/}"
    local backup_file="$BACKUP_DIR/$relative_path"
    local backup_dir=$(dirname "$backup_file")
    
    # Create backup directory structure
    if [[ ! -d "$backup_dir" ]]; then
        mkdir -p "$backup_dir"
    fi
    
    # Move file to backup location
    if mv "$source_file" "$backup_file" 2>/dev/null; then
        log_success "Moved to backup: $relative_path"
        echo "$backup_file"  # Return backup path for hardlink creation
        return 0
    else
        log_error "Failed to move to backup: $source_file"
        return 1
    fi
}

# Create hardlink from backup to upload directory
create_hardlink_from_backup() {
    local backup_file="$1"
    local filename=$(basename "$backup_file")
    local target_file="$UPLOAD_DIR/$filename"
    
    if [[ -f "$target_file" ]]; then
        log_warning "File already exists in upload directory: $filename"
        return 1
    fi
    
    if ln "$backup_file" "$target_file" 2>/dev/null; then
        log_success "Created hardlink from backup: $filename"
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
    
    # Initialize backup directory
    init_backup_directory
    
    local files_found=0
    local files_processed=0
    local files_skipped=0
    local files_invalid=0
    
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
        
        # Move to backup preserving directory structure, then create hardlink
        local backup_file
        if backup_file=$(move_to_backup "$file"); then
            if create_hardlink_from_backup "$backup_file"; then
                mark_file_processed "$file"
                ((files_processed++))
            else
                log_error "Failed to create hardlink for: $filename"
            fi
        else
            log_error "Failed to move to backup: $filename"
        fi
        
    done < <(find "$BOOKS_DIR" -type f -print0 2>/dev/null)
    
    log_info "Crawl summary:"
    log_info "  Total files found: $files_found"
    log_info "  New files processed: $files_processed"
    log_info "  Files skipped (already processed): $files_skipped"
    log_info "  Files skipped (invalid format): $files_invalid"
    
    return 0
}

# ============================================================================
# WATCHER FUNCTIONS
# ============================================================================

# Check if calibredb is available
check_calibredb() {
    if ! command -v calibredb &> /dev/null; then
        log_info "calibredb command not found. Installing calibre-bin..."
        
        if ! apt update; then
            log_error "Failed to update package list"
            exit 1
        fi
        
        if apt install -y calibre-bin; then
            log_success "calibre-bin installed successfully"
        else
            log_error "Failed to install calibre-bin"
            exit 1
        fi
        
        if ! command -v calibredb &> /dev/null; then
            log_error "calibredb still not available after installation"
            exit 1
        fi
    else
        log_info "calibredb is already available"
    fi
}

# Check watch directory
check_watch_directory() {
    if [[ ! -d "$UPLOAD_DIR" ]]; then
        log_info "Watch directory does not exist. Creating: $UPLOAD_DIR"
        if mkdir -p "$UPLOAD_DIR"; then
            log_success "Created watch directory: $UPLOAD_DIR"
        else
            log_error "Failed to create watch directory: $UPLOAD_DIR"
            exit 1
        fi
        
        if chown calibre:calibre "$UPLOAD_DIR"; then
            log_info "Set ownership to calibre:calibre"
        else
            log_warning "Failed to set ownership (may need to run as root)"
        fi
        
        if chmod 755 "$UPLOAD_DIR"; then
            log_info "Set permissions to 755"
        else
            log_warning "Failed to set permissions"
        fi
    else
        log_info "Watch directory exists: $UPLOAD_DIR"
    fi
    
    if [[ ! -w "$UPLOAD_DIR" ]]; then
        log_error "Watch directory $UPLOAD_DIR is not writable"
        exit 1
    fi
}

# Check Calibre library
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

# ============================================================================
# SERVICE MANAGEMENT FUNCTIONS
# ============================================================================

# Create feeder service file
create_feeder_service() {
    log_info "Creating feeder service file: $FEEDER_SERVICE_FILE"
    
    cat > "$FEEDER_SERVICE_FILE" << 'EOF'
[Unit]
Description=Calibre Feeder Crawler - Daily Book Discovery
After=network.target

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/local/sbin/calibreMonolith.sh feeder-cron
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    if [[ $? -eq 0 ]]; then
        log_success "Feeder service file created successfully"
        if [[ -f "$VERSION_FILE" ]]; then
            cp "$VERSION_FILE" "$FEEDER_VERSION_FILE"
            log_info "Service version tracked: $(cat "$VERSION_FILE")"
        fi
    else
        log_error "Failed to create feeder service file"
        exit 1
    fi
}

# Create watcher service file
create_watcher_service() {
    log_info "Creating watcher service file: $WATCHER_SERVICE_FILE"
    
    cat > "$WATCHER_SERVICE_FILE" << 'EOF'
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
        log_success "Watcher service file created successfully"
        if [[ -f "$VERSION_FILE" ]]; then
            cp "$VERSION_FILE" "$WATCHER_VERSION_FILE"
            log_info "Service version tracked: $(cat "$VERSION_FILE")"
        fi
    else
        log_error "Failed to create watcher service file"
        exit 1
    fi
}

# Create daily timer for feeder
create_feeder_timer() {
    log_info "Creating daily timer for feeder service..."
    
    cat > "$FEEDER_TIMER_FILE" << EOF
[Unit]
Description=Calibre Feeder - Daily Book Discovery
Requires=${FEEDER_SERVICE}.service

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

    if [[ $? -eq 0 ]]; then
        log_success "Daily timer created: $FEEDER_TIMER_FILE"
        systemctl daemon-reload
        systemctl enable "${FEEDER_SERVICE}.timer"
        log_info "Daily timer enabled (runs at 2 AM with 5-minute random delay)"
    else
        log_error "Failed to create daily timer"
        exit 1
    fi
}

# ============================================================================
# MAIN COMMAND FUNCTIONS
# ============================================================================

# Install feeder component
install_feeder() {
    log_info "Installing Calibre Feeder component..."
    
    init_tracking
    init_backup_directory
    create_feeder_service
    create_feeder_timer
    
    systemctl daemon-reload
    systemctl enable "$FEEDER_SERVICE"
    
    log_success "Feeder component installed"
    log_info "Books directory: $BOOKS_DIR"
    log_info "Backup directory: $BACKUP_DIR"
    log_info "Upload directory: $UPLOAD_DIR"
    log_info "Tracking file: $TRACKING_FILE"
}

# Install watcher component
install_watcher() {
    log_info "Installing Calibre Watcher component..."
    
    check_calibredb
    check_watch_directory
    check_calibre_library
    create_watcher_service
    
    systemctl daemon-reload
    systemctl enable "$WATCHER_SERVICE"
    systemctl start "$WATCHER_SERVICE"
    
    log_success "Watcher component installed and started"
    log_info "Watch directory: $UPLOAD_DIR"
    log_info "Calibre library: $CALIBRE_LIBRARY"
}

# Install complete system
install_system() {
    log_info "Installing complete Calibre System..."
    
    install_feeder
    install_watcher
    
    log_success "Calibre System installed successfully!"
    log_info "Components:"
    log_info "  - Feeder: Discovers and hardlinks new books"
    log_info "  - Watcher: Processes books from upload directory"
    log_info "  - Timer: Daily feeder runs at 2 AM"
}

# Uninstall feeder component
uninstall_feeder() {
    log_info "Uninstalling feeder component..."
    
    systemctl stop "$FEEDER_SERVICE" 2>/dev/null
    systemctl disable "$FEEDER_SERVICE" 2>/dev/null
    systemctl stop "${FEEDER_SERVICE}.timer" 2>/dev/null
    systemctl disable "${FEEDER_SERVICE}.timer" 2>/dev/null
    
    rm -f "$FEEDER_SERVICE_FILE"
    rm -f "$FEEDER_TIMER_FILE"
    rm -f "$FEEDER_VERSION_FILE"
    
    systemctl daemon-reload
    log_success "Feeder component uninstalled"
}

# Uninstall watcher component
uninstall_watcher() {
    log_info "Uninstalling watcher component..."
    
    systemctl stop "$WATCHER_SERVICE" 2>/dev/null
    systemctl disable "$WATCHER_SERVICE" 2>/dev/null
    
    rm -f "$WATCHER_SERVICE_FILE"
    rm -f "$WATCHER_VERSION_FILE"
    
    systemctl daemon-reload
    log_success "Watcher component uninstalled"
}

# Uninstall complete system
uninstall_system() {
    log_info "Uninstalling complete Calibre System..."
    
    uninstall_feeder
    uninstall_watcher
    
    log_success "Calibre System uninstalled"
}

# Check system status
check_status() {
    log_info "Calibre System Status:"
    echo ""
    
    # Check feeder service
    log_info "=== Feeder Service ==="
    if systemctl is-active --quiet "$FEEDER_SERVICE"; then
        log_success "Feeder service: ACTIVE"
    else
        log_warning "Feeder service: INACTIVE"
    fi
    
    if systemctl is-enabled --quiet "$FEEDER_SERVICE"; then
        log_info "Feeder service: ENABLED"
    else
        log_warning "Feeder service: DISABLED"
    fi
    
    # Check timer
    if systemctl is-active --quiet "${FEEDER_SERVICE}.timer"; then
        log_success "Daily timer: ACTIVE"
    else
        log_warning "Daily timer: INACTIVE"
    fi
    
    echo ""
    
    # Check watcher service
    log_info "=== Watcher Service ==="
    if systemctl is-active --quiet "$WATCHER_SERVICE"; then
        log_success "Watcher service: ACTIVE"
    else
        log_warning "Watcher service: INACTIVE"
    fi
    
    if systemctl is-enabled --quiet "$WATCHER_SERVICE"; then
        log_info "Watcher service: ENABLED"
    else
        log_warning "Watcher service: DISABLED"
    fi
    
    echo ""
    
    # Show detailed status
    log_info "=== Detailed Status ==="
    systemctl status "$FEEDER_SERVICE" --no-pager -l
    echo ""
    systemctl status "$WATCHER_SERVICE" --no-pager -l
}

# Start system
start_system() {
    log_info "Starting Calibre System..."
    
    if systemctl start "$WATCHER_SERVICE"; then
        log_success "Watcher service started"
    else
        log_error "Failed to start watcher service"
        exit 1
    fi
    
    if systemctl start "${FEEDER_SERVICE}.timer"; then
        log_success "Daily timer started"
    else
        log_warning "Failed to start daily timer"
    fi
    
    log_success "Calibre System started"
}

# Stop system
stop_system() {
    log_info "Stopping Calibre System..."
    
    if systemctl stop "$WATCHER_SERVICE"; then
        log_success "Watcher service stopped"
    else
        log_warning "Failed to stop watcher service"
    fi
    
    if systemctl stop "${FEEDER_SERVICE}.timer"; then
        log_success "Daily timer stopped"
    else
        log_warning "Failed to stop daily timer"
    fi
    
    log_success "Calibre System stopped"
}

# Restart system
restart_system() {
    log_info "Restarting Calibre System..."
    stop_system
    sleep 2
    start_system
}

# Run immediate sync
sync_now() {
    log_info "Running immediate sync (feeder + watcher)..."
    
    if crawl_books_directory; then
        log_success "Feeder sync completed"
    else
        log_error "Feeder sync failed"
        exit 1
    fi
    
    log_info "Watcher service will automatically process new files"
    log_info "Check status with: calibreMonolith.sh status"
}

# Show processing statistics
show_stats() {
    log_info "Calibre System Statistics:"
    echo ""
    
    if [[ -f "$TRACKING_FILE" ]]; then
        local total_processed=$(wc -l < "$TRACKING_FILE")
        local unique_hashes=$(cut -d: -f1 "$TRACKING_FILE" | sort -u | wc -l)
        local duplicate_entries=$((total_processed - unique_hashes))
        
        log_info "=== Feeder Statistics ==="
        log_info "  Total files processed: $total_processed"
        log_info "  Unique file hashes: $unique_hashes"
        log_info "  Duplicate entries: $duplicate_entries"
        
        if [[ $duplicate_entries -gt 0 ]]; then
            log_info "  (Duplicates indicate files were moved/renamed but already processed)"
        fi
    else
        log_info "=== Feeder Statistics ==="
        log_info "  No tracking file found - no files processed yet"
    fi
    
    echo ""
    
    log_info "=== Watcher Status ==="
    if systemctl is-active --quiet "$WATCHER_SERVICE"; then
        log_success "Watcher service: ACTIVE"
    else
        log_warning "Watcher service: INACTIVE"
    fi
}

# ============================================================================
# MAIN SCRIPT LOGIC
# ============================================================================

# Show usage information
show_usage() {
    echo "Usage: $0 [COMMAND] [COMPONENT]"
    echo ""
    echo "Commands:"
    echo "  install   - Install component(s) (default: system)"
    echo "  uninstall - Remove component(s)"
    echo "  status    - Show system status"
    echo "  start     - Start system components"
    echo "  stop      - Stop system components"
    echo "  restart   - Restart system components"
    echo "  sync-now  - Run immediate sync (discover and process books)"
    echo "  stats     - Show processing statistics"
    echo "  help      - Show this help message"
    echo ""
    echo "Components:"
    echo "  feeder    - Book discovery and hardlinking"
    echo "  watcher   - Upload directory monitoring and processing"
    echo "  system    - Complete system (default)"
    echo ""
    echo "Examples:"
    echo "  $0 install system     # Install complete system"
    echo "  $0 install feeder     # Install only feeder component"
    echo "  $0 status             # Show system status"
    echo "  $0 sync-now           # Run immediate sync"
    echo ""
    echo "System Architecture:"
    echo "  Feeder: Crawls /mnt/nas/books → moves to backup preserving structure → hardlinks to upload"
    echo "  Watcher: Monitors upload directory → adds to Calibre library"
    echo "  Timer: Daily feeder runs at 2 AM (with random delay)"
    echo ""
    echo "Directory Structure:"
    echo "  Books: $BOOKS_DIR (source files)"
    echo "  Backup: $BACKUP_DIR (preserves original directory structure)"
    echo "  Upload: $UPLOAD_DIR (temporary processing directory)"
    echo "  Library: $CALIBRE_LIBRARY (final Calibre library)"
}

# Main function
main() {
    check_root
    
    local command="${1:-help}"
    local component="${2:-system}"
    
    case "$command" in
        install)
            case "$component" in
                feeder) install_feeder ;;
                watcher) install_watcher ;;
                system) install_system ;;
                *) log_error "Invalid component: $component"; show_usage; exit 1 ;;
            esac
            ;;
        uninstall)
            case "$component" in
                feeder) uninstall_feeder ;;
                watcher) uninstall_watcher ;;
                system) uninstall_system ;;
                *) log_error "Invalid component: $component"; show_usage; exit 1 ;;
            esac
            ;;
        status)
            check_status
            ;;
        start)
            start_system
            ;;
        stop)
            stop_system
            ;;
        restart)
            restart_system
            ;;
        sync-now)
            sync_now
            ;;
        feeder-cron)
            init_tracking
            crawl_books_directory
            ;;
        stats)
            show_stats
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
