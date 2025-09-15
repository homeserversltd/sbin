#!/bin/bash

# ============================================================================
# CALIBRE SYSTEM ORCHESTRATOR
# ============================================================================
# Master script that manages the complete Calibre book processing system:
# - calibreFeeder.sh (feeder crawler)
# - calibreWatch.sh (data cruncher)
# Provides unified install/uninstall/management for the two-part system
#
# Usage: calibreSystem.sh [install|uninstall|status|start|stop|restart|sync-now|stats|help]

set -u  # Exit on undefined variables

# Configuration
SYSTEM_NAME="calibre-system"
FEEDER_SCRIPT="/usr/local/sbin/calibreFeeder.sh"
WATCHER_SCRIPT="/usr/local/sbin/calibreWatch.sh"
FEEDER_SERVICE="calibre-feeder"
WATCHER_SERVICE="calibre-watch"

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

# Check if component scripts exist
check_scripts() {
    local missing_scripts=()
    
    if [[ ! -f "$FEEDER_SCRIPT" ]]; then
        missing_scripts+=("calibreFeeder.sh")
    fi
    
    if [[ ! -f "$WATCHER_SCRIPT" ]]; then
        missing_scripts+=("calibreWatch.sh")
    fi
    
    if [[ ${#missing_scripts[@]} -gt 0 ]]; then
        log_error "Missing required scripts: ${missing_scripts[*]}"
        log_error "Please ensure both calibreFeeder.sh and calibreWatch.sh are installed"
        exit 1
    fi
}

# Install the complete system
install_system() {
    log_info "Installing Calibre System (Feeder + Watcher)..."
    
    # Check prerequisites
    check_scripts
    
    # Install feeder service
    log_info "Installing feeder service..."
    if "$FEEDER_SCRIPT" install; then
        log_success "Feeder service installed"
    else
        log_error "Failed to install feeder service"
        exit 1
    fi
    
    # Install watcher service
    log_info "Installing watcher service..."
    if "$WATCHER_SCRIPT" install; then
        log_success "Watcher service installed"
    else
        log_error "Failed to install watcher service"
        exit 1
    fi
    
    # Create systemd timer for daily feeder runs
    create_daily_timer
    
    log_success "Calibre System installed successfully!"
    log_info "Components:"
    log_info "  - Feeder: Discovers and hardlinks new books"
    log_info "  - Watcher: Processes books from upload directory"
    log_info "  - Timer: Daily feeder runs at 2 AM"
    log_info ""
    log_info "Usage:"
    log_info "  calibreSystem.sh sync-now  - Run feeder immediately"
    log_info "  calibreSystem.sh status    - Check system status"
    log_info "  calibreSystem.sh stats     - Show processing statistics"
}

# Create daily timer for feeder
create_daily_timer() {
    local timer_file="/etc/systemd/system/${FEEDER_SERVICE}.timer"
    
    log_info "Creating daily timer for feeder service..."
    
    cat > "$timer_file" << EOF
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
        log_success "Daily timer created: $timer_file"
        systemctl daemon-reload
        systemctl enable "${FEEDER_SERVICE}.timer"
        log_info "Daily timer enabled (runs at 2 AM with 5-minute random delay)"
    else
        log_error "Failed to create daily timer"
        exit 1
    fi
}

# Uninstall the complete system
uninstall_system() {
    log_info "Uninstalling Calibre System..."
    
    # Stop and disable timer
    systemctl stop "${FEEDER_SERVICE}.timer" 2>/dev/null
    systemctl disable "${FEEDER_SERVICE}.timer" 2>/dev/null
    rm -f "/etc/systemd/system/${FEEDER_SERVICE}.timer"
    
    # Uninstall feeder service
    log_info "Uninstalling feeder service..."
    if [[ -f "$FEEDER_SCRIPT" ]]; then
        "$FEEDER_SCRIPT" uninstall
    fi
    
    # Uninstall watcher service
    log_info "Uninstalling watcher service..."
    if [[ -f "$WATCHER_SCRIPT" ]]; then
        "$WATCHER_SCRIPT" uninstall
    fi
    
    # Reload systemd
    systemctl daemon-reload
    
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

# Start the system
start_system() {
    log_info "Starting Calibre System..."
    
    # Start watcher service (continuous)
    if "$WATCHER_SCRIPT" start; then
        log_success "Watcher service started"
    else
        log_error "Failed to start watcher service"
        exit 1
    fi
    
    # Start timer (scheduled)
    if systemctl start "${FEEDER_SERVICE}.timer"; then
        log_success "Daily timer started"
    else
        log_warning "Failed to start daily timer"
    fi
    
    log_success "Calibre System started"
}

# Stop the system
stop_system() {
    log_info "Stopping Calibre System..."
    
    # Stop watcher service
    if "$WATCHER_SCRIPT" stop; then
        log_success "Watcher service stopped"
    else
        log_warning "Failed to stop watcher service"
    fi
    
    # Stop timer
    if systemctl stop "${FEEDER_SERVICE}.timer"; then
        log_success "Daily timer stopped"
    else
        log_warning "Failed to stop daily timer"
    fi
    
    log_success "Calibre System stopped"
}

# Restart the system
restart_system() {
    log_info "Restarting Calibre System..."
    stop_system
    sleep 2
    start_system
}

# Run immediate sync
sync_now() {
    log_info "Running immediate sync (feeder + watcher)..."
    
    # Run feeder to discover and hardlink new books
    if "$FEEDER_SCRIPT" sync-now; then
        log_success "Feeder sync completed"
    else
        log_error "Feeder sync failed"
        exit 1
    fi
    
    # The watcher service will automatically process any new files
    log_info "Watcher service will automatically process new files"
    log_info "Check status with: calibreSystem.sh status"
}

# Show processing statistics
show_stats() {
    log_info "Calibre System Statistics:"
    echo ""
    
    if [[ -f "$FEEDER_SCRIPT" ]]; then
        log_info "=== Feeder Statistics ==="
        "$FEEDER_SCRIPT" stats
        echo ""
    fi
    
    if [[ -f "$WATCHER_SCRIPT" ]]; then
        log_info "=== Watcher Status ==="
        "$WATCHER_SCRIPT" status
    fi
}

# Update the system
update_system() {
    log_info "Updating Calibre System..."
    
    # Update feeder service
    if [[ -f "$FEEDER_SCRIPT" ]]; then
        log_info "Updating feeder service..."
        "$FEEDER_SCRIPT" force-update
    fi
    
    # Update watcher service
    if [[ -f "$WATCHER_SCRIPT" ]]; then
        log_info "Updating watcher service..."
        "$WATCHER_SCRIPT" force-update
    fi
    
    log_success "Calibre System updated"
}

# Show usage information
show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  install   - Install the complete Calibre System (feeder + watcher + timer)"
    echo "  uninstall - Remove the complete Calibre System"
    echo "  status    - Show system status for all components"
    echo "  start     - Start all system components"
    echo "  stop      - Stop all system components"
    echo "  restart   - Restart all system components"
    echo "  sync-now  - Run immediate sync (discover and process books)"
    echo "  stats     - Show processing statistics"
    echo "  update    - Update all system components"
    echo "  help      - Show this help message"
    echo ""
    echo "System Architecture:"
    echo "  Feeder Service:"
    echo "    - Crawls /mnt/nas/books for new files"
    echo "    - Validates file types"
    echo "    - Creates hardlinks to upload directory"
    echo "    - Tracks processed files by hash"
    echo "    - Runs daily at 2 AM (with random delay)"
    echo ""
    echo "  Watcher Service:"
    echo "    - Monitors upload directory continuously"
    echo "    - Processes books in batches"
    echo "    - Adds to Calibre library"
    echo "    - Removes processed files"
    echo ""
    echo "  Combined Workflow:"
    echo "    1. Feeder discovers new books → hardlinks to upload"
    echo "    2. Watcher processes upload directory → adds to library"
    echo "    3. Process repeats daily or on-demand"
}

# Main script logic
main() {
    # Check if running as root
    check_root
    
    # Get command (default to help)
    local command="${1:-help}"
    
    case "$command" in
        install)
            install_system
            ;;
        uninstall)
            uninstall_system
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
        stats)
            show_stats
            ;;
        update)
            update_system
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
