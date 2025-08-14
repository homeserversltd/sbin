#!/bin/bash

# Hard drive testing script
# Performs comprehensive testing including badblocks and filesystem checks
# Handles both regular and LUKS-encrypted devices

set -e  # Exit on error

RESULTS_FILE="/var/harddriveTest.txt"
TEMP_DIR="/tmp/hdtest"

# Function to log messages with timestamps
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [HDTEST] $1" | sudo tee -a "$RESULTS_FILE" > /dev/null
}

# Function to check if a device exists
check_device() {
    local device=$1
    if [[ ! -b "$device" ]]; then
        log_message "ERROR: Device $device does not exist or is not a block device"
        exit 1
    fi
}

# Function to check if device is mounted
check_if_mounted() {
    local device=$1
    if mountpoint -q "$device" || grep -q "^$device " /proc/mounts; then
        log_message "ERROR: Device $device is mounted. Please unmount it first."
        exit 1
    fi
}

# Function to get LUKS mapper device
get_luks_mapper() {
    local device=$1
    # Check if device is LUKS
    if cryptsetup isLuks "$device" 2>/dev/null; then
        # Find unlocked mapper device using lsblk
        local mapper_path
        mapper_path=$(lsblk -rno NAME,TYPE "$device" | awk '$2=="crypt"{print $1}')
        if [[ -n "$mapper_path" ]]; then
            # Prepend /dev/mapper/ if not already present
            if [[ "$mapper_path" != /dev/mapper/* ]]; then
                mapper_path="/dev/mapper/$mapper_path"
            fi
            # Check if the mapper device exists and is a block device
            if [[ -b "$mapper_path" ]]; then
                echo "$mapper_path"
                return 0
            fi
        fi
        log_message "Device $device is LUKS encrypted but not unlocked (no valid mapper found)"
        exit 1
    fi
    echo "$device"
}

# Function to run badblocks test
run_badblocks() {
    local device=$1
    local pid_file="/tmp/badblocks_${RANDOM}.pid"
    
    log_message "Starting badblocks scan (this step takes the longest)..."
    
    # Start badblocks in background and capture PID
    badblocks -sv "$device" | sudo tee -a "$RESULTS_FILE" 2>&1 & 
    local bb_pid=$!
    echo $bb_pid > "$pid_file"
    
    # Monitor progress
    while kill -0 $bb_pid 2>/dev/null; do
        echo -n "."
        sleep 5
    done
    echo
    
    wait $bb_pid
    local result=$?
    rm -f "$pid_file"
    
    if [[ $result -eq 0 ]]; then
        log_message "Badblocks scan completed"
        return 0
    else
        log_message "Badblocks scan failed"
        return 1
    fi
}

# Function to run filesystem check
run_fsck() {
    local device=$1
    local fs_type
    
    fs_type=$(lsblk -no FSTYPE "$device" | head -n1)
    log_message "Detected filesystem: $fs_type"
    
    # If crypto_LUKS, try to resolve the mapper and check its FS type
    if [[ "$fs_type" == "crypto_LUKS" ]]; then
        local mapper_device
        mapper_device=$(get_luks_mapper "$device")
        if [[ "$mapper_device" != "$device" ]]; then
            fs_type=$(lsblk -no FSTYPE "$mapper_device" | head -n1)
            log_message "Detected LUKS-mapped filesystem: $fs_type"
            device="$mapper_device"
        fi
    fi
    
    case "$fs_type" in
        "xfs")
            log_message "Running XFS check..."
            xfs_repair -n "$device" | sudo tee -a "$RESULTS_FILE" > /dev/null
            ;;
        "ext4"|"ext3"|"ext2")
            log_message "Running e2fsck..."
            e2fsck -fn "$device" | sudo tee -a "$RESULTS_FILE" > /dev/null
            ;;
        *)
            log_message "Unsupported filesystem type: $fs_type"
            return 1
            ;;
    esac
    
    if [[ $? -eq 0 ]]; then
        log_message "Filesystem check passed"
        return 0
    else
        log_message "Filesystem check failed"
        return 1
    fi
}

# Main function
main() {
    if [[ $# -lt 1 ]]; then
        echo "Usage: $0 <device> [full|quick|ultimate]"
        echo "Examples:"
        echo "  Regular device:     $0 /dev/sdb full"
        echo "  LUKS device:        $0 /dev/sdb full        # Will auto-detect if unlocked"
        echo "  Direct mapper:      $0 /dev/mapper/sdb_crypt full"
        echo "  Ultimate (destructive): $0 /dev/sdb ultimate"
        exit 1
    fi
    
    local device="$1"
    local test_type="${2:-full}"
    local test_device
    
    # Initialize results file
    {
        echo "# Hard Drive Test Results"
        echo "# Device: $device"
        echo "# Test Type: $test_type"
        echo "# Started: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "#$(printf '=%.0s' {1..50})"
    } | sudo tee "$RESULTS_FILE" > /dev/null
    
    # Check device
    check_device "$device"
    check_if_mounted "$device"
    
    # Get LUKS mapper if needed
    test_device=$(get_luks_mapper "$device")
    log_message "Using device: $test_device"
    
    # Get device info
    lsblk -f "$test_device" | sudo tee -a "$RESULTS_FILE" > /dev/null
    
    # Run tests based on type
    local badblocks_result=0
    local fsck_result=0
    
    if [[ "$test_type" == "ultimate" ]]; then
        log_message "[STEP] ULTIMATE: Starting destructive test sequence (badblocks write)"
        log_message "[STEP] ULTIMATE: Running destructive badblocks (write-mode, single pass)"
        badblocks -wsv "$test_device" | sudo tee -a "$RESULTS_FILE" 2>&1
        badblocks_result=${PIPESTATUS[0]}
        # No filesystem check or recreation
    elif [[ "$test_type" == "full" ]]; then
        log_message "[STEP] FULL: Starting badblocks scan (read-only)"
        run_badblocks "$test_device" || badblocks_result=1
        log_message "[STEP] FULL: Running filesystem check"
        run_fsck "$test_device" || fsck_result=1
    else
        log_message "[STEP] QUICK: Running filesystem check"
        run_fsck "$test_device" || fsck_result=1
    fi
    
    # Generate summary
    {
        echo
        echo "Test Summary"
        [[ "$test_type" == "full" ]] && echo "Badblocks Test: $([[ $badblocks_result -eq 0 ]] && echo "PASSED" || echo "FAILED")"
        echo "Filesystem Check: $([[ $fsck_result -eq 0 ]] && echo "PASSED" || echo "FAILED")"
    } | sudo tee -a "$RESULTS_FILE" > /dev/null
    
    log_message "Test completed"
}

# Run main with all arguments
main "$@" 