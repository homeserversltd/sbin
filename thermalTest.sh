#!/bin/bash

# Thermal Abuse Test Script
# Pins CPU at 90% for 10 minutes and monitors all temperature sensors
# Fails if any component exceeds 100°C

set -e

FAILURE_LOG="/var/www/homeserver/thermalFail.txt"
TEMP_LIMIT=100  # °C - Hard failure limit
TEST_DURATION=600  # 10 minutes in seconds
CPU_LOAD=90  # Target CPU percentage
MONITOR_INTERVAL=5  # Check temperatures every 5 seconds

# Function to log with timestamp (only to console during normal operation)
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [THERMAL] $1"
}

# Function to log failure with timestamp to failure log
log_failure() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [THERMAL] $1" | sudo tee -a "$FAILURE_LOG" > /dev/null
}

# Function to get all temperature readings
get_temperatures() {
    local temps=""
    local max_temp=0
    local sensor_name=""
    
    # Read CPU core temperatures
    if [[ -d "/sys/class/thermal" ]]; then
        for thermal_zone in /sys/class/thermal/thermal_zone*; do
            if [[ -f "$thermal_zone/temp" ]]; then
                local temp_raw=$(cat "$thermal_zone/temp" 2>/dev/null || echo "0")
                local temp_celsius=$((temp_raw / 1000))
                local zone_type=$(cat "$thermal_zone/type" 2>/dev/null || echo "unknown")
                
                temps="$temps $zone_type:${temp_celsius}°C"
                
                if [[ $temp_celsius -gt $max_temp ]]; then
                    max_temp=$temp_celsius
                    sensor_name="$zone_type"
                fi
            fi
        done
    fi
    
    # Read ACPI thermal zones if available
    if command -v sensors >/dev/null 2>&1; then
        local sensor_output=$(sensors 2>/dev/null | grep -E "°C|Core" | head -20)
        if [[ -n "$sensor_output" ]]; then
            while IFS= read -r line; do
                if [[ "$line" =~ ([0-9]+\.[0-9]+)°C ]]; then
                    local temp_float="${BASH_REMATCH[1]}"
                    local temp_int=${temp_float%.*}
                    
                    if [[ $temp_int -gt $max_temp ]]; then
                        max_temp=$temp_int
                        sensor_name=$(echo "$line" | cut -d':' -f1 | xargs)
                    fi
                fi
            done <<< "$sensor_output"
        fi
    fi
    
    # Return max temperature and sensor info
    echo "$max_temp|$sensor_name|$temps"
}

# Function to start CPU stress test
start_cpu_stress() {
    local num_cores=$(nproc)
    local stress_processes=$((num_cores * CPU_LOAD / 100))
    
    # Ensure at least one process
    if [[ $stress_processes -lt 1 ]]; then
        stress_processes=1
    fi
    
    log_message "Starting CPU stress test: $stress_processes processes on $num_cores cores (target: ${CPU_LOAD}%)"
    
    # Use stress-ng if available, fallback to dd/yes
    if command -v stress-ng >/dev/null 2>&1; then
        stress-ng --cpu $stress_processes --timeout ${TEST_DURATION}s &
        echo $!
    elif command -v stress >/dev/null 2>&1; then
        stress --cpu $stress_processes --timeout ${TEST_DURATION}s &
        echo $!
    else
        # Fallback: use yes command piped to /dev/null
        log_message "Using fallback stress method (yes commands)"
        local pids=""
        for ((i=1; i<=stress_processes; i++)); do
            yes > /dev/null &
            pids="$pids $!"
        done
        echo "$pids"
    fi
}

# Function to stop stress processes
stop_stress() {
    local stress_pids="$1"
    
    log_message "Stopping stress processes..."
    
    # Kill stress processes
    for pid in $stress_pids; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    
    # Kill any remaining stress processes
    pkill -f "stress" 2>/dev/null || true
    pkill -f "yes" 2>/dev/null || true
    
    # Wait a moment for cleanup
    sleep 2
}

# Function to handle thermal failure
thermal_failure() {
    local temp="$1"
    local sensor="$2"
    
    log_message "THERMAL FAILURE: Temperature limit exceeded! ${sensor}: ${temp}°C (limit: ${TEMP_LIMIT}°C)"
    log_failure "THERMAL FAILURE: Temperature limit exceeded! ${sensor}: ${temp}°C (limit: ${TEMP_LIMIT}°C)"
    log_failure "Test started: $(date '+%Y-%m-%d %H:%M:%S')"
    log_failure "Failed after: $(($(date +%s) - start_time)) seconds"
    log_failure "System thermal management insufficient for sustained load"
    
    # Stop stress test immediately
    stop_stress "$stress_pids"
    
    log_message "Thermal test FAILED - stopping stress test"
    log_failure "Thermal test terminated due to excessive temperature"
    
    exit 1
}

# Main test function
main() {
    
    log_message "Starting thermal abuse test"
    
    # Get baseline temperatures
    local baseline_info=$(get_temperatures)
    local baseline_temp=$(echo "$baseline_info" | cut -d'|' -f1)
    local baseline_sensors=$(echo "$baseline_info" | cut -d'|' -f3)
    
    log_message "Baseline temperature: ${baseline_temp}°C"
    log_message "Available sensors: $baseline_sensors"
    
    # Start CPU stress test
    local stress_pids=$(start_cpu_stress)
    log_message "Stress test PID(s): $stress_pids"
    
    # Monitor temperatures during test
    local start_time=$(date +%s)
    local test_passed=true
    local max_recorded_temp=0
    local max_temp_sensor=""
    
    log_message "Beginning temperature monitoring (${MONITOR_INTERVAL}s intervals)"
    
    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        # Check if test duration completed
        if [[ $elapsed -ge $TEST_DURATION ]]; then
            log_message "Test duration completed (${TEST_DURATION}s)"
            break
        fi
        
        # Get current temperatures
        local temp_info=$(get_temperatures)
        local current_max_temp=$(echo "$temp_info" | cut -d'|' -f1)
        local current_sensor=$(echo "$temp_info" | cut -d'|' -f2)
        local all_temps=$(echo "$temp_info" | cut -d'|' -f3)
        
        # Log current state
        local remaining=$((TEST_DURATION - elapsed))
        log_message "T+${elapsed}s (${remaining}s remaining): Max temp ${current_max_temp}°C ($current_sensor) - $all_temps"
        
        # Track maximum temperature
        if [[ $current_max_temp -gt $max_recorded_temp ]]; then
            max_recorded_temp=$current_max_temp
            max_temp_sensor="$current_sensor"
        fi
        
        # Check temperature limit
        if [[ $current_max_temp -gt $TEMP_LIMIT ]]; then
            test_passed=false
            thermal_failure "$current_max_temp" "$current_sensor"
        fi
        
        sleep $MONITOR_INTERVAL
    done
    
    # Stop stress test
    stop_stress "$stress_pids"
    
    # Get final temperatures
    sleep 5  # Let system settle
    local final_info=$(get_temperatures)
    local final_temp=$(echo "$final_info" | cut -d'|' -f1)
    
    # Generate test summary
    if [[ $test_passed == true ]]; then
        log_message "Thermal abuse test PASSED"
        log_message "Baseline: ${baseline_temp}°C | Maximum: ${max_recorded_temp}°C ($max_temp_sensor) | Final: ${final_temp}°C"
        log_message "Duration: ${TEST_DURATION}s | Limit: ${TEMP_LIMIT}°C"
        exit 0
    else
        log_message "Thermal abuse test FAILED - Temperature exceeded limit"
        exit 1
    fi
}

# Check if running as root or with sudo
if [[ $EUID -ne 0 ]] && [[ -z "$SUDO_USER" ]]; then
    echo "Error: This script must be run with sudo privileges"
    echo "Usage: sudo $0"
    exit 1
fi

# Run main function
main "$@"
