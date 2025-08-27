#!/bin/bash
# data-cleanup.sh - Automated data lifecycle management script
# Usage: ./data-cleanup.sh [--dry-run] [--config /path/to/config]

set -euo pipefail

# Default configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DRY_RUN=false
CONFIG_FILE="${PROJECT_ROOT}/config/data-retention.yml"

# Data retention policies (days)
MEMORY_DUMPS_RETENTION=7
MEMORY_DUMPS_ARCHIVE_AFTER=1
SESSIONS_RETENTION=30
SESSIONS_ARCHIVE_AFTER=7
LOGS_RETENTION=14
LOGS_ARCHIVE_AFTER=3
TEMP_FILES_RETENTION=1

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--config /path/to/config]"
            echo "  --dry-run    Show what would be done without making changes"
            echo "  --config     Use custom configuration file"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Load configuration if exists
if [[ -f "$CONFIG_FILE" ]]; then
    echo "Loading configuration from: $CONFIG_FILE"
    # In a real implementation, you'd parse YAML here
    # For now, we'll use the defaults above
fi

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Execute command with dry-run support
execute() {
    local cmd="$*"
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Would execute: $cmd"
    else
        log "Executing: $cmd"
        eval "$cmd"
    fi
}

# Create necessary directories
ensure_directories() {
    local dirs=(
        "${PROJECT_ROOT}/data/archives"
        "${PROJECT_ROOT}/data/archives/memory_dumps"
        "${PROJECT_ROOT}/data/archives/sessions"
        "${PROJECT_ROOT}/data/archives/logs"
        "${PROJECT_ROOT}/data/temp"
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            execute "mkdir -p '$dir'"
        fi
    done
}

# Clean up memory dumps
cleanup_memory_dumps() {
    local data_dir="${PROJECT_ROOT}/data/outputs/memory_dumps"
    local archive_dir="${PROJECT_ROOT}/data/archives/memory_dumps"
    
    if [[ ! -d "$data_dir" ]]; then
        log "Memory dumps directory not found: $data_dir"
        return
    fi
    
    log "Processing memory dumps in: $data_dir"
    
    # Archive old files (older than MEMORY_DUMPS_ARCHIVE_AFTER days)
    local archive_date=$(date -d "${MEMORY_DUMPS_ARCHIVE_AFTER} days ago" '+%Y%m%d')
    local archive_file="${archive_dir}/memory_dumps_${archive_date}_$(date +%H%M%S).tar.gz"
    
    local files_to_archive
    files_to_archive=$(find "$data_dir" -name "snapshot_*.json" -type f -mtime +"$MEMORY_DUMPS_ARCHIVE_AFTER" 2>/dev/null | head -1000 || true)
    
    if [[ -n "$files_to_archive" ]]; then
        local count=$(echo "$files_to_archive" | wc -l)
        log "Archiving $count memory dump files older than $MEMORY_DUMPS_ARCHIVE_AFTER days"
        
        if [[ "$DRY_RUN" == "false" ]]; then
            echo "$files_to_archive" | tar -czf "$archive_file" -T -
            echo "$files_to_archive" | xargs rm -f
        else
            echo "[DRY-RUN] Would archive $count files to: $archive_file"
        fi
    fi
    
    # Remove very old files (older than MEMORY_DUMPS_RETENTION days)
    local old_files
    old_files=$(find "$data_dir" -name "snapshot_*.json" -type f -mtime +"$MEMORY_DUMPS_RETENTION" 2>/dev/null || true)
    
    if [[ -n "$old_files" ]]; then
        local count=$(echo "$old_files" | wc -l)
        log "Removing $count memory dump files older than $MEMORY_DUMPS_RETENTION days"
        execute "echo '$old_files' | xargs rm -f"
    fi
}

# Clean up session data
cleanup_sessions() {
    local data_dir="${PROJECT_ROOT}/data/outputs/sessions"
    local archive_dir="${PROJECT_ROOT}/data/archives/sessions"
    
    if [[ ! -d "$data_dir" ]]; then
        log "Sessions directory not found: $data_dir"
        return
    fi
    
    log "Processing sessions in: $data_dir"
    
    # Archive old sessions (older than SESSIONS_ARCHIVE_AFTER days)
    local archive_date=$(date -d "${SESSIONS_ARCHIVE_AFTER} days ago" '+%Y%m%d')
    local files_to_archive
    files_to_archive=$(find "$data_dir" -name "*.json" -type f -mtime +"$SESSIONS_ARCHIVE_AFTER" 2>/dev/null || true)
    
    if [[ -n "$files_to_archive" ]]; then
        local count=$(echo "$files_to_archive" | wc -l)
        log "Archiving $count session files older than $SESSIONS_ARCHIVE_AFTER days"
        
        local archive_file="${archive_dir}/sessions_${archive_date}_$(date +%H%M%S).tar.gz"
        if [[ "$DRY_RUN" == "false" ]]; then
            echo "$files_to_archive" | tar -czf "$archive_file" -T -
            echo "$files_to_archive" | xargs gzip
            find "$data_dir" -name "*.json.gz" -mtime +"$SESSIONS_ARCHIVE_AFTER" -exec mv {} "$archive_dir/" \;
        else
            echo "[DRY-RUN] Would archive $count files to: $archive_file"
        fi
    fi
    
    # Remove old sessions (older than SESSIONS_RETENTION days)
    execute "find '$data_dir' -name '*.json' -type f -mtime +$SESSIONS_RETENTION -delete"
    execute "find '$data_dir' -name '*.json.gz' -type f -mtime +$SESSIONS_RETENTION -delete"
}

# Clean up logs
cleanup_logs() {
    local data_dir="${PROJECT_ROOT}/data/outputs/logs"
    
    if [[ ! -d "$data_dir" ]]; then
        log "Logs directory not found: $data_dir"
        return
    fi
    
    log "Processing logs in: $data_dir"
    
    # Compress old logs (older than LOGS_ARCHIVE_AFTER days)
    execute "find '$data_dir' -name '*.log' -type f -mtime +$LOGS_ARCHIVE_AFTER -exec gzip {} \\;"
    
    # Remove old compressed logs (older than LOGS_RETENTION days)
    execute "find '$data_dir' -name '*.log.gz' -type f -mtime +$LOGS_RETENTION -delete"
    
    # Remove old debug logs (shorter retention)
    execute "find '$data_dir' -name 'debug-*.log' -type f -mtime +7 -delete"
    execute "find '$data_dir' -name 'debug-*.log.gz' -type f -mtime +7 -delete"
}

# Clean up temporary files
cleanup_temp_files() {
    local temp_dirs=(
        "${PROJECT_ROOT}/data/temp"
        "${PROJECT_ROOT}/data/outputs/tmp"
        "/tmp/mcp-analysis-*"
    )
    
    log "Cleaning up temporary files"
    
    for temp_dir in "${temp_dirs[@]}"; do
        if [[ -d "$temp_dir" ]] || [[ "$temp_dir" == "/tmp/mcp-analysis-*" ]]; then
            execute "find $temp_dir -type f -mtime +$TEMP_FILES_RETENTION -delete 2>/dev/null || true"
            execute "find $temp_dir -type d -empty -delete 2>/dev/null || true"
        fi
    done
}

# Clean up Docker resources (with dry-run support)
cleanup_docker_resources() {
    if ! command -v docker &> /dev/null; then
        log "Docker not found, skipping Docker cleanup"
        return
    fi
    
    log "Cleaning up Docker resources"
    
    # Remove stopped containers
    local stopped_containers
    stopped_containers=$(docker ps -aq --filter "status=exited" 2>/dev/null || true)
    if [[ -n "$stopped_containers" ]]; then
        execute "docker rm $stopped_containers"
    fi
    
    # Remove dangling images
    local dangling_images
    dangling_images=$(docker images -qf "dangling=true" 2>/dev/null || true)
    if [[ -n "$dangling_images" ]]; then
        execute "docker rmi $dangling_images"
    fi
    
    # Remove unused volumes (be careful with this)
    if [[ "$DRY_RUN" == "false" ]]; then
        docker volume prune -f >/dev/null 2>&1 || true
    else
        echo "[DRY-RUN] Would run: docker volume prune -f"
    fi
}

# Generate cleanup report
generate_report() {
    local report_file="${PROJECT_ROOT}/data/outputs/cleanup_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "Data Cleanup Report - $(date)"
        echo "=================================="
        echo
        echo "Configuration:"
        echo "- Memory dumps retention: $MEMORY_DUMPS_RETENTION days"
        echo "- Sessions retention: $SESSIONS_RETENTION days"
        echo "- Logs retention: $LOGS_RETENTION days"
        echo "- Temp files retention: $TEMP_FILES_RETENTION days"
        echo "- Dry run: $DRY_RUN"
        echo
        echo "Directory sizes after cleanup:"
        
        local dirs=(
            "${PROJECT_ROOT}/data/outputs/memory_dumps"
            "${PROJECT_ROOT}/data/outputs/sessions"
            "${PROJECT_ROOT}/data/outputs/logs"
            "${PROJECT_ROOT}/data/archives"
        )
        
        for dir in "${dirs[@]}"; do
            if [[ -d "$dir" ]]; then
                echo "- $(basename "$dir"): $(du -sh "$dir" 2>/dev/null | cut -f1)"
            fi
        done
        
    } > "$report_file"
    
    log "Cleanup report generated: $report_file"
    
    if [[ "$DRY_RUN" == "false" ]]; then
        cat "$report_file"
    fi
}

# Main execution
main() {
    log "Starting data cleanup process"
    log "Project root: $PROJECT_ROOT"
    log "Dry run mode: $DRY_RUN"
    
    ensure_directories
    cleanup_memory_dumps
    cleanup_sessions
    cleanup_logs
    cleanup_temp_files
    cleanup_docker_resources
    generate_report
    
    log "Data cleanup process completed"
}

# Run main function
main "$@"