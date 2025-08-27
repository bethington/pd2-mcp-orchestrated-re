#!/bin/bash
# schedule-cleanup.sh - Setup automated data cleanup via cron
# Usage: ./schedule-cleanup.sh [install|uninstall|status]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CLEANUP_SCRIPT="${SCRIPT_DIR}/data-cleanup.sh"
CRON_COMMENT="# MCP Platform Data Cleanup"

# Cron entries
DAILY_CRON="0 2 * * * $CLEANUP_SCRIPT >> /var/log/mcp-cleanup.log 2>&1 $CRON_COMMENT-daily"
WEEKLY_CRON="0 3 * * 0 $CLEANUP_SCRIPT --config ${PROJECT_ROOT}/config/data-retention.yml >> /var/log/mcp-cleanup.log 2>&1 $CRON_COMMENT-weekly"

usage() {
    cat << EOF
Usage: $0 [install|uninstall|status]

Commands:
    install     Install cleanup cron jobs
    uninstall   Remove cleanup cron jobs
    status      Show current cron job status
    
Options:
    -h, --help  Show this help message
EOF
}

install_cron() {
    echo "Installing data cleanup cron jobs..."
    
    # Create log directory
    sudo mkdir -p /var/log
    sudo touch /var/log/mcp-cleanup.log
    sudo chmod 644 /var/log/mcp-cleanup.log
    
    # Backup current crontab
    crontab -l > /tmp/crontab.backup 2>/dev/null || true
    
    # Remove existing MCP cleanup entries
    crontab -l 2>/dev/null | grep -v "$CRON_COMMENT" > /tmp/crontab.new || true
    
    # Add new entries
    echo "$DAILY_CRON" >> /tmp/crontab.new
    echo "$WEEKLY_CRON" >> /tmp/crontab.new
    
    # Install new crontab
    crontab /tmp/crontab.new
    
    # Cleanup temp files
    rm -f /tmp/crontab.new
    
    echo "✅ Cron jobs installed successfully"
    echo "   Daily cleanup: 2:00 AM"
    echo "   Weekly cleanup: 3:00 AM on Sundays"
    echo "   Logs: /var/log/mcp-cleanup.log"
}

uninstall_cron() {
    echo "Removing data cleanup cron jobs..."
    
    # Backup current crontab
    crontab -l > /tmp/crontab.backup 2>/dev/null || true
    
    # Remove MCP cleanup entries
    crontab -l 2>/dev/null | grep -v "$CRON_COMMENT" > /tmp/crontab.new || true
    
    # Install cleaned crontab
    crontab /tmp/crontab.new
    
    # Cleanup temp files
    rm -f /tmp/crontab.new
    
    echo "✅ Cron jobs removed successfully"
}

show_status() {
    echo "Current MCP data cleanup cron jobs:"
    echo "=================================="
    
    if crontab -l 2>/dev/null | grep -q "$CRON_COMMENT"; then
        crontab -l 2>/dev/null | grep "$CRON_COMMENT"
        echo
        echo "Status: ✅ Installed"
        
        # Show log file info
        if [[ -f /var/log/mcp-cleanup.log ]]; then
            echo "Log file: /var/log/mcp-cleanup.log"
            echo "Log size: $(du -h /var/log/mcp-cleanup.log 2>/dev/null | cut -f1)"
            echo "Last 5 lines:"
            tail -5 /var/log/mcp-cleanup.log 2>/dev/null || echo "  (empty)"
        else
            echo "Log file: Not found"
        fi
    else
        echo "Status: ❌ Not installed"
    fi
    
    echo
    echo "Next cron runs:"
    # This would show next cron run times (implementation depends on system)
    echo "  Use 'crontab -l' to see current schedule"
}

# Check if cleanup script exists
if [[ ! -f "$CLEANUP_SCRIPT" ]]; then
    echo "Error: Cleanup script not found: $CLEANUP_SCRIPT"
    exit 1
fi

# Make cleanup script executable
chmod +x "$CLEANUP_SCRIPT"

# Parse command line arguments
case "${1:-status}" in
    install)
        install_cron
        ;;
    uninstall)
        uninstall_cron
        ;;
    status)
        show_status
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        echo "Error: Unknown command: $1"
        echo
        usage
        exit 1
        ;;
esac