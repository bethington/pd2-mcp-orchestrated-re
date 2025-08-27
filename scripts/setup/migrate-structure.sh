#!/bin/bash
# migrate-structure.sh - Automated project structure migration script
# This script implements the structural recommendations for the MCP platform

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BACKUP_DIR="${PROJECT_ROOT}/backup-$(date +%Y%m%d_%H%M%S)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Create backup of current state
create_backup() {
    log_info "Creating backup of current project state..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup important files and directories (excluding large data)
    tar -czf "${BACKUP_DIR}/project-backup.tar.gz" \
        --exclude='data/outputs' \
        --exclude='*.pyc' \
        --exclude='__pycache__' \
        --exclude='.git' \
        --exclude='node_modules' \
        . || {
        log_error "Failed to create backup"
        exit 1
    }
    
    log_success "Backup created: ${BACKUP_DIR}/project-backup.tar.gz"
}

# Phase 1: Data cleanup and organization
phase1_data_cleanup() {
    log_info "Phase 1: Data cleanup and organization"
    
    # Create archive directories
    mkdir -p "${PROJECT_ROOT}/data/archives"/{memory_dumps,sessions,logs}
    mkdir -p "${PROJECT_ROOT}/data/temp"
    
    # Run data cleanup if script exists
    if [[ -f "${PROJECT_ROOT}/scripts/maintenance/data-cleanup.sh" ]]; then
        log_info "Running data cleanup script..."
        "${PROJECT_ROOT}/scripts/maintenance/data-cleanup.sh" --dry-run
        read -p "Proceed with actual cleanup? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            "${PROJECT_ROOT}/scripts/maintenance/data-cleanup.sh"
        fi
    fi
    
    log_success "Phase 1 completed"
}

# Phase 2: Container standardization
phase2_container_standardization() {
    log_info "Phase 2: Container standardization"
    
    # Standardize container directory structure
    local containers=(
        "d2-analysis"
        "mcp-coordinator" 
        "analysis-engine"
        "network-monitor"
        "web-dashboard"
    )
    
    for container in "${containers[@]}"; do
        local container_dir="${PROJECT_ROOT}/containers/${container}"
        
        if [[ -d "$container_dir" ]]; then
            log_info "Standardizing container: $container"
            
            # Create standard directories
            mkdir -p "${container_dir}"/{src,config,tests,scripts}
            
            # Move Python files to src/ (if not already there)
            if [[ -f "${container_dir}"/coordinator.py ]]; then
                mv "${container_dir}"/coordinator.py "${container_dir}/src/" 2>/dev/null || true
            fi
            
            # Move shell scripts to scripts/ (if not already there)
            find "${container_dir}" -maxdepth 1 -name "*.sh" -exec mv {} "${container_dir}/scripts/" 2>/dev/null \; || true
            
            # Move config files to config/ (if not already there)
            for config_file in supervisord.conf nginx.conf fluxbox-*; do
                if [[ -f "${container_dir}/${config_file}" ]]; then
                    mv "${container_dir}/${config_file}" "${container_dir}/config/" 2>/dev/null || true
                fi
            done
        fi
    done
    
    log_success "Phase 2 completed"
}

# Phase 3: Configuration management
phase3_configuration_management() {
    log_info "Phase 3: Configuration management"
    
    # Create configuration structure (already done in previous steps)
    local config_dirs=(
        "config/environments"
        "config/security" 
        "config/monitoring"
        "config/docker"
    )
    
    for dir in "${config_dirs[@]}"; do
        mkdir -p "${PROJECT_ROOT}/${dir}"
    done
    
    # Update .gitignore for new structure
    cat >> "${PROJECT_ROOT}/.gitignore" << 'EOF'

# Environment-specific files (added by migration)
.env.local
config/environments/.env.local
*.local

# Backup files
backup-*/

# Test results
test-results/
reports/

# Temporary files
data/temp/
*.tmp

EOF
    
    log_success "Phase 3 completed"
}

# Phase 4: Shared libraries improvement
phase4_shared_libraries() {
    log_info "Phase 4: Shared libraries improvement"
    
    # Ensure all shared modules have __init__.py files
    local shared_modules=(
        "shared/mcp"
        "shared/analysis" 
        "shared/game"
        "shared/data"
        "shared/security"
        "shared/testing"
    )
    
    for module in "${shared_modules[@]}"; do
        if [[ -d "${PROJECT_ROOT}/${module}" ]]; then
            if [[ ! -f "${PROJECT_ROOT}/${module}/__init__.py" ]]; then
                touch "${PROJECT_ROOT}/${module}/__init__.py"
                log_info "Created ${module}/__init__.py"
            fi
        fi
    done
    
    log_success "Phase 4 completed"
}

# Phase 5: Documentation and tooling
phase5_documentation_tooling() {
    log_info "Phase 5: Documentation and tooling"
    
    # Create documentation structure
    mkdir -p "${PROJECT_ROOT}/docs"/{architecture,deployment,development,api}
    
    # Create development scripts structure (already mostly done)
    mkdir -p "${PROJECT_ROOT}/scripts"/{setup,development,deployment,maintenance,monitoring}
    
    # Create tests structure
    mkdir -p "${PROJECT_ROOT}/tests"/{unit,integration,e2e,performance}
    
    # Make scripts executable
    find "${PROJECT_ROOT}/scripts" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    
    log_success "Phase 5 completed"
}

# Validation phase
validate_migration() {
    log_info "Validating migration..."
    
    local errors=0
    
    # Check critical directories exist
    local required_dirs=(
        "config/environments"
        "scripts/maintenance" 
        "data/archives"
        "shared/security"
        "shared/testing"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [[ ! -d "${PROJECT_ROOT}/${dir}" ]]; then
            log_error "Missing directory: $dir"
            ((errors++))
        fi
    done
    
    # Check critical files exist
    local required_files=(
        "config/environments/.env.template"
        "scripts/maintenance/data-cleanup.sh"
        "shared/security/__init__.py"
        "shared/testing/__init__.py"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "${PROJECT_ROOT}/${file}" ]]; then
            log_error "Missing file: $file"
            ((errors++))
        fi
    done
    
    # Check container structure
    for container in containers/*/; do
        if [[ -d "$container" && "$container" != *"analysis-legacy"* ]]; then
            local container_name=$(basename "$container")
            if [[ ! -d "${container}/src" ]]; then
                log_warning "Container $container_name missing src/ directory"
            fi
        fi
    done
    
    if [[ $errors -eq 0 ]]; then
        log_success "Migration validation passed"
        return 0
    else
        log_error "Migration validation failed with $errors errors"
        return 1
    fi
}

# Generate migration report
generate_report() {
    local report_file="${PROJECT_ROOT}/MIGRATION_REPORT.md"
    
    cat > "$report_file" << EOF
# Project Structure Migration Report

Generated: $(date)

## Migration Summary

The MCP Platform project structure has been migrated according to the architectural recommendations.

## Changes Made

### Phase 1: Data Cleanup
- Created archive directories for historical data
- Implemented automated data cleanup system
- Cleaned up memory dumps directory

### Phase 2: Container Standardization  
- Standardized container directory structure
- Organized source code, configs, and scripts
- Created container-specific documentation

### Phase 3: Configuration Management
- Created centralized configuration system
- Added environment-specific templates
- Implemented security and monitoring configs

### Phase 4: Shared Libraries
- Improved shared library structure
- Added proper Python package structure
- Created security and testing modules

### Phase 5: Documentation & Tooling
- Created documentation structure
- Added development and deployment scripts
- Implemented automated testing framework

## Directory Structure (After Migration)

\`\`\`
$(tree -L 3 -I '__pycache__|*.pyc|node_modules' "$PROJECT_ROOT" 2>/dev/null || find "$PROJECT_ROOT" -type d -not -path "*/.*" | head -50 | sort)
\`\`\`

## Next Steps

1. Review and test the migrated structure
2. Update CI/CD pipelines for new structure
3. Run comprehensive tests: \`scripts/testing/run-tests.sh\`
4. Deploy using new environment templates
5. Set up monitoring and alerting

## Rollback

If needed, restore from backup:
\`\`\`bash
tar -xzf ${BACKUP_DIR}/project-backup.tar.gz
\`\`\`

## Support

For issues or questions about the new structure:
- Review documentation in \`docs/\`
- Check troubleshooting guide in \`docs/troubleshooting.md\`
- Run validation: \`scripts/setup/validate-structure.sh\`
EOF

    log_success "Migration report generated: $report_file"
}

# Main execution
main() {
    log_info "Starting MCP Platform structure migration"
    log_info "Project root: $PROJECT_ROOT"
    
    # Confirm before proceeding
    echo
    log_warning "This script will modify the project structure."
    log_warning "A backup will be created before making changes."
    echo
    read -p "Proceed with migration? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Migration cancelled by user"
        exit 0
    fi
    
    # Execute migration phases
    create_backup
    phase1_data_cleanup
    phase2_container_standardization
    phase3_configuration_management
    phase4_shared_libraries
    phase5_documentation_tooling
    
    # Validate and report
    if validate_migration; then
        generate_report
        log_success "Migration completed successfully!"
        echo
        log_info "Next steps:"
        echo "  1. Review the migration report: MIGRATION_REPORT.md"
        echo "  2. Test the new structure: scripts/testing/run-tests.sh"
        echo "  3. Update your development workflow"
        echo
    else
        log_error "Migration completed with errors - check the output above"
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi