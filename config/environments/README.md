# Environment Configuration Guide

This directory contains environment templates and configurations for different deployment scenarios.

## Files Overview

| File | Purpose | Usage |
|------|---------|-------|
| `.env.template` | Base template with all variables | Reference for all environments |
| `.env.dev` | Development overrides | Development environment |
| `.env.prod` | Production overrides | Production deployment |
| `.env.test` | Testing overrides | CI/CD and testing |
| `.env.local.template` | Local development template | Copy to `.env.local` |

## Quick Setup

### For Development
```bash
# Use development environment
cp config/environments/.env.dev .env
docker-compose up -d
```

### For Production
```bash
# Use production environment
cp config/environments/.env.prod .env
# Set production secrets in environment or secret manager
export VAULT_JWT_SECRET="your-production-jwt-secret"
export ALERTS_WEBHOOK_URL="your-alerts-webhook"
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### For Testing
```bash
# Use testing environment
cp config/environments/.env.test .env
docker-compose -f docker-compose.test.yml up -d
```

### For Local Development
```bash
# Create local environment file (never commit this)
cp config/environments/.env.local.template .env.local
# Edit .env.local with your preferences
# Use with: docker-compose --env-file .env.local up -d
```

## Environment Variables Reference

### Required Variables
- `SESSION_ID`: Unique session identifier
- `DGRAPH_ENDPOINT`: Database connection URL
- `REDIS_URL`: Cache connection URL
- `MCP_COORDINATOR_URL`: MCP service URL
- `WINEPREFIX`: Wine installation path
- `WINEARCH`: Wine architecture (win32)
- `DISPLAY`: X11 display for GUI

### Security Variables
- `JWT_SECRET_KEY`: JWT signing secret
- `API_RATE_LIMIT`: Rate limiting threshold
- `ENABLE_TLS`: Enable/disable HTTPS
- `CORS_ALLOWED_ORIGINS`: Allowed CORS origins

### Performance Variables
- `WORKER_PROCESSES`: Number of worker processes
- `MAX_MEMORY_USAGE`: Memory limit per container
- `CPU_LIMIT`: CPU limit per container

### Development Variables
- `DEBUG_MODE`: Enable debug logging
- `HOT_RELOAD`: Enable hot reload
- `ENABLE_PROFILING`: Enable performance profiling
- `EXPOSE_DEBUG_PORTS`: Expose debugging ports

## Security Best Practices

1. **Never commit `.env.local`** - Add to `.gitignore`
2. **Use secret management** in production (Vault, AWS Secrets Manager, etc.)
3. **Generate strong secrets** - Use `openssl rand -hex 32`
4. **Rotate secrets regularly** - Implement automated rotation
5. **Use environment-specific networks** - Different subnets per environment

## Validation

Use the environment validation script:
```bash
# Validate current environment
scripts/setup/validate-env.sh

# Validate specific environment
scripts/setup/validate-env.sh config/environments/.env.prod
```

## Examples

### Override specific variables
```bash
# Use dev environment but override session ID
cp config/environments/.env.dev .env
echo "SESSION_ID=my-custom-session" >> .env
```

### Multiple environment files
```bash
# Layer multiple environment files
docker-compose --env-file config/environments/.env.template --env-file config/environments/.env.dev --env-file .env.local up -d
```

### Environment switching
```bash
# Switch between environments
ln -sf config/environments/.env.dev .env     # Development
ln -sf config/environments/.env.prod .env    # Production
ln -sf config/environments/.env.test .env    # Testing
```