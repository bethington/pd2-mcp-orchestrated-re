# Installation Guide

## System Requirements

### Hardware Requirements
- **CPU:** 4+ cores (Intel/AMD x64)
- **RAM:** 8GB minimum, 16GB recommended
- **Storage:** 20GB free space minimum
- **Network:** Broadband internet connection

### Software Requirements
- **Docker:** Version 20.10+ 
- **Docker Compose:** Version 2.0+
- **Git:** For cloning repository
- **VNC Viewer:** For game visualization (optional)

### Supported Operating Systems
- Windows 10/11 (with WSL2)
- Ubuntu 20.04+
- CentOS 8+
- macOS 11+ (Intel/Apple Silicon)

## Pre-Installation Setup

### 1. Install Docker

#### Windows
1. Download Docker Desktop from [docker.com](https://docker.com)
2. Enable WSL2 integration
3. Restart system

#### Linux (Ubuntu/Debian)
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

#### macOS
1. Download Docker Desktop from [docker.com](https://docker.com)
2. Install and start Docker Desktop

### 2. Verify Docker Installation
```bash
docker --version
docker-compose --version
```

## Project Diablo 2 Setup

### Required Game Files
You need a complete Project Diablo 2 installation. The platform expects this directory structure:

```
data/game_files/pd2/
├── Base Game Files (Root Level):
├── D2.LNG              # Language file
├── d2char.mpq          # Base character data
├── d2data.mpq          # Base game data
├── d2exp.mpq           # Expansion pack data
├── d2music.mpq         # Base music files
├── d2sfx.mpq           # Base sound effects
├── d2speech.mpq        # Base voice files
├── d2video.mpq         # Base video files
├── D2xMusic.mpq        # Expansion music
├── d2xtalk.mpq         # Expansion voice files
├── D2xVideo.mpq        # Expansion videos
├── Patch_D2.mpq        # Base game patches
├── Save/               # Save Directory
│
└── ProjectD2/          # Project D2 mod directory
    ├── Executables:
    ├── Game.exe        # Main game executable
    ├── Diablo II.exe   # Original Diablo 2 executable
    ├── PD2Launcher.exe # Project D2 launcher
    ├── D2VidTst.exe    # Video test utility
    │
    ├── Core Game Libraries:
    ├── D2Client.dll    # Client library
    ├── D2Common.dll    # Common game functions
    ├── D2Game.dll      # Core game library
    ├── D2gfx.dll       # Graphics library
    ├── D2Lang.dll      # Language support
    ├── D2Launch.dll    # Game launcher
    ├── D2Net.dll       # Network functionality
    ├── D2sound.dll     # Audio system
    ├── D2Win.dll       # Windows interface
    ├── D2CMP.dll       # Compression library
    ├── D2Multi.dll     # Multiplayer support
    ├── D2MCPClient.dll # Battle.net client
    ├── Fog.dll         # Blizzard utility library
    ├── Storm.dll       # Blizzard core library
    │
    └── [Additional files as per copilot-instructions.md]
```

## Installation Steps

### 1. Clone Repository
```bash
git clone https://github.com/your-repo/pd2-mcp-orchestrated-re.git
cd pd2-mcp-orchestrated-re
```

### 2. Setup Game Files Directory
```bash
make setup-game-files
```

### 3. Copy Game Files
Copy your complete PD2 installation to `data/game_files/pd2/`

**Windows (PowerShell):**
```powershell
Copy-Item -Recurse "C:\Path\To\Your\PD2\Installation\*" "data\game_files\pd2\"
```

**Linux/macOS:**
```bash
cp -r /path/to/your/pd2/installation/* data/game_files/pd2/
```

### 4. Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env  # or your preferred editor
```

### 5. Build Platform
```bash
make build
```

### 6. Start Development Environment
```bash
make dev
```

### 7. Verify Installation
```bash
make health
```

You should see output like:
```
🔍 Checking service health...
D2 Analysis: ✅
MCP Coordinator: ✅ 
Dgraph: ✅
Health check complete
```

## Access and Verification

### 1. Web Dashboard
Open `http://localhost:80` in your browser

### 2. VNC Access
Connect VNC client to `localhost:5900` (no password)

### 3. MCP Coordinator
Test API: `curl http://localhost:8000/health`

### 4. Dgraph Interface
Open `http://localhost:8081` for graph database

### 5. Jupyter Notebooks
Open `http://localhost:8888` for analysis notebooks

## Common Issues & Solutions

### Docker Issues
**Issue:** "Cannot connect to Docker daemon"
**Solution:** Ensure Docker service is running
```bash
# Linux
sudo systemctl start docker

# Windows/macOS
# Start Docker Desktop
```

**Issue:** "Port already in use"
**Solution:** Stop conflicting services or change ports in docker-compose.yml

### Game File Issues
**Issue:** "Game.exe not found"
**Solution:** Verify game files are in correct location:
```bash
ls -la data/game_files/pd2/ProjectD2/Game.exe
```

**Issue:** Wine initialization fails
**Solution:** Check Wine dependencies in container:
```bash
docker-compose logs d2-analysis
```

### Memory Issues
**Issue:** Container out of memory
**Solution:** Increase Docker memory limits or close other applications

### Network Issues
**Issue:** Cannot access services
**Solution:** Check firewall settings and port availability:
```bash
# Check if ports are available
netstat -an | grep -E "(5900|8000|8080|8081)"
```

## Performance Optimization

### 1. Resource Allocation
Edit `docker-compose.prod.yml` for production:
```yaml
services:
  d2-analysis:
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '2.0'
```

### 2. Storage Optimization
Use SSD storage for better I/O performance:
```yaml
volumes:
  analysis_data:
    driver_opts:
      type: none
      o: bind
      device: /path/to/fast/storage
```

### 3. Network Optimization
For production deployments, consider:
- Using host networking mode
- Setting up reverse proxy with SSL
- Configuring firewall rules

## Security Considerations

### 1. Container Security
- Run containers with non-root user where possible
- Use security profiles (AppArmor/SELinux)
- Regular security updates

### 2. Network Security
- Use firewalls to restrict access
- Enable SSL/TLS for production
- Monitor network traffic

### 3. Data Security
- Encrypt sensitive data at rest
- Use secure backup procedures
- Implement access controls

## Backup and Recovery

### 1. Data Backup
```bash
# Backup analysis data
tar -czf backup-$(date +%Y%m%d).tar.gz data/outputs/

# Backup database
docker-compose exec dgraph-alpha dgraph export
```

### 2. Configuration Backup
```bash
# Backup configuration
tar -czf config-backup-$(date +%Y%m%d).tar.gz config/
```

### 3. Container Recovery
```bash
# Rebuild and restart services
make clean
make build
make dev
```

## Uninstallation

### 1. Stop Services
```bash
docker-compose down -v
```

### 2. Remove Images
```bash
docker rmi $(docker images -q "pd2-*")
```

### 3. Clean Up Volumes
```bash
docker volume prune -f
```

### 4. Remove Files
```bash
rm -rf pd2-mcp-orchestrated-re/
```

## Next Steps

After successful installation:

1. **Read the User Guide** - Learn basic operations
2. **Run Example Analysis** - Try the provided examples
3. **Configure Security** - Set up security scanning
4. **Explore Features** - Test different analysis modes
5. **Join Community** - Connect with other users

## Support

If you encounter issues during installation:

1. Check the [Troubleshooting Guide](docs/troubleshooting.md)
2. Review container logs: `make logs`
3. Open an issue on GitHub with:
   - Your operating system
   - Docker version
   - Error logs
   - Steps to reproduce

---

**Installation complete! Ready to analyze.**
