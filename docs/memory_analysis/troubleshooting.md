# Memory Analysis Troubleshooting Guide

This guide helps resolve common issues encountered during memory analysis operations.

## Common Issues and Solutions

### Process and Container Issues

#### 1. "Game.exe process not found"

**Symptoms:**
- Tools report "No Game.exe process found"
- Process ID lookup fails
- Container shows no D2 processes

**Diagnosis:**
```bash
# Check if Game.exe is running
docker exec d2-analysis ps aux | grep Game.exe

# Check D2 analysis container status
docker ps | grep d2-analysis

# Check container logs for startup errors
docker logs d2-analysis | tail -20
```

**Solutions:**

1. **Restart D2 analysis container:**
   ```bash
   docker-compose restart d2-analysis
   # Wait 30 seconds for initialization
   docker exec d2-analysis ps aux | grep Game.exe
   ```

2. **Manually start D2 inside container:**
   ```bash
   docker exec -it d2-analysis bash
   cd /game/pd2/ProjectD2
   wine Game.exe
   ```

3. **Check VNC connection:**
   - Connect to `vnc://localhost:5900`
   - Verify D2 is visible and running
   - Check character is loaded and active

#### 2. "Permission denied" on memory access

**Symptoms:**
- `/proc/PID/mem` access fails
- "Operation not permitted" errors
- Memory reading returns empty data

**Diagnosis:**
```bash
# Check process ownership and permissions
docker exec d2-analysis ls -la /proc/14/mem
docker exec d2-analysis ps -o pid,user,cmd | grep Game

# Check current user permissions
docker exec d2-analysis whoami
docker exec d2-analysis id
```

**Solutions:**

1. **Use container-based memory access:**
   ```python
   # Instead of external access, run inside container
   python tools/memory_hunters/extract_from_container.py
   ```

2. **Check ptrace permissions:**
   ```bash
   # Inside container
   docker exec d2-analysis sysctl kernel.yama.ptrace_scope
   # Should be 0 for unrestricted access
   ```

3. **Run tools inside container:**
   ```bash
   docker exec -it d2-analysis python /analysis/tools/rosterunit_hunter.py
   ```

### Memory Address Issues

#### 3. "Invalid memory address" errors

**Symptoms:**
- Segmentation faults during memory reading
- "Bad address" errors
- Inconsistent address calculations

**Diagnosis:**
```bash
# Check current D2Client.dll base address
docker exec d2-analysis gdb -p $(docker exec d2-analysis pgrep Game.exe) -batch -ex "info proc mappings" | grep d2client

# Verify static offsets are current
docker exec d2-analysis python -c "
import struct
with open('/proc/14/mem', 'rb') as f:
    f.seek(0x6FAB0000 + 0x11BBFC)
    data = f.read(4)
    print(f'Player unit pointer: 0x{struct.unpack(\"<L\", data)[0]:08X}')
"
```

**Solutions:**

1. **Recalculate base addresses:**
   ```python
   # Get current D2Client.dll base
   import subprocess
   result = subprocess.run([
       'docker', 'exec', 'd2-analysis', 'gdb', '-p', '14', 
       '-batch', '-ex', 'info proc mappings'
   ], capture_output=True, text=True)
   
   for line in result.stdout.split('\n'):
       if 'd2client' in line.lower():
           base_addr = int(line.split()[0], 16)
           print(f"Current D2Client base: 0x{base_addr:08X}")
   ```

2. **Update static offsets:**
   ```python
   # Update live_memory_offsets.json with current addresses
   import json
   
   offsets = {
       "D2Client.dll": {
           "base_address": f"0x{base_addr:08X}",
           "current_player_unit": base_addr + 0x11BBFC,
           "rosterunit_list": base_addr + 0x11BC14
       }
   }
   
   with open('data/reference/live_memory_offsets.json', 'w') as f:
       json.dump(offsets, f, indent=2)
   ```

3. **Validate pointer chains:**
   ```python
   # Check if pointers are valid before dereferencing
   def validate_pointer(addr):
       try:
           with open('/proc/14/mem', 'rb') as mem:
               mem.seek(addr)
               data = mem.read(4)
               ptr = struct.unpack('<L', data)[0]
               return 0x00400000 <= ptr <= 0x7FFFFFFF
       except:
           return False
   ```

#### 4. "Structure validation failed" errors

**Symptoms:**
- Parsed data doesn't match expected values
- Field validation fails
- Unrealistic character stats

**Diagnosis:**
```python
# Debug structure parsing step by step
def debug_structure_parsing(data, offset=0):
    print(f"Raw data at offset {offset}:")
    print(" ".join(f"{b:02X}" for b in data[offset:offset+16]))
    
    # Parse each field individually
    name = data[0:16].split(b'\x00')[0].decode('ascii', errors='ignore')
    unit_id = struct.unpack('<L', data[0x10:0x14])[0]
    party_life = struct.unpack('<L', data[0x14:0x18])[0]
    
    print(f"Name: '{name}'")
    print(f"Unit ID: {unit_id}")
    print(f"Party Life: {party_life}")
```

**Solutions:**

1. **Verify game state:**
   ```bash
   # Ensure character is fully loaded
   # Character should be in-game, not in menu
   # Check via VNC that character is active
   ```

2. **Update target values:**
   ```python
   # Match target values to current character
   target_values = {
       "szName": "ActualCharName",  # Check actual name in game
       "dwPartyLife": 100,          # Check actual health percentage
       "wLevel": 99                 # Check actual level
   }
   ```

3. **Cross-validate with multiple structures:**
   ```python
   # Compare RosterUnit data with UnitAny data
   roster_data = hunt_roster_unit()
   unit_data = extract_unit_any()
   
   # Names should match
   assert roster_data['szName'] == unit_data['player_name']
   # Unit IDs should match
   assert roster_data['dwUnitId'] == unit_data['dwUnitId']
   ```

### Database and Storage Issues

#### 5. "Cannot connect to Dgraph" errors

**Symptoms:**
- Dgraph connection timeouts
- "Connection refused" errors
- Storage operations fail

**Diagnosis:**
```bash
# Check Dgraph containers
docker ps | grep dgraph

# Test Dgraph endpoint
curl -X GET http://localhost:8081/health

# Check Dgraph logs
docker logs dgraph-alpha | tail -20
docker logs dgraph-zero | tail -20
```

**Solutions:**

1. **Start Dgraph services:**
   ```bash
   docker-compose up -d dgraph-zero dgraph-alpha
   # Wait for initialization (30 seconds)
   ```

2. **Reset Dgraph database:**
   ```bash
   docker-compose down dgraph-alpha dgraph-zero
   docker volume rm $(docker volume ls -q | grep dgraph)
   docker-compose up -d dgraph-zero dgraph-alpha
   ```

3. **Verify Dgraph schema:**
   ```bash
   curl -X POST http://localhost:8080/admin/schema -d '{
     "schema": "type Character { char.name: string @index(exact) . }"
   }'
   ```

#### 6. "Unicode encoding errors"

**Symptoms:**
- `UnicodeEncodeError: 'charmap' codec can't encode`
- Character names display incorrectly
- JSON serialization fails

**Solutions:**

1. **Set Python encoding:**
   ```python
   # Add to top of all Python files
   # -*- coding: utf-8 -*-
   import os
   os.environ['PYTHONIOENCODING'] = 'utf-8'
   ```

2. **Use proper string handling:**
   ```python
   # Safe string decoding
   def safe_decode(data):
       try:
           return data.decode('ascii')
       except UnicodeDecodeError:
           return data.decode('ascii', errors='ignore')
   ```

3. **Set container environment:**
   ```bash
   docker exec -it d2-analysis bash
   export PYTHONIOENCODING=utf-8
   export LC_ALL=C.UTF-8
   ```

### Development and Integration Issues

#### 7. "Import module errors"

**Symptoms:**
- `ModuleNotFoundError` for local modules
- Python path issues
- Import failures in containers

**Solutions:**

1. **Set Python path:**
   ```python
   import sys
   import os
   sys.path.append(os.path.dirname(os.path.abspath(__file__)))
   ```

2. **Use absolute imports:**
   ```python
   # Instead of relative imports
   from tools.memory_hunters.base import MemoryHunter
   # Use absolute imports from project root
   ```

3. **Install in container:**
   ```bash
   docker exec d2-analysis pip install -e /analysis
   ```

#### 8. "Git repository issues"

**Symptoms:**
- "Not a git repository" errors
- Lock file issues
- Commit failures

**Solutions:**

1. **Initialize repository:**
   ```bash
   cd pd2-mcp-orchestrated-re
   git init
   git add .
   git commit -m "Initial commit"
   ```

2. **Fix lock files:**
   ```bash
   rm -f .git/index.lock
   rm -f .git/refs/heads/main.lock
   ```

3. **Reset repository state:**
   ```bash
   git reset --hard HEAD
   git clean -fd
   ```

## Performance Issues

### 9. Slow memory reading

**Symptoms:**
- Long delays during structure hunting
- Timeouts on memory operations
- High CPU usage during analysis

**Solutions:**

1. **Batch memory operations:**
   ```python
   # Read multiple addresses at once
   addresses = [addr1, addr2, addr3]
   with open('/proc/14/mem', 'rb') as mem:
       data = {}
       for addr in addresses:
           mem.seek(addr)
           data[addr] = mem.read(size)
   ```

2. **Use memory mapping:**
   ```python
   import mmap
   
   with open('/proc/14/mem', 'rb') as f:
       with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
           data = mm[address:address+size]
   ```

3. **Cache base addresses:**
   ```python
   from functools import lru_cache
   
   @lru_cache(maxsize=1)
   def get_d2client_base():
       # Expensive base address lookup
       return find_module_base("d2client.dll")
   ```

### 10. High memory usage

**Symptoms:**
- Container memory limits exceeded
- Out of memory errors
- System slowdown

**Solutions:**

1. **Limit analysis scope:**
   ```python
   # Only read necessary structure sizes
   ROSTERUNIT_SIZE = 132  # Don't read more than needed
   
   def read_structure(addr):
       return read_memory(addr, ROSTERUNIT_SIZE)  # Not 1024+ bytes
   ```

2. **Clean up resources:**
   ```python
   import gc
   
   def analyze_memory():
       try:
           # Analysis code here
           pass
       finally:
           gc.collect()  # Force garbage collection
   ```

3. **Use streaming for large datasets:**
   ```python
   def process_large_memory_dump():
       with open('large_dump.bin', 'rb') as f:
           while True:
               chunk = f.read(4096)
               if not chunk:
                   break
               process_chunk(chunk)
   ```

## Environment-Specific Issues

### Windows/WSL Issues

#### 11. Docker connectivity problems

**Solutions:**

1. **Use Docker Desktop:**
   - Ensure Docker Desktop is running
   - Check WSL2 integration is enabled
   - Verify containers can access host network

2. **Port forwarding:**
   ```bash
   # Forward VNC port
   netsh interface portproxy add v4tov4 listenport=5900 listenaddress=0.0.0.0 connectport=5900 connectaddress=127.0.0.1
   ```

### Linux Container Issues

#### 12. Wine/X11 display problems

**Solutions:**

1. **Check X11 forwarding:**
   ```bash
   docker exec d2-analysis echo $DISPLAY
   docker exec d2-analysis xdpyinfo
   ```

2. **Restart X server:**
   ```bash
   docker exec d2-analysis supervisorctl restart xvfb
   docker exec d2-analysis supervisorctl restart fluxbox
   ```

## Diagnostic Commands

### System Health Check

```bash
#!/bin/bash
echo "=== System Health Check ==="

echo "1. Container Status:"
docker ps | grep -E "(d2-analysis|dgraph)"

echo -e "\n2. Game Process:"
docker exec d2-analysis ps aux | grep Game.exe || echo "Game.exe not found"

echo -e "\n3. Memory Access Test:"
docker exec d2-analysis ls -la /proc/*/mem 2>/dev/null | head -5 || echo "No processes found"

echo -e "\n4. Dgraph Health:"
curl -s http://localhost:8081/health || echo "Dgraph not accessible"

echo -e "\n5. VNC Status:"
nc -z localhost 5900 && echo "VNC port open" || echo "VNC not accessible"

echo -e "\n6. Disk Space:"
df -h | grep -E "(/$|docker)"

echo -e "\n7. Memory Usage:"
free -h
```

### Memory Analysis Debug

```python
#!/usr/bin/env python3
"""Debug script for memory analysis issues"""

def debug_memory_access():
    print("=== Memory Analysis Debug ===")
    
    # 1. Check process
    try:
        result = subprocess.run(['docker', 'exec', 'd2-analysis', 'pgrep', 'Game.exe'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            pid = result.stdout.strip()
            print(f"✓ Game.exe found at PID: {pid}")
        else:
            print("✗ Game.exe not found")
            return
    except Exception as e:
        print(f"✗ Container access failed: {e}")
        return
    
    # 2. Check memory access
    try:
        with open(f'/proc/{pid}/mem', 'rb') as mem:
            print("✓ Memory access available")
    except Exception as e:
        print(f"✗ Memory access failed: {e}")
    
    # 3. Check base address
    try:
        base_addr = get_module_base_address("d2client.dll")
        print(f"✓ D2Client base: 0x{base_addr:08X}")
    except Exception as e:
        print(f"✗ Base address lookup failed: {e}")
    
    # 4. Test structure read
    try:
        addr = base_addr + 0x11BBFC
        with open(f'/proc/{pid}/mem', 'rb') as mem:
            mem.seek(addr)
            data = mem.read(4)
            ptr = struct.unpack('<L', data)[0]
            print(f"✓ Player unit pointer: 0x{ptr:08X}")
    except Exception as e:
        print(f"✗ Structure read failed: {e}")

if __name__ == "__main__":
    debug_memory_access()
```

## Getting Help

### Log Collection

When reporting issues, collect these logs:

```bash
# Container logs
docker logs d2-analysis > d2-analysis.log 2>&1
docker logs dgraph-alpha > dgraph-alpha.log 2>&1

# System information
docker version > system-info.txt
docker-compose version >> system-info.txt
uname -a >> system-info.txt

# Process information
docker exec d2-analysis ps auxww > process-list.txt
docker exec d2-analysis cat /proc/meminfo > memory-info.txt
```

### Issue Reporting Template

When creating GitHub issues, include:

1. **Environment Information:**
   - OS and version
   - Docker version
   - Container status

2. **Error Details:**
   - Complete error messages
   - Stack traces
   - Log excerpts

3. **Reproduction Steps:**
   - Commands that trigger the issue
   - Expected vs actual behavior
   - Workarounds attempted

4. **System Diagnostics:**
   - Health check output
   - Memory analysis debug results
   - Container logs

### Community Resources

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Check latest docs for updates
- **Examples**: Review working examples for patterns
- **API Reference**: Consult API docs for proper usage

## Prevention

### Best Practices

1. **Regular Health Checks:**
   ```bash
   # Daily health check
   make health
   docker-compose ps
   ```

2. **Resource Monitoring:**
   ```bash
   # Monitor resource usage
   docker stats d2-analysis dgraph-alpha
   ```

3. **Backup Critical Data:**
   ```bash
   # Backup discoveries
   tar -czf memory-analysis-backup.tar.gz data/reference/ docs/
   ```

4. **Keep Documentation Updated:**
   - Update offsets when game updates
   - Document new structure discoveries
   - Record working configurations