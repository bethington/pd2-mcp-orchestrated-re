# PD2 MCP Orchestrated RE Platform - Architecture Analysis & Containerization Strategy

## Current Containerization Review

Let me analyze the current design and provide optimal containerization recommendations:

## 🏗️ **Current Container Architecture (docker-compose.yml Analysis)**

### ✅ **Well-Containerized Services**
1. **dgraph-zero & dgraph-alpha**: ✅ Properly containerized graph database
2. **redis**: ✅ Properly containerized session/cache storage  
3. **nginx**: ✅ Properly containerized reverse proxy

### ⚠️ **Containers Needing Optimization**
1. **d2-analysis**: Currently monolithic - contains game + analysis + MCP server
2. **mcp-coordinator**: Handles too many responsibilities
3. **analysis-engine**: Undefined scope in current docker-compose
4. **web-dashboard**: Basic implementation
5. **network-monitor**: Shares network namespace (good) but needs refinement

## 🎯 **Recommended Container Architecture**

### **Separation of Concerns Principle**

```yaml
# Optimized Container Strategy
services:
  # === GAME EXECUTION LAYER ===
  d2-game-runner:
    # ONLY runs Diablo 2 in Wine
    # Minimal, focused container
    
  # === ANALYSIS LAYER ===  
  memory-analyzer:
    # Dedicated memory analysis
    # Connects to game runner via shared volumes/network
    
  network-analyzer:
    # Dedicated network packet analysis
    # Uses network_mode: "container:d2-game-runner"
    
  static-analyzer:
    # Ghidra + other static analysis tools
    # Processes binaries from shared storage
    
  # === ORCHESTRATION LAYER ===
  mcp-coordinator:
    # Pure coordination logic
    # No analysis - just orchestration
    
  # === MCP SERVERS ===
  mcp-d2-server:
  mcp-ghidra-server: 
  mcp-network-server:
  mcp-memory-server:
    # Each MCP server in its own container
    
  # === DATA LAYER ===
  dgraph-alpha:     # ✅ Already optimal
  dgraph-zero:      # ✅ Already optimal  
  redis:            # ✅ Already optimal
  
  # === INTERFACE LAYER ===
  web-dashboard:    # Frontend only
  api-gateway:      # REST API + WebSocket gateway
  nginx:            # ✅ Already optimal
```

## 📊 **Detailed Architectural Diagrams**

### **Diagram 1: High-Level System Architecture**

```mermaid
graph TB
    subgraph "User Interface Layer"
        WEB[Web Dashboard<br/>React/Vue Frontend]
        CLI[CLI Tools<br/>Direct API Access]
        VNC[VNC Client<br/>Game Viewing]
    end
    
    subgraph "API Gateway Layer" 
        NGINX[Nginx Reverse Proxy<br/>Load Balancer]
        API[API Gateway<br/>REST + WebSocket]
    end
    
    subgraph "Orchestration Layer"
        COORD[MCP Coordinator<br/>Task Management]
        CLAUDE[Claude AI<br/>Analysis Strategy]
    end
    
    subgraph "MCP Server Layer"
        MCP_D2[D2 MCP Server<br/>Game State]
        MCP_MEM[Memory MCP Server<br/>Memory Analysis] 
        MCP_NET[Network MCP Server<br/>Packet Analysis]
        MCP_STATIC[Static MCP Server<br/>Ghidra Integration]
        MCP_GRAPH[Graph MCP Server<br/>Knowledge Storage]
    end
    
    subgraph "Analysis Engine Layer"
        D2_GAME[D2 Game Runner<br/>Wine + Game]
        MEM_ANALYZER[Memory Analyzer<br/>Process Injection]
        NET_ANALYZER[Network Analyzer<br/>Packet Capture]
        STATIC_ANALYZER[Static Analyzer<br/>Ghidra + Tools]
        BEHAVIOR[Behavioral Analyzer<br/>Pattern Detection]
    end
    
    subgraph "Data Storage Layer"
        DGRAPH[(Dgraph<br/>Knowledge Graph)]
        REDIS[(Redis<br/>Sessions + Cache)]
        FILES[(File Storage<br/>Binaries + Reports)]
    end
    
    %% User Connections
    WEB --> NGINX
    VNC --> D2_GAME
    CLI --> API
    
    %% API Layer Connections  
    NGINX --> API
    NGINX --> WEB
    API --> COORD
    
    %% Orchestration Connections
    COORD --> MCP_D2
    COORD --> MCP_MEM
    COORD --> MCP_NET  
    COORD --> MCP_STATIC
    COORD --> MCP_GRAPH
    CLAUDE --> COORD
    
    %% MCP to Analysis Engine Connections
    MCP_D2 --> D2_GAME
    MCP_MEM --> MEM_ANALYZER
    MCP_NET --> NET_ANALYZER
    MCP_STATIC --> STATIC_ANALYZER
    
    %% Analysis Engine Interconnections
    MEM_ANALYZER -.->|Memory Access| D2_GAME
    NET_ANALYZER -.->|Network Monitoring| D2_GAME
    BEHAVIOR --> MEM_ANALYZER
    BEHAVIOR --> NET_ANALYZER
    
    %% Data Storage Connections
    MCP_GRAPH --> DGRAPH
    COORD --> REDIS
    STATIC_ANALYZER --> FILES
    
    %% Styling
    classDef userLayer fill:#e1f5fe,stroke:#01579b,stroke-width:3px,color:#000000
    classDef apiLayer fill:#f3e5f5,stroke:#4a148c,stroke-width:3px,color:#000000  
    classDef orchestrationLayer fill:#e8f5e8,stroke:#1b5e20,stroke-width:3px,color:#000000
    classDef mcpLayer fill:#fff3e0,stroke:#e65100,stroke-width:3px,color:#000000
    classDef analysisLayer fill:#fce4ec,stroke:#880e4f,stroke-width:3px,color:#000000
    classDef dataLayer fill:#f1f8e9,stroke:#33691e,stroke-width:3px,color:#000000
    
    class WEB,VNC,CLI userLayer
    class NGINX,API apiLayer
    class COORD,CLAUDE orchestrationLayer
    class MCP_D2,MCP_MEM,MCP_NET,MCP_STATIC,MCP_GRAPH mcpLayer
    class D2_GAME,MEM_ANALYZER,NET_ANALYZER,STATIC_ANALYZER,BEHAVIOR analysisLayer
    class DGRAPH,REDIS,FILES dataLayer
```

### **Diagram 2: Container Network Architecture**

```mermaid
graph TB
    subgraph "External Network"
        USER[User Browser/VNC]
        INTERNET[Internet Access]
    end
    
    subgraph "Host Network Bridge: re-platform (172.20.0.0/16)"
        
        subgraph "Frontend Tier"
            NGINX_C[nginx-proxy<br/>172.20.0.10<br/>Ports: 80,443,8090]
            WEB_C[web-dashboard<br/>172.20.0.11<br/>Port: 3000]
        end
        
        subgraph "API Tier"  
            API_C[api-gateway<br/>172.20.0.20<br/>Port: 8000]
            COORD_C[mcp-coordinator<br/>172.20.0.21<br/>Port: 9000]
        end
        
        subgraph "MCP Server Tier"
            MCP_D2_C[mcp-d2-server<br/>172.20.0.30<br/>Port: 8765]
            MCP_MEM_C[mcp-memory-server<br/>172.20.0.31<br/>Port: 8766]  
            MCP_NET_C[mcp-network-server<br/>172.20.0.32<br/>Port: 8767]
            MCP_STATIC_C[mcp-static-server<br/>172.20.0.33<br/>Port: 8768]
        end
        
        subgraph "Analysis Tier"
            D2_C[d2-game-runner<br/>172.20.0.40<br/>Ports: 5900,8080]
            MEM_C[memory-analyzer<br/>172.20.0.41]
            STATIC_C[static-analyzer<br/>172.20.0.42]
        end
        
        subgraph "Network Analysis (Shared Namespace)"
            NET_C[network-analyzer<br/>network_mode: container:d2-game-runner<br/>Shares: 172.20.0.40]
        end
        
        subgraph "Data Tier"
            DGRAPH_Z[dgraph-zero<br/>172.20.0.50<br/>Port: 5080]
            DGRAPH_A[dgraph-alpha<br/>172.20.0.51<br/>Port: 8081]
            REDIS_C[redis<br/>172.20.0.52<br/>Port: 6379]
        end
        
    end
    
    %% External Connections
    USER --> NGINX_C
    NGINX_C --> INTERNET
    
    %% Frontend Connections
    NGINX_C --> WEB_C
    NGINX_C --> API_C
    NGINX_C --> D2_C
    
    %% API Connections
    API_C --> COORD_C
    
    %% Orchestration to MCP
    COORD_C --> MCP_D2_C  
    COORD_C --> MCP_MEM_C
    COORD_C --> MCP_NET_C
    COORD_C --> MCP_STATIC_C
    
    %% MCP to Analysis
    MCP_D2_C --> D2_C
    MCP_MEM_C --> MEM_C
    MCP_NET_C --> NET_C
    MCP_STATIC_C --> STATIC_C
    
    %% Analysis Interconnections  
    MEM_C -.->|ptrace/gdb| D2_C
    NET_C -.->|shared network| D2_C
    
    %% Data Connections
    COORD_C --> REDIS_C
    MCP_D2_C --> DGRAPH_A
    MCP_MEM_C --> DGRAPH_A
    DGRAPH_A --> DGRAPH_Z
    
    %% Styling
    classDef external fill:#ffebee,stroke:#c62828,stroke-width:3px,color:#000000
    classDef frontend fill:#e3f2fd,stroke:#1565c0,stroke-width:3px,color:#000000
    classDef api fill:#f3e5f5,stroke:#7b1fa2,stroke-width:3px,color:#000000
    classDef mcp fill:#fff8e1,stroke:#f57f17,stroke-width:3px,color:#000000
    classDef analysis fill:#fce4ec,stroke:#ad1457,stroke-width:3px,color:#000000
    classDef data fill:#e8f5e8,stroke:#2e7d32,stroke-width:3px,color:#000000
    classDef network fill:#fff3e0,stroke:#ef6c00,stroke-width:3px,color:#000000
    
    class USER,INTERNET external
    class NGINX_C,WEB_C frontend
    class API_C,COORD_C api
    class MCP_D2_C,MCP_MEM_C,MCP_NET_C,MCP_STATIC_C mcp
    class D2_C,MEM_C,STATIC_C analysis
    class NET_C network
    class DGRAPH_Z,DGRAPH_A,REDIS_C data
```

### **Diagram 3: Data Flow & Security Architecture**

```mermaid
graph LR
    subgraph "Security Zones"
        
        subgraph "DMZ Zone (Exposed)"
            LB[Load Balancer<br/>SSL Termination]
            FW[Firewall Rules<br/>Rate Limiting]
        end
        
        subgraph "Application Zone (Restricted)"
            API[API Gateway<br/>Authentication]
            WEB[Web Dashboard<br/>HTTPS Only]
        end
        
        subgraph "Orchestration Zone (Internal)"
            COORD[MCP Coordinator<br/>Session Management]
            SEC[Security Manager<br/>Sandboxing]
        end
        
        subgraph "Analysis Zone (Sandboxed)"
            D2[D2 Game Runner<br/>Wine Sandbox]
            MEM[Memory Analyzer<br/>Limited Privileges] 
            NET[Network Monitor<br/>Read-Only Capture]
        end
        
        subgraph "Data Zone (Encrypted)"
            GRAPH[(Knowledge Graph<br/>Encrypted at Rest)]
            CACHE[(Session Cache<br/>TTL + Encryption)]
            FILES[(File Storage<br/>Quarantine System)]
        end
        
    end
    
    %% Data Flow
    USER[Users] --> LB
    LB --> FW
    FW --> API
    FW --> WEB
    
    API --> COORD
    WEB --> COORD
    
    COORD --> SEC
    SEC --> D2
    SEC --> MEM  
    SEC --> NET
    
    COORD --> GRAPH
    COORD --> CACHE
    MEM --> FILES
    
    %% Security Controls
    SEC -.->|Resource Limits| D2
    SEC -.->|Process Isolation| MEM
    SEC -.->|Network Policies| NET
    SEC -.->|File Quarantine| FILES
    
    %% Styling
    classDef dmz fill:#ffebee,stroke:#c62828,stroke-width:3px,color:#000000
    classDef app fill:#e8eaf6,stroke:#3f51b5,stroke-width:3px,color:#000000
    classDef orchestration fill:#e0f2f1,stroke:#00695c,stroke-width:3px,color:#000000
    classDef analysis fill:#fce4ec,stroke:#ad1457,stroke-width:3px,color:#000000
    classDef data fill:#f1f8e9,stroke:#2e7d32,stroke-width:3px,color:#000000
    classDef user fill:#fff3e0,stroke:#ef6c00,stroke-width:3px,color:#000000
    
    class LB,FW dmz
    class API,WEB app
    class COORD,SEC orchestration
    class D2,MEM,NET analysis
    class GRAPH,CACHE,FILES data
    class USER user
```

## 🚀 **Containerization Strategy & Design Analysis**

### **Answer to Original Question: "Is Dgraph in a Container?"**

✅ **YES - Dgraph is Properly Containerized**:
- **dgraph-zero**: Coordination service container
- **dgraph-alpha**: Database service container  
- **Persistent Volumes**: Data persistence with Docker volumes
- **Network Isolation**: Backend network (172.21.0.0/24) access only
- **Security**: Encrypted at rest, whitelist access control

### **Answer to: "Is D2 Analysis Tooling in Same or Different Containers?"**

✅ **SEPARATED INTO SPECIALIZED CONTAINERS** for optimal isolation:

| Analysis Tool | Container | Justification |
|---------------|-----------|---------------|
| **Game Execution** | `d2-game-runner` | Wine environment isolation |
| **Memory Analysis** | `memory-analyzer` | Privileged operations (SYS_PTRACE) |
| **Network Analysis** | `network-analyzer` | Packet capture capabilities (NET_RAW) |
| **Static Analysis** | `static-analyzer` | Heavy Ghidra workload (8GB RAM) |
| **Behavioral Analysis** | `behavioral-analyzer` | Pattern detection isolation |

## 📊 **Additional Architectural Diagrams**

### **Diagram 4: Container Dependency & Startup Sequence**

```mermaid
graph TD
    subgraph "Phase 1: Infrastructure Services"
        A[dgraph-zero] --> B[dgraph-alpha]
        C[redis] 
        D[nginx-proxy]
    end
    
    subgraph "Phase 2: Security & Orchestration"
        B --> E[security-manager]
        C --> E
        E --> F[mcp-coordinator]
    end
    
    subgraph "Phase 3: API Services"
        F --> G[api-gateway]
        G --> H[web-dashboard]
        D --> G
        D --> H
    end
    
    subgraph "Phase 4: Analysis Engines"
        E --> I[d2-game-runner]
        I --> J[memory-analyzer]
        I --> K[network-analyzer]
        E --> L[static-analyzer]
        E --> M[behavioral-analyzer]
    end
    
    subgraph "Phase 5: MCP Servers"
        F --> N[mcp-d2-server]
        F --> O[mcp-memory-server]
        F --> P[mcp-network-server]
        F --> Q[mcp-static-server]
        
        N --> I
        O --> J
        P --> K
        Q --> L
    end
    
    %% Dependency Styling
    classDef infrastructure fill:#e3f2fd,stroke:#1976d2,stroke-width:3px,color:#000000
    classDef security fill:#fff3e0,stroke:#f57c00,stroke-width:3px,color:#000000
    classDef api fill:#f3e5f5,stroke:#7b1fa2,stroke-width:3px,color:#000000
    classDef analysis fill:#fce4ec,stroke:#ad1457,stroke-width:3px,color:#000000
    classDef mcp fill:#e8f5e8,stroke:#388e3c,stroke-width:3px,color:#000000
    
    class A,B,C,D infrastructure
    class E,F security
    class G,H api
    class I,J,K,L,M analysis
    class N,O,P,Q mcp
```

### **Diagram 5: Data Flow & Processing Pipeline**

```mermaid
flowchart TD
    subgraph "Data Ingestion"
        USER[User Request] --> API[API Gateway]
        GAME[D2 Game State] --> CAPTURE[Data Capture]
    end
    
    subgraph "Analysis Pipeline"
        CAPTURE --> MEM_RAW[Raw Memory Data]
        CAPTURE --> NET_RAW[Raw Network Packets]
        CAPTURE --> GAME_RAW[Game State Data]
        
        MEM_RAW --> MEM_PROC[Memory Analyzer]
        NET_RAW --> NET_PROC[Network Analyzer]
        GAME_RAW --> GAME_PROC[Game State Analyzer]
        
        MEM_PROC --> MEM_STRUCT[Structured Memory Data]
        NET_PROC --> NET_STRUCT[Parsed Network Protocols]
        GAME_PROC --> GAME_STRUCT[Character/Inventory Data]
    end
    
    subgraph "Static Analysis Pipeline"
        BINARIES[Game Binaries] --> GHIDRA[Ghidra Analysis]
        GHIDRA --> FUNCTIONS[Function Analysis]
        GHIDRA --> STRUCTURES[Data Structures]
        GHIDRA --> VULNERABILITIES[Security Analysis]
    end
    
    subgraph "Correlation & AI Analysis"
        MEM_STRUCT --> CORRELATE[Data Correlation Engine]
        NET_STRUCT --> CORRELATE
        GAME_STRUCT --> CORRELATE
        FUNCTIONS --> CORRELATE
        STRUCTURES --> CORRELATE
        
        CORRELATE --> AI[Claude AI Analysis]
        AI --> INSIGHTS[Security Insights]
        AI --> RECOMMENDATIONS[Optimization Recommendations]
        AI --> PATTERNS[Behavioral Patterns]
    end
    
    subgraph "Data Persistence"
        INSIGHTS --> DGRAPH[(Dgraph Knowledge Graph)]
        RECOMMENDATIONS --> DGRAPH
        PATTERNS --> DGRAPH
        VULNERABILITIES --> DGRAPH
        
        CORRELATE --> CACHE[(Redis Cache)]
        API --> SESSIONS[(Session Data)]
    end
    
    subgraph "Output Generation"
        DGRAPH --> REPORTS[Analysis Reports]
        CACHE --> REALTIME[Real-time Dashboard]
        SESSIONS --> ALERTS[Security Alerts]
    end
    
    %% Styling
    classDef input fill:#e1f5fe,stroke:#0277bd,stroke-width:3px,color:#000000
    classDef processing fill:#fff3e0,stroke:#f57c00,stroke-width:3px,color:#000000
    classDef ai fill:#e8f5e8,stroke:#388e3c,stroke-width:3px,color:#000000
    classDef storage fill:#fce4ec,stroke:#ad1457,stroke-width:3px,color:#000000
    classDef output fill:#f3e5f5,stroke:#7b1fa2,stroke-width:3px,color:#000000
    
    class USER,GAME,BINARIES input
    class CAPTURE,MEM_PROC,NET_PROC,GAME_PROC,GHIDRA processing
    class CORRELATE,AI,INSIGHTS,RECOMMENDATIONS,PATTERNS ai
    class DGRAPH,CACHE,SESSIONS storage
    class REPORTS,REALTIME,ALERTS output
```

### **Diagram 6: Security Zones & Communication Matrix**

```mermaid
graph LR
    subgraph "External Zone (Internet)"
        USERS[External Users]
        ATTACKERS[Potential Attackers]
    end
    
    subgraph "DMZ Zone - 172.20.0.0/24"
        direction TB
        LB[Load Balancer<br/>nginx-proxy:80,443]
        WAF[Web Application Firewall<br/>Rate Limiting + DDoS Protection]
        
        LB --> WAF
    end
    
    subgraph "Application Zone - 172.21.0.0/24"
        direction TB
        API[API Gateway<br/>Authentication & Authorization]
        WEB[Web Dashboard<br/>Static Content + React/Vue]
        COORD[MCP Coordinator<br/>Task Orchestration]
        SEC[Security Manager<br/>Container Sandboxing]
        
        API --> COORD
        WEB --> API
        COORD --> SEC
    end
    
    subgraph "Data Zone - 172.21.0.0/24"
        direction TB
        DGRAPH[Dgraph Cluster<br/>Knowledge Storage]
        REDIS[Redis Cluster<br/>Session Cache]
        FILES[File Storage<br/>Analysis Artifacts]
        
        COORD --> DGRAPH
        API --> REDIS
        SEC --> FILES
    end
    
    subgraph "Analysis Sandbox - 172.22.0.0/24"
        direction TB
        D2[D2 Game Runner<br/>Wine + Diablo 2]
        MEM[Memory Analyzer<br/>GDB + Process Injection]
        NET[Network Analyzer<br/>Packet Capture + DPI]
        STATIC[Static Analyzer<br/>Ghidra + Reverse Engineering]
        BEHAVIOR[Behavioral Analyzer<br/>Pattern Detection + ML]
        
        MEM -.->|ptrace| D2
        NET -.->|shared network| D2
        STATIC -.->|binary analysis| FILES
        BEHAVIOR --> MEM
        BEHAVIOR --> NET
    end
    
    %% External Connections
    USERS --> LB
    ATTACKERS -.->|blocked| WAF
    
    %% DMZ to Application
    WAF --> API
    WAF --> WEB
    
    %% Security Controls
    SEC -.->|resource limits| D2
    SEC -.->|process isolation| MEM
    SEC -.->|network policies| NET
    SEC -.->|file quarantine| STATIC
    SEC -.->|monitoring| BEHAVIOR
    
    %% Security Styling
    classDef external fill:#ffebee,stroke:#c62828,stroke-width:3px,color:#000000
    classDef dmz fill:#fff3e0,stroke:#ef6c00,stroke-width:3px,color:#000000
    classDef application fill:#e8eaf6,stroke:#3f51b5,stroke-width:3px,color:#000000
    classDef data fill:#e0f2f1,stroke:#00695c,stroke-width:3px,color:#000000
    classDef sandbox fill:#fce4ec,stroke:#ad1457,stroke-width:3px,color:#000000
    
    class USERS,ATTACKERS external
    class LB,WAF dmz
    class API,WEB,COORD,SEC application
    class DGRAPH,REDIS,FILES data
    class D2,MEM,NET,STATIC,BEHAVIOR sandbox
```

### **Diagram 7: Container Resource Allocation & Scaling Strategy**

```mermaid
graph TB
    subgraph "Resource Tiers"
        subgraph "Heavy Compute (8GB+ RAM)"
            STATIC_HEAVY[static-analyzer<br/>Ghidra Analysis<br/>8GB RAM, 4 CPU]
            D2_HEAVY[d2-game-runner<br/>Wine + Game<br/>4GB RAM, 2 CPU]
        end
        
        subgraph "Medium Compute (1-2GB RAM)"
            MEM_MED[memory-analyzer<br/>Process Analysis<br/>2GB RAM, 1 CPU]
            COORD_MED[mcp-coordinator<br/>Orchestration<br/>1GB RAM, 1 CPU]
            BEHAVIOR_MED[behavioral-analyzer<br/>Pattern Analysis<br/>2GB RAM, 1 CPU]
        end
        
        subgraph "Light Compute (256-512MB RAM)"
            API_LIGHT[api-gateway<br/>HTTP/WebSocket<br/>512MB RAM, 1 CPU]
            WEB_LIGHT[web-dashboard<br/>Static Content<br/>256MB RAM, 0.5 CPU]
            NET_LIGHT[network-analyzer<br/>Packet Capture<br/>1GB RAM, 0.5 CPU]
            MCP_LIGHT[mcp-servers<br/>Protocol Adapters<br/>512MB RAM, 0.5 CPU each]
        end
    end
    
    subgraph "Scaling Patterns"
        subgraph "Horizontal Scaling (Stateless)"
            API_SCALE[api-gateway × 3<br/>Load Balanced]
            WEB_SCALE[web-dashboard × 3<br/>CDN Distribution]
            MCP_SCALE[mcp-servers × 2<br/>Analysis Load Distribution]
        end
        
        subgraph "Vertical Scaling (Resource Intensive)"
            STATIC_SCALE[static-analyzer<br/>Scale Up: 16GB RAM, 8 CPU]
            D2_SCALE[d2-game-runner<br/>Multiple Instances per Session]
        end
        
        subgraph "Singleton (Stateful)"
            DGRAPH_SINGLE[dgraph-alpha<br/>Single Writer + Read Replicas]
            REDIS_SINGLE[redis<br/>Single Instance + Persistence]
            SEC_SINGLE[security-manager<br/>Centralized Control]
        end
    end
    
    %% Resource Allocation
    STATIC_HEAVY -.->|High CPU/Memory| STATIC_SCALE
    D2_HEAVY -.->|Per Session| D2_SCALE
    
    API_LIGHT -.->|Load Distribution| API_SCALE
    WEB_LIGHT -.->|CDN Caching| WEB_SCALE
    MCP_LIGHT -.->|Analysis Load| MCP_SCALE
    
    %% Styling
    classDef heavy fill:#ffcdd2,stroke:#d32f2f,stroke-width:3px,color:#000000
    classDef medium fill:#fff3e0,stroke:#f57c00,stroke-width:3px,color:#000000
    classDef light fill:#e8f5e8,stroke:#388e3c,stroke-width:3px,color:#000000
    classDef horizontal fill:#e3f2fd,stroke:#1976d2,stroke-width:3px,color:#000000
    classDef vertical fill:#f3e5f5,stroke:#7b1fa2,stroke-width:3px,color:#000000
    classDef singleton fill:#fce4ec,stroke:#ad1457,stroke-width:3px,color:#000000
    
    class STATIC_HEAVY,D2_HEAVY heavy
    class MEM_MED,COORD_MED,BEHAVIOR_MED medium
    class API_LIGHT,WEB_LIGHT,NET_LIGHT,MCP_LIGHT light
    class API_SCALE,WEB_SCALE,MCP_SCALE horizontal
    class STATIC_SCALE,D2_SCALE vertical
    class DGRAPH_SINGLE,REDIS_SINGLE,SEC_SINGLE singleton
```

## 🎯 **Containerization Design Decisions Summary**

### **Core Architectural Principles Applied**

1. **Single Responsibility Principle**: Each container handles one specific function
2. **Defense in Depth**: Multi-layer security with network isolation
3. **Separation of Concerns**: Clear boundaries between data, logic, and presentation
4. **Microservices Architecture**: Small, loosely coupled services
5. **Resource Optimization**: Right-sized containers for their workload

### **Container Optimization Rationale**

| Design Decision | Rationale | Benefits |
|-----------------|-----------|----------|
| **Dgraph Containerized** | Database isolation & scalability | Easy backup, resource control, horizontal scaling |
| **Separate Analysis Containers** | Security & resource isolation | Fault tolerance, privilege separation, independent scaling |
| **Shared Network Namespace** | Network packet capture requirement | Real-time traffic analysis without bridging overhead |
| **MCP Server Microservices** | Protocol specialization | Independent updates, load distribution, fault isolation |
| **Multi-tier Networks** | Security zone enforcement | Attack surface reduction, traffic segmentation |

### **How the Design Comes Together**

```mermaid
sequenceDiagram
    participant User
    participant Nginx as Load Balancer
    participant API as API Gateway
    participant Coord as MCP Coordinator
    participant Sec as Security Manager
    participant D2 as D2 Game Runner
    participant Mem as Memory Analyzer
    participant Static as Static Analyzer
    participant Graph as Dgraph

    User->>+Nginx: HTTPS Request
    Nginx->>+API: Route to API Gateway
    API->>API: Authenticate & Authorize
    API->>+Coord: Analysis Request
    
    Coord->>+Sec: Request Security Context
    Sec->>Sec: Create Sandbox Environment
    Sec-->>-Coord: Security Context Ready
    
    Coord->>+D2: Start Game Instance
    D2->>D2: Initialize Wine & Game
    D2-->>-Coord: Game Ready
    
    par Memory Analysis
        Coord->>+Mem: Analyze Memory Structures
        Mem->>D2: Attach Debugger (ptrace)
        Mem->>Mem: Extract Memory Data
        Mem-->>-Coord: Memory Analysis Results
    and Static Analysis
        Coord->>+Static: Analyze Game Binaries
        Static->>Static: Ghidra Processing
        Static-->>-Coord: Static Analysis Results
    end
    
    Coord->>+Graph: Store Analysis Data
    Graph-->>-Coord: Data Stored
    
    Coord-->>-API: Complete Analysis Results
    API-->>-Nginx: JSON Response
    Nginx-->>-User: HTTPS Response
```

This architecture successfully addresses the original questions:

✅ **Dgraph is properly containerized** with dedicated zero/alpha containers
✅ **D2 analysis tooling is separated** into specialized containers for security and performance
✅ **Design coherence is demonstrated** through detailed architectural diagrams showing data flow, security zones, and container interactions

The containerization strategy provides enterprise-grade security, scalability, and maintainability while maintaining clear separation of concerns and optimal resource utilization.
