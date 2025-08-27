# D2 Memory Structures Reference

This document provides detailed information about Project Diablo 2 memory structures discovered through live memory analysis.

## Verified Static Offsets

### D2Client.dll Module
- **Base Address**: `0x6FAB0000` (Wine environment)
- **Size**: 90,112 bytes (0x16000)
- **Path**: `/game/pd2/ProjectD2/D2Client.dll`

### Critical Static Offsets

| Name | Offset | Full Address | Data Type | Description |
|------|--------|--------------|-----------|-------------|
| Current Player Unit | 0x11BBFC | D2Client.dll+0x11BBFC | UnitAny* | Pointer to current player's UnitAny structure |
| RosterUnit List | 0x11BC14 | D2Client.dll+0x11BC14 | RosterUnit* | Pointer to first RosterUnit in party list |

## Structure Layouts

### UnitAny Structure (236 bytes / 0xEC)

The main structure for all game units (players, monsters, objects, items, etc.).

```c
struct UnitAny {
    DWORD dwType;              // 0x00 - Unit type (0=Player, 1=Monster, etc.)
    DWORD dwTxtFileNo;         // 0x04 - Character class or monster type ID
    DWORD _1;                  // 0x08 - Unknown
    DWORD dwUnitId;            // 0x0C - Unique unit identifier
    DWORD dwMode;              // 0x10 - Current unit mode/state
    PlayerData* pPlayerData;   // 0x14 - Player data (players only)
    DWORD dwAct;               // 0x18 - Current act number
    Act* pAct;                 // 0x1C - Pointer to Act structure
    // ... additional fields ...
    StatList* pStats;          // 0x5C - Character statistics
    Inventory* pInventory;     // 0x60 - Equipment and items
    // ... additional fields ...
    WORD wX;                   // 0x8C - World X coordinate
    WORD wY;                   // 0x8E - World Y coordinate
    // ... additional fields ...
    Info* pInfo;               // 0xA8 - Skills and abilities
    // ... additional fields ...
    DWORD dwFlags;             // 0xC4 - Primary unit flags
    DWORD dwFlags2;            // 0xC8 - Extended unit flags
    // ... additional fields ...
    UnitAny* pNext;            // 0xE8 - Next unit in list
};
```

#### Key UnitAny Fields

| Offset | Field Name | Size | Type | Description |
|--------|------------|------|------|-------------|
| 0x00 | dwType | 4 | DWORD | Unit type (0=Player, 1=Monster, 2=Object, 3=Missile, 4=Item, 5=Tile) |
| 0x04 | dwTxtFileNo | 4 | DWORD | Character class ID (0=Amazon, 1=Sorceress, 2=Necromancer, 3=Paladin, 4=Barbarian, 5=Druid, 6=Assassin) |
| 0x0C | dwUnitId | 4 | DWORD | Unique identifier for this unit |
| 0x10 | dwMode | 4 | DWORD | Current animation/state mode |
| 0x14 | pPlayerData | 4 | PlayerData* | Pointer to player-specific data (name, quests, waypoints) |
| 0x18 | dwAct | 4 | DWORD | Current act (0-4) |
| 0x5C | pStats | 4 | StatList* | Pointer to character statistics |
| 0x60 | pInventory | 4 | Inventory* | Pointer to equipment and inventory |
| 0x8C | wX | 2 | WORD | World X coordinate |
| 0x8E | wY | 2 | WORD | World Y coordinate |
| 0xA8 | pInfo | 4 | Info* | Pointer to skills and abilities data |
| 0xC4 | dwFlags | 4 | DWORD | Primary unit flags |
| 0xC8 | dwFlags2 | 4 | DWORD | Extended unit flags |

### RosterUnit Structure (132 bytes / 0x84)

Contains party/roster information for players.

```c
struct RosterUnit {
    char szName[16];           // 0x00 - Player name (null-terminated)
    DWORD dwUnitId;            // 0x10 - Unit ID (matches UnitAny.dwUnitId)
    DWORD dwPartyLife;         // 0x14 - Party life percentage (0-100)
    DWORD _1;                  // 0x18 - Unknown
    DWORD dwClassId;           // 0x1C - Character class ID
    WORD wLevel;               // 0x20 - Character level
    WORD wPartyId;             // 0x22 - Party identifier
    DWORD dwLevelId;           // 0x24 - Current area/level ID
    DWORD Xpos;                // 0x28 - X position
    DWORD Ypos;                // 0x2C - Y position
    DWORD dwPartyFlags;        // 0x30 - Party status flags
    BYTE* _5;                  // 0x34 - Unknown pointer
    DWORD _6[11];              // 0x38 - Reserved array (44 bytes)
    WORD _7;                   // 0x64 - Unknown
    char szName2[16];          // 0x66 - Secondary name field (duplicate)
    WORD _8;                   // 0x76 - Unknown
    DWORD _9[2];               // 0x78 - Unknown array (8 bytes)
    RosterUnit* pNext;         // 0x80 - Pointer to next RosterUnit
};
```

#### Key RosterUnit Fields

| Offset | Field Name | Size | Type | Description |
|--------|------------|------|------|-------------|
| 0x00 | szName | 16 | char[16] | Player name (null-terminated string) |
| 0x10 | dwUnitId | 4 | DWORD | Unit ID matching UnitAny.dwUnitId |
| 0x14 | dwPartyLife | 4 | DWORD | Party life percentage (0=dead, 100=full) |
| 0x1C | dwClassId | 4 | DWORD | Character class (same as UnitAny.dwTxtFileNo) |
| 0x20 | wLevel | 2 | WORD | Character level |
| 0x22 | wPartyId | 2 | WORD | Party identifier (65535=not in party) |
| 0x24 | dwLevelId | 4 | DWORD | Current area/level ID |
| 0x28 | Xpos | 4 | DWORD | X position (world coordinates) |
| 0x2C | Ypos | 4 | DWORD | Y position (world coordinates) |
| 0x30 | dwPartyFlags | 4 | DWORD | Party status and flags |
| 0x66 | szName2 | 16 | char[16] | Duplicate name field |
| 0x80 | pNext | 4 | RosterUnit* | Pointer to next party member (NULL=last) |

### PlayerData Structure (40 bytes / 0x28)

Contains player-specific data including name, quests, and waypoints.

```c
struct PlayerData {
    char szName[16];           // 0x00 - Character name
    QuestInfo* pNormalQuest;   // 0x10 - Normal difficulty quest data
    QuestInfo* pNightmareQuest;// 0x14 - Nightmare difficulty quest data
    QuestInfo* pHellQuest;     // 0x18 - Hell difficulty quest data
    Waypoint* pNormalWaypoint; // 0x1C - Normal difficulty waypoints
    Waypoint* pNightmareWaypoint; // 0x20 - Nightmare waypoints
    Waypoint* pHellWaypoint;   // 0x24 - Hell difficulty waypoints
};
```

### StatList and Stat Structures

#### StatList Structure
- **pStat** (0x24): Pointer to Stat array
- **wStatCount1** (0x28): Number of stats in array
- **wStatCount2** (0x2A): Secondary stat count
- **pNext** (0x3C): Pointer to next StatList

#### Stat Structure (8 bytes)
- **wSubIndex** (0x00): Stat sub-index
- **wStatIndex** (0x02): Stat type identifier
- **dwStatValue** (0x04): Stat value

#### Common Stat Indices

| Index | Stat Name | Description | Notes |
|-------|-----------|-------------|-------|
| 0 | Strength | Strength attribute | Base stat |
| 1 | Energy | Energy attribute | Base stat |
| 2 | Dexterity | Dexterity attribute | Base stat |
| 3 | Vitality | Vitality attribute | Base stat |
| 4 | StatPoints | Available stat points | |
| 5 | SkillPoints | Available skill points | |
| 6 | Hitpoints | Current HP | Raw value (divide by 256) |
| 7 | MaxHP | Maximum HP | Raw value (divide by 256) |
| 8 | Manapoints | Current mana | Raw value (divide by 256) |
| 9 | MaxMana | Maximum mana | Raw value (divide by 256) |
| 10 | Stamina | Current stamina | |
| 11 | MaxStamina | Maximum stamina | |
| 12 | Level | Character level | |
| 13 | Experience | Experience points | |
| 14 | Gold | Gold in inventory | |
| 15 | GoldBank | Gold in stash | |

## Character Classes

| ID | Class Name | Description |
|----|------------|-------------|
| 0 | Amazon | Bow and spear specialist |
| 1 | Sorceress | Magic user |
| 2 | Necromancer | Death magic and minions |
| 3 | Paladin | Holy warrior |
| 4 | Barbarian | Melee combat specialist |
| 5 | Druid | Shape-shifting nature magic |
| 6 | Assassin | Martial arts and traps |

## Live Memory Examples

### Verified Character Data

#### Level 1 Sorceress "Xerzes"
- **Memory Address**: 0x0E45AB00
- **Class ID**: 1 (Sorceress)
- **Stats**: STR=10, ENE=35, DEX=25, VIT=10
- **HP/Mana**: 45/45 HP, 50/50 Mana
- **Position**: (5726, 4539) in Act 1

#### Level 99 Druid "Druid"
- **Memory Address**: 0x0E447D00
- **Class ID**: 5 (Druid)
- **Stats**: STR=27, ENE=20, DEX=28, VIT=25
- **HP/Mana**: 262/262 HP, 216/216 Mana
- **Position**: (5113, 5068) in Act 4
- **Experience**: 3,520,485,254

## Memory Access Methods

### Direct Process Memory Reading
```python
# Read from /proc/PID/mem (Linux/Wine)
with open('/proc/14/mem', 'rb') as mem:
    mem.seek(address)
    data = mem.read(size)
    value = struct.unpack('<L', data)[0]
```

### Address Calculation
```python
# Calculate absolute address from module + offset
d2client_base = 0x6FAB0000  # From process mapping
player_unit_offset = 0x11BBFC
absolute_address = d2client_base + player_unit_offset
```

### Structure Parsing
```python
# Parse UnitAny structure fields
dwType = struct.unpack('<L', data[0x00:0x04])[0]
dwTxtFileNo = struct.unpack('<L', data[0x04:0x08])[0]
pPlayerData = struct.unpack('<L', data[0x14:0x18])[0]
wX = struct.unpack('<H', data[0x8C:0x8E])[0]
wY = struct.unpack('<H', data[0x8E:0x90])[0]
```

## Validation and Testing

All structures and offsets have been verified through:
- ✅ Live memory extraction from running Game.exe
- ✅ Field-by-field validation with known values
- ✅ Cross-reference between multiple characters
- ✅ Structure size and alignment verification
- ✅ Pointer validation and dereferencing

## Notes and Limitations

- **Version Specific**: Offsets valid for Project Diablo 2 / D2 1.13c
- **Environment**: Tested in Wine/Linux container environment
- **Base Addresses**: May vary between game sessions
- **Static Offsets**: Should remain consistent for same game version
- **HP/Mana Values**: Stored as raw values (multiply/divide by 256)
- **Coordinates**: World units, not screen pixels