#include "ArrayEx.h"
#include "D2Structs.h"

#ifdef _DEFINE_VARS

enum {DLLNO_D2CLIENT, DLLNO_D2COMMON, DLLNO_D2GFX, DLLNO_D2LANG, DLLNO_D2WIN, DLLNO_D2NET, DLLNO_D2GAME, DLLNO_D2LAUNCH, DLLNO_FOG, DLLNO_BNCLIENT, DLLNO_STORM, DLLNO_D2CMP, DLLNO_D2MULTI};

#define DLLOFFSET(a1,b1) ((DLLNO_##a1)|((b1)<<8))
#define FUNCPTR(d1,v1,t1,t2,o1)	typedef t1 d1##_##v1##_t t2; d1##_##v1##_t *d1##_##v1 = (d1##_##v1##_t *)DLLOFFSET(d1,o1);
#define VARPTR(d1,v1,t1,o1)		typedef t1 d1##_##v1##_t;    d1##_##v1##_t *p_##d1##_##v1 = (d1##_##v1##_t *)DLLOFFSET(d1,o1);
#define ASMPTR(d1,v1,o1)			DWORD d1##_##v1 = DLLOFFSET(d1,o1);

#else

#define FUNCPTR(d1,v1,t1,t2,o1)	typedef t1 d1##_##v1##_t t2; extern d1##_##v1##_t *d1##_##v1;
#define VARPTR(d1,v1,t1,o1)		typedef t1 d1##_##v1##_t;    extern d1##_##v1##_t *p_##d1##_##v1;
#define ASMPTR(d1,v1,o1)			extern DWORD d1##_##v1;

#endif
#define _D2PTRS_START	D2CLIENT_GetMonsterTxt

FUNCPTR(D2CLIENT, GetMonsterTxt, MonsterTxt * __fastcall, (DWORD monno), 0x1230)
FUNCPTR(D2CLIENT, GetCurrentPlayerUnit, UnitAny* __stdcall, (VOID), 0x2C5C0) // Gets the current player unit based on game mode (singleplayer vs multiplayer)
FUNCPTR(D2CLIENT, GetMonsterDataTableCount, DWORD __stdcall, (VOID), 0x1690) // Gets the count/size of monster data table entries // returns maximum number of monsters for iteration loops
FUNCPTR(D2CLIENT, ClearPlayerSkillData, VOID __fastcall, (VOID), 0x16A0) // Clears player skill/action data fields // resets temporary skill state after skill processing
FUNCPTR(D2CLIENT, InitRegistrySettings, BOOL __stdcall, (VOID), 0x62CC0) // Initializes registry settings and configuration for Diablo 2
FUNCPTR(D2CLIENT, InitLanguageManager, BOOL __stdcall, (VOID), 0x62CF0) // Initializes language/localization system // loads LNG DLL and sets up string resources
FUNCPTR(D2CLIENT, GetDifficultySettings, BYTE __stdcall, (DWORD unused, INT difficultyIndex), 0x62DE0) // Ordinal 10002 // Retrieves difficulty settings from global configuration table with bounds checking
FUNCPTR(D2CLIENT, RecvCommand07, void __fastcall, (BYTE *cmdbuf), 0xAC3D0) 
FUNCPTR(D2CLIENT, RecvCommand08, void __fastcall, (BYTE *cmdbuf), 0xAC440) 
FUNCPTR(D2CLIENT, PrintGameString, void __stdcall, (wchar_t *wMessage, int nColor), 0x7D850)
FUNCPTR(D2CLIENT, PrintPartyString, void __stdcall, (wchar_t *wMessage, int nColor), 0x7D610)
FUNCPTR(D2CLIENT, PrintGameString2, void __stdcall, (char *szMessage), 0x7F780)
FUNCPTR(BNCLIENT, SendBNMessage,void __fastcall,(LPSTR lpMessage),0xC400)

FUNCPTR(D2CLIENT, GetPlayerXOffset, int __stdcall, (), 0x3F6C0)
FUNCPTR(D2CLIENT, GetPlayerYOffset, int __stdcall, (), 0x3F6D0)
FUNCPTR(D2CLIENT, GetUnitX, int __fastcall, (UnitAny* pUnit), 0x1630) // Gets X coordinate for any unit type // handles items, players, monsters with different storage methods
FUNCPTR(D2CLIENT, GetUnitY, int __fastcall, (UnitAny* pUnit), 0x1660) // Gets Y coordinate for any unit type // mirrors GetUnitX logic with offset +4 bytes for Y coordinate
FUNCPTR(D2CLIENT, GetValidSelectedUnit, UnitAny* __stdcall, (VOID), 0x1A80) // Gets the currently selected unit if valid and clickable, clears selection if invalid
FUNCPTR(D2CLIENT, IsUnitClickable, BOOL __stdcall, (UnitAny* pUnit, DWORD mouseX, DWORD mouseY, DWORD checkBounds), 0x568E0) // Checks if unit can be clicked based on game state, unit flags, and mouse position

FUNCPTR(D2WIN, TakeScreenshot, void __fastcall, (), 0x17EB0)

FUNCPTR(D2CLIENT, SetSelectedUnit_I, void __fastcall, (UnitAny *pUnit), 0x51860)
FUNCPTR(D2CLIENT, GetSelectedUnit, UnitAny * __stdcall, (), 0x51A80)
FUNCPTR(D2CLIENT, GetDifficulty, BYTE __stdcall, (), 0x41930)
FUNCPTR(D2CLIENT, GetUnknownFlag, DWORD __fastcall, (), 0x37A60)
FUNCPTR(D2CLIENT, GetGameInfo, GameStructInfo *__stdcall, (), 0x108B0)
FUNCPTR(D2CLIENT, GetAutomapSize, DWORD __stdcall, (), 0x5F970)

// Unicode and Object Lifecycle Management Functions
FUNCPTR(D2CLIENT, UnicodeArrayInitializer_1cb0, VOID __stdcall, (VOID), 0x1CB0) // Initializes 6 Unicode string array blocks of 0x400 strings each // establishes global Unicode string pool for game text
FUNCPTR(D2CLIENT, ObjectDestructor2_1d80, VOID __fastcall, (LPVOID pObject), 0x1D80) // C++ object destructor with conditional memory freeing // handles C++ object cleanup with null pointer validation
FUNCPTR(D2CLIENT, ObjectDestructor3_1db0, VOID __fastcall, (LPVOID pObject), 0x1DB0) // C++ object destructor variant with conditional memory deallocation // implements safe object destruction patterns
FUNCPTR(D2CLIENT, ObjectDestructor4_1de0, VOID __fastcall, (LPVOID pObject), 0x1DE0) // C++ object destructor with memory validation // performs defensive object cleanup with pointer safety checks
FUNCPTR(D2CLIENT, GetDataTableEntry9_1e10, LPVOID __fastcall, (DWORD index), 0x1E10) // Retrieves entry from data table with 0xc-byte structures // accesses game data table with bounds checking for 12-byte entries
FUNCPTR(D2CLIENT, GetUnitMaskValue_1e40, DWORD __fastcall, (UnitAny* pUnit, DWORD fieldOffset), 0x1E40) // Gets masked value from unit data structure // extracts specific bit patterns from unit flags or properties
FUNCPTR(D2CLIENT, DeleteCriticalSectionWrapper_1e70, VOID __stdcall, (CRITICAL_SECTION* pCritSec), 0x1E70) // Wrapper for DeleteCriticalSection with error handling // safely deletes critical section with exception handling
FUNCPTR(D2CLIENT, CriticalSectionDestructor_1e80, VOID __stdcall, (CRITICAL_SECTION* pCritSec), 0x1E80) // Critical section destructor with structured exception handling // comprehensive cleanup for thread synchronization objects
FUNCPTR(D2CLIENT, CleanupWithSEH_1ed0, VOID __fastcall, (LPVOID pData), 0x1ED0) // Cleanup function with structured exception handling // handles conditional memory freeing with zero initialization and uses __try/__except blocks for safe cleanup operations
FUNCPTR(D2CLIENT, ConditionalCleanup_1f10, VOID __fastcall, (LPVOID pObject), 0x1F10) // Conditional cleanup function performing memory validation and conditional freeing // checks pointer validity before deallocation with proper null pointer handling
FUNCPTR(D2CLIENT, ObjectLifecycleCleanup_1f70, VOID __fastcall, (LPVOID pObject), 0x1F70) // Object lifecycle cleanup function handling conditional memory deallocation // performs pointer validation and safe memory freeing for C++ object destruction patterns
FUNCPTR(D2CLIENT, MemoryCleanupWrapper_1fb0, VOID __fastcall, (LPVOID pMemory), 0x1FB0) // Memory cleanup wrapper function providing safe deallocation with pointer validation // implements standard C++ memory management patterns with null pointer safety checks
FUNCPTR(D2CLIENT, SafeMemoryDestructor_20d0, VOID __fastcall, (LPVOID pObject), 0x20D0) // Safe memory destructor implementing defensive deallocation patterns // validates memory pointers before freeing and ensures proper cleanup for object destruction sequences
FUNCPTR(D2CLIENT, FinalCleanupHandler_2100, VOID __fastcall, (LPVOID pObject), 0x2100) // Final cleanup handler for object destruction sequences // performs comprehensive memory validation and safe deallocation as the final step in C++ object lifecycle management

// Advanced Object Lifecycle and Container Management Functions
FUNCPTR(D2CLIENT, ObjectDestructor5_2130, VOID* __thiscall, (LPVOID pObject, BYTE bFreeMemory), 0x2130) // C++ object destructor with memory cleanup wrapper // calls MemoryCleanupWrapper_1fb0 then conditionally frees object memory with debug tracking
FUNCPTR(D2CLIENT, ObjectDestructor6_2160, VOID* __thiscall, (LPVOID pObject, BYTE bFreeMemory), 0x2160) // C++ object destructor with SEH constructor cleanup // calls ConstructorWithSEH_2050 then conditionally frees object memory with debug tracking
FUNCPTR(D2CLIENT, ContainerDestructorWithSEH_2190, VOID __stdcall, (VOID), 0x2190) // Container destructor with structured exception handling // sets up SEH frame and calls container cleanup function
FUNCPTR(D2CLIENT, LinkedListRemoverWithSEH_21d0, VOID __stdcall, (LPVOID pListNode), 0x21D0) // Linked list node remover with structured exception handling // sets up SEH frame and calls linked list cleanup function
FUNCPTR(D2CLIENT, DoublyLinkedListRemover_2210, VOID __stdcall, (LPVOID pListNode), 0x2210) // Doubly-linked list node remover // removes nodes from two linked lists with pointer arithmetic and link updates
FUNCPTR(D2CLIENT, HashObjectConstructor_22c0, LPVOID __stdcall, (LPVOID pHashObject), 0x22C0) // Hash object constructor with SEH // initializes hash object with vtable pointer, sets up hash mask and counter fields with structured exception handling
FUNCPTR(D2CLIENT, GameDataManagerCleanup_2320, VOID __stdcall, (VOID), 0x2320) // Game data manager cleanup // cleans up hash object chunks and game data entries with debug memory tracking for USGAMEDATA structures
FUNCPTR(D2CLIENT, HashTableIterator_2360, VOID __stdcall, (INT nMode), 0x2360) // Hash table iterator with conditional cleanup // iterates through hash table buckets, either calling destructor or performing linked list removal based on parameter
FUNCPTR(D2CLIENT, LinkedListManipulator_2400, VOID __stdcall, (INT nParam1, INT nParam2), 0x2400) // Linked list manipulator // performs complex linked list operations including node removal and insertion with pointer arithmetic calculations
FUNCPTR(D2CLIENT, GameDataAllocatorWithSEH_24b0, LPVOID __stdcall, (DWORD dwParam1, INT nParam2, UINT uFlags), 0x24B0) // Game data allocator with SEH // allocates USGAMEDATA structures with exception handling, initializes fields to zero, and integrates with linked list
FUNCPTR(D2CLIENT, ExplicitListDestructor_2540, VOID __stdcall, (VOID), 0x2540) // Explicit list destructor // iterates through list elements calling cleanup function, then frees list memory with debug tracking for TSExplicitList
FUNCPTR(D2CLIENT, LinkedListNodeRemoverWithSEH_2580, VOID __stdcall, (LPVOID pListNode), 0x2580) // Linked list node remover with SEH // removes node from linked list with structured exception handling and proper pointer link updates
FUNCPTR(D2CLIENT, ObjectDestructor7_2600, VOID* __thiscall, (LPVOID pObject, BYTE bFreeMemory), 0x2600) // C++ object destructor with SEH cleanup // calls CleanupWithSEH_1ed0 then conditionally frees object memory with debug tracking

// Container Management and Hash Table System Functions
FUNCPTR(D2CLIENT, GameDataContainerDestructorWithSEH_2630, VOID __stdcall, (VOID), 0x2630) // Game data container destructor with SEH // sets up structured exception handling frame and calls game data container cleanup function
FUNCPTR(D2CLIENT, ComplexObjectConstructor_2670, LPVOID __stdcall, (LPVOID pObject), 0x2670) // Complex object constructor with multiple initialization phases // sets up vtable, initializes hash tables and lists with proper size tracking and exception handling
FUNCPTR(D2CLIENT, GameDataContainerCleanup_2700, VOID __stdcall, (VOID), 0x2700) // Game data container cleanup // iterates through USGAMEDATA container elements (0x1df4 byte structures) calling LinkedListRemoverWithSEH_21d0, then frees container memory
FUNCPTR(D2CLIENT, HashObjectChunkDestructorWithSEH_2750, VOID __stdcall, (LPVOID pHashChunk), 0x2750) // Hash object chunk destructor with SEH // removes linked list node from hash structure then calls GameDataContainerCleanup_2700 with exception handling
FUNCPTR(D2CLIENT, HashTableManagerConstructor_27d0, LPVOID __stdcall, (LPVOID pHashManager), 0x27D0) // Hash table manager constructor // initializes vtable, hash table buckets, sets capacity to 3 buckets, and initializes each bucket with proper hash linking
FUNCPTR(D2CLIENT, HashTableInitializer_28a0, VOID __stdcall, (LPVOID pHashTable), 0x28A0) // Hash table initializer // sets up hash table structure with debug pattern 0xdddddddd, initializes circular linked list pointers and hash mask
FUNCPTR(D2CLIENT, HashTableInitializer16_2900, VOID __stdcall, (LPVOID pHashTable), 0x2900) // Hash table initializer variant // sets up hash table structure with size 0x10, initializes circular linked list pointers and hash mask for 16-bucket hash table
FUNCPTR(D2CLIENT, DynamicContainerResizer_2960, VOID __stdcall, (VOID), 0x2960) // Dynamic container resizer // expands or shrinks container capacity, initializes new elements, destroys excess elements
FUNCPTR(D2CLIENT, ContainerElementInitializerWithSEH_29f0, VOID __stdcall, (LPVOID pElement), 0x29F0) // Container element initializer with SEH // safely initializes container element using HashTableInitializer_28a0 with null pointer checking and exception handling
FUNCPTR(D2CLIENT, HashTableSizeCalculator_2a40, UINT __stdcall, (INT nDesiredSize), 0x2A40) // Hash table size calculator // calculates optimal hash table size using bit manipulation, ensures power-of-2 sizing with maximum limit of 0x15 (21) buckets
FUNCPTR(D2CLIENT, ContainerReallocator_2a80, VOID __stdcall, (VOID), 0x2A80) // Container reallocator // reallocates container memory using realloc, copies existing elements, handles fallback allocation and cleanup
FUNCPTR(D2CLIENT, ElementCopyConstructorWithSEH_2b40, VOID __thiscall, (LPVOID pSource, LPVOID pDestination), 0x2B40) // Element copy constructor with SEH // safely copies container element with null pointer checking and exception handling
FUNCPTR(D2CLIENT, HashTableElementCopier_2b90, VOID __stdcall, (LPVOID pDestination, LPVOID pSource), 0x2B90) // Hash table element copier // copies hash table element data, sets up circular linked list pointers and hash mask from source element

FUNCPTR(D2CLIENT, NewAutomapCell, AutomapCell * __fastcall, (), 0x5F6B0)
FUNCPTR(D2CLIENT, AddAutomapCell, void __fastcall, (AutomapCell *aCell, AutomapCell **node), 0x61320)
FUNCPTR(D2CLIENT, RevealAutomapRoom, void __stdcall, (Room1 *pRoom1, DWORD dwClipFlag, AutomapLayer *aLayer), 0x62580)
FUNCPTR(D2CLIENT, InitAutomapLayer_I, AutomapLayer* __fastcall, (DWORD nLayerNo), 0x62710)
FUNCPTR(D2CLIENT, GetMonsterOwner, DWORD __fastcall, (DWORD nMonsterId), 0x216A0)
FUNCPTR(D2CLIENT, GetUiVar_I, DWORD __fastcall, (DWORD dwVarNo), 0xBE400)
FUNCPTR(D2CLIENT, SetUIState, DWORD __fastcall, (DWORD varno, DWORD howset, DWORD unknown1), 0xC2794)
FUNCPTR(D2CLIENT, GetItemNameString, void __stdcall, (UnitAny *pItem, wchar_t *wItemName, int nLen), 0x914F0)
FUNCPTR(D2CLIENT, CalculateShake, void __stdcall, (DWORD *dwPosX, DWORD *dwPosY), 0x8AFD0)
FUNCPTR(D2CLIENT, GetPlayerUnit, UnitAny*  __stdcall,(),0xA4D60)
FUNCPTR(D2CLIENT, DrawRectFrame, VOID __fastcall, (DWORD Rect), 0xBE4C0)
FUNCPTR(D2CLIENT, ExitGame, VOID __fastcall, (VOID), 0x42850)
FUNCPTR(D2CLIENT, Attack, VOID __stdcall, (AttackStruct* Attack, BOOL AttackingUnit), 0x1A060)
FUNCPTR(D2CLIENT, GetItemName, BOOL __stdcall, (UnitAny* pItem, wchar_t* wBuffer, DWORD dwSize), 0x914F0)
FUNCPTR(D2CLIENT, AcceptTrade, VOID __fastcall, (VOID), 0x59600)
FUNCPTR(D2CLIENT, DrawPartyName ,void __stdcall, (LPSTR pR,DWORD yPos,DWORD Col,DWORD UNK), 0x75780)
FUNCPTR(D2CLIENT, CancelTrade, VOID __fastcall, (VOID), 0x8CB90)
FUNCPTR(D2CLIENT, GetMouseXOffset, DWORD __fastcall, (VOID), 0x3F6C0)
FUNCPTR(D2CLIENT, GetMouseYOffset, DWORD __fastcall, (VOID), 0x3F6D0)
FUNCPTR(D2CLIENT, GameShowAttack, DWORD __stdcall, (UnitAny* pUnit, DWORD dwSpell, DWORD dwSkillLevel, DWORD _1), 0xA2C90)
FUNCPTR(D2CLIENT, xGetNextPartyPlayer, PartyPlayer * __fastcall, (PartyPlayer *pla), 0x9D2B0)
FUNCPTR(D2CLIENT, FindRosterUnitByPlayerId, int __fastcall, (DWORD unitId, DWORD playerId), 0x4D630) // Finds roster unit by player ID
FUNCPTR(D2CLIENT, IsInPartyWithOtherMembers, BOOL __fastcall, (DWORD unitId), 0x4D9D0) // Checks if player is in party with others
FUNCPTR(D2CLIENT, IsPlayerHostileOrPK, BOOL __stdcall, (), 0x4DB90) // Checks if player has hostile status or PK flag

// Player Management and State Validation Functions
FUNCPTR(D2CLIENT, ProcessUnitTypeValidation, VOID __stdcall, (DWORD param), 0x8E20) // Validates unit types and processes conditional logic for types 2-6, includes parameter validation and error handling with exit codes
FUNCPTR(D2CLIENT, DispatchArrayLookup, VOID __stdcall, (DWORD param), 0x8F40) // Array bounds checking and dispatch function with error handling, looks up values in array and calls processing function if valid
FUNCPTR(D2CLIENT, ValidatePlayerCharacterState, DWORD __stdcall, (DWORD *pParam), 0x8F90) // Validates player character state and class-based logic, includes level checking and conditional processing based on character class
FUNCPTR(D2CLIENT, UpdatePlayerReference, DWORD __stdcall, (DWORD *pParam), 0x9030) // Updates player references in Player.cpp, validates and updates unit references with error checking and state management
FUNCPTR(D2CLIENT, ProcessActivePlayersData, VOID __stdcall, (VOID), 0x90B0) // Processes data for all active players, iterates through player lists and calls update functions for each valid player unit
FUNCPTR(D2CLIENT, CleanupPlayerInstance, VOID __stdcall, (VOID), 0x9130) // Comprehensive player cleanup including removing from arrays, clearing graphics data, freeing resources, and updating global state
FUNCPTR(D2CLIENT, InitializePlayerInstance, VOID __thiscall, (LPVOID pThis, DWORD param1, DWORD param2), 0x91E0) // Comprehensive player initialization including registering in arrays, setting up graphics, applying stats, and configuring initial state
FUNCPTR(D2CLIENT, HandlePlayerMovementAction, DWORD __stdcall, (VOID), 0x9350) // Handles player movement actions including skill data clearing, movement validation, and network packet sending
FUNCPTR(D2CLIENT, ProcessPlayerItemInteraction, VOID __stdcall, (DWORD param), 0x94E0) // Complex item interaction processing including inventory management, item transfer validation, and player-to-player item exchanges
FUNCPTR(D2CLIENT, ValidatePlayerStateFlags, VOID __stdcall, (DWORD param), 0x97D0) // Validates player state flags and applies appropriate state changes, includes flag bit manipulation and conditional processing

// Player Advanced State Management and Action Processing Functions
FUNCPTR(D2CLIENT, UpdatePlayerStatusFlags, VOID __thiscall, (LPVOID pThis, DWORD param), 0x9710) // Updates player status and flags, clears status bits, and handles player mode changes with position updates
FUNCPTR(D2CLIENT, ProcessPlayerModeTransition, DWORD __fastcall, (DWORD mode, DWORD *pPlayer, DWORD *pParams, DWORD param4), 0x9830) // Complex player mode transition handler with multiple states (0-25), handles movement, combat, teleportation, and death states
FUNCPTR(D2CLIENT, HandlePlayerStateLoss, VOID __stdcall, (VOID), 0x9D80) // Handles player state loss/death processing, validates stats and processes resurrection or state restoration
FUNCPTR(D2CLIENT, ProcessPlayerTransportAction, VOID __fastcall, (DWORD param), 0x9EF0) // Processes player transport actions like waypoints and portals, handles teleportation and area transitions
FUNCPTR(D2CLIENT, ExecutePlayerUnitMode, DWORD __thiscall, (DWORD param1, DWORD param2, DWORD pPlayer), 0xA010) // Executes player unit mode changes, updates position and validates unit state transitions
FUNCPTR(D2CLIENT, ProcessPlayerMovementRequest, VOID __stdcall, (DWORD *pRequest, DWORD param), 0xA060) // Comprehensive movement request processing from UnitMode.cpp, handles walk/run actions with network packet sending
FUNCPTR(D2CLIENT, HandlePlayerStateChange, VOID __stdcall, (VOID), 0xAAA0) // Handles player state changes and mode transitions for different player modes (2, 3, 6)
FUNCPTR(D2CLIENT, ProcessPlayerInteractionCommand, VOID __stdcall, (LPBYTE pCommand, DWORD param), 0xAB20) // Complex interaction command processor handling unit interactions, quest validation, and monster encounters
FUNCPTR(D2CLIENT, CalculatePlayerSkillRange, DWORD __stdcall, (DWORD param), 0xB1D0) // Calculates skill range and targeting for player abilities, handles position interpolation and skill validation
FUNCPTR(D2CLIENT, InitializePlayerTransport, VOID __stdcall, (VOID), 0xB320) // Initializes player transport systems and processes transport actions with proper state setup
FUNCPTR(D2CLIENT, ProcessNPCInteraction, VOID __stdcall, (DWORD unitId), 0xB360) // Processes NPC interactions including shop transactions, quest NPCs, and monster encounters with validation
FUNCPTR(D2CLIENT, HandlePlayerTeleportation, VOID __stdcall, (VOID), 0xB540) // Handles player teleportation mechanics including waypoint usage and area transitions with position validation
FUNCPTR(D2CLIENT, ValidatePlayerActionFlags, DWORD __stdcall, (VOID), 0xB620) // Validates player action flags and processes player action validation with error checking and state management

// Player Action Processing and Game State Management Functions
FUNCPTR(D2CLIENT, ProcessPlayerTargetAction, VOID __thiscall, (LPVOID pThis, DWORD param), 0xB700) // Processes player targeting actions with validation, handles skill range checking and target validation for combat and interactions
FUNCPTR(D2CLIENT, HandlePlayerClickAction, VOID __stdcall, (VOID), 0xB7F0) // Complex click action handler from Player.cpp, processes movement, targeting, NPC interactions, and combat actions with comprehensive validation
FUNCPTR(D2CLIENT, ProcessPlayerSkillCasting, DWORD __stdcall, (VOID), 0xBCC0) // Processes player skill casting with mana validation, stamina checking, and skill execution with target validation
FUNCPTR(D2CLIENT, UpdatePlayerClientState, VOID __stdcall, (VOID), 0xBE90) // Updates player client state including area transitions, PvP flags, and game state synchronization with server
FUNCPTR(D2CLIENT, HandleMouseClickDispatcher, DWORD* __stdcall, (DWORD param1, DWORD param2, DWORD* pParams, DWORD param4, DWORD param5, DWORD param6, DWORD param7, DWORD param8, DWORD param9, DWORD param10, DWORD param11, DWORD param12, BYTE flags), 0xBF4C) // Mouse click dispatcher handling left/right clicks, shift clicks, and skill activation with coordinate conversion and target selection
FUNCPTR(D2CLIENT, ProcessPlayerModeUpdate, VOID __stdcall, (DWORD* pPlayer), 0xC150) // Comprehensive player mode update processor handling all player states, animations, teleportation, and area transitions
FUNCPTR(D2CLIENT, ResetGlobalFlag, VOID __stdcall, (VOID), 0xC720) // Simple global flag reset function for game state management
FUNCPTR(D2CLIENT, UpdateGameCoordinates, VOID __fastcall, (DWORD param), 0xC740) // Updates game coordinates from network packet data for position synchronization
FUNCPTR(D2CLIENT, FindModeTableIndex, DWORD __fastcall, (DWORD param1, DWORD param2), 0xC890) // Searches mode table for matching entry and returns index, used for mode lookup operations
FUNCPTR(D2CLIENT, UpdateModeTableEntry, VOID __fastcall, (DWORD param1, DWORD param2), 0xC940) // Updates mode table entry with new values for player state management and mode transitions
FUNCPTR(D2CLIENT, GetGameDifficulty, BYTE __stdcall, (VOID), 0xC980) // Returns current game difficulty level (Normal, Nightmare, Hell) based on game state and conditions
FUNCPTR(D2CLIENT, SendPlayerStatusUpdate, VOID __fastcall, (DWORD param), 0xCA00) // Sends player status updates via network packets for multiplayer synchronization
FUNCPTR(D2CLIENT, CleanupGameResources, VOID __stdcall, (VOID), 0xCAD0) // Comprehensive game resource cleanup including memory deallocation and resource management for game shutdown
FUNCPTR(D2CLIENT, InitializeGameState, VOID __stdcall, (VOID), 0xCC00) // Initializes all game state variables and data structures, sets up GAMEOVER state and resets global game variables

FUNCPTR(D2COMMON, AbsScreenToMap, void __stdcall, (long *pX, long *pY), -10474)
FUNCPTR(D2COMMON, CheckCollision, DWORD __stdcall, (LPROOM1 pRoom, DWORD X, DWORD Y, DWORD dwBitMask), -10482)
FUNCPTR(D2COMMON, GetUnitState, INT __stdcall, (LPUNITANY Unit, DWORD State), -10494)
FUNCPTR(D2CLIENT, DrawManaOrb, void __stdcall, (), 0x27A90)

//extra
FUNCPTR(D2CLIENT, ClearScreen, VOID __fastcall, (VOID), 0x492F0)
FUNCPTR(D2CLIENT, GetQuestInfo, VOID* __stdcall, (VOID), 0x45A00)
FUNCPTR(D2CLIENT, UnitTestSelect, DWORD __stdcall, (UnitAny* pUnit, DWORD _1, DWORD _2, DWORD _3), 0xA68E0)
FUNCPTR(D2CLIENT, FindServerSideUnit, UnitAny* __fastcall, (DWORD dwId, DWORD dwType), 0x19438)
FUNCPTR(D2CLIENT, FindClientSideUnit, UnitAny* __fastcall, (DWORD dwId, DWORD dwType), 0xA5B20)
FUNCPTR(D2CLIENT, SetUIVar, DWORD __fastcall, (DWORD varno, DWORD howset, DWORD unknown1), 0xC2790)
FUNCPTR(D2CLIENT, HandleMapClick, VOID __stdcall, (DWORD clickType, DWORD mouseX, DWORD mouseY, DWORD mouseFlags), 0x1BF20) // // Handles mouse clicks on game map
FUNCPTR(D2CLIENT, HandleLeftClick, BOOL __stdcall, (VOID), 0xCBDE0) // Handles left mouse button clicks on units // processes unit interaction and skill usage
FUNCPTR(D2CLIENT, HandleRightClick, BOOL __stdcall, (VOID), 0xCBC40) // Handles right mouse button clicks on units // processes skill usage and unit targeting
FUNCPTR(D2CLIENT, HandleShiftClick, BOOL __stdcall, (VOID), 0xCBBC0) // Handles shift+click combinations // processes forced attack and skill targeting
FUNCPTR(D2CLIENT, GetCursorItem, UnitAny* __fastcall, (VOID), 0x16020)
FUNCPTR(D2CLIENT, UpdateCurrentPlayerSkillState, VOID __stdcall, (DWORD currentTick), 0xF5660) // Updates current player skill state and manages timing
FUNCPTR(D2CLIENT, LeftClickItem, VOID __stdcall, (UnitAny* pPlayer, Inventory* pInventory, INT x, INT y, DWORD dwClickType, InventoryLayout* pLayout, DWORD Location), 0x96AA0)
FUNCPTR(D2CLIENT, CloseNPCInteract, VOID __fastcall, (VOID), 0x48350)
FUNCPTR(D2CLIENT, CloseInteract, VOID __fastcall, (VOID), 0x43870)
FUNCPTR(D2CLIENT, DrawGameExitButton, VOID __stdcall, (VOID), 0xD8320) // Updated 1.13c // Draws and handles the game exit button in the UI
FUNCPTR(D2CLIENT, IsMouseWithinExitButton, BOOL __fastcall, (INT mouseX), 0xD65A0) // Updated 1.13c // Checks if mouse is within exit button bounds
FUNCPTR(D2CLIENT, HandleExitButtonClick, VOID __stdcall, (VOID), 0xD7EF0) // Updated 1.13c // Handles exit button click and game termination
FUNCPTR(D2CLIENT, GetGameStateFlag, DWORD __stdcall, (VOID), 0x112E20) // Updated 1.13c // Returns current game state flag (ordinal 10001)
FUNCPTR(D2CLIENT, SendActivateAppMessage, VOID __stdcall, (VOID), 0x108C0) // Ordinal 10003 // Sends WM_ACTIVATEAPP message to game window for application activation/deactivation handling
FUNCPTR(D2CLIENT, ConvertScreenToGameCoords, VOID __fastcall, (VOID), 0xEF5F0) // Converts screen coordinates to game world coordinates with perspective projection and camera offset handling
FUNCPTR(D2CLIENT, ChatBoxHandler, DWORD __stdcall, (MSG* pMsg), 0x70C40)
FUNCPTR(D2CLIENT, InitInventory, VOID __fastcall, (VOID), 0x908C0)
FUNCPTR(D2CLIENT, FixShopActions, VOID __fastcall, (VOID), 0x47AB0)
FUNCPTR(D2CLIENT, submitItem, VOID __fastcall, (DWORD dwItemId), 0x45FB0)
FUNCPTR(D2CLIENT, GetUnitHPPercent, DWORD __fastcall, (DWORD dwUnitId), 0x21590)
FUNCPTR(D2CLIENT, GetMercUnit, UnitAny* __fastcall, (VOID), 0x97CD0)
FUNCPTR(D2CLIENT, ShopAction, VOID __fastcall, (UnitAny* pItem, UnitAny* pNpc, UnitAny* pNpc2, DWORD dwSell, DWORD dwItemCost, DWORD dwMode, DWORD _2, DWORD _3), 0x47D60)
FUNCPTR(D2CLIENT, GetCurrentInteractingNPC, UnitAny* __fastcall, (VOID), 0x7C5C0)
FUNCPTR(D2CLIENT, PerformGoldDialogAction, VOID __fastcall, (VOID), 0xBFDF0)
FUNCPTR(D2CLIENT, InvokeCatchBlock, void* __cdecl, (EHExceptionRecord* pExceptionRecord, EHRegistrationNode* pRegistrationNode, _CONTEXT* pContext, _s_FuncInfo* pFuncInfo, void* pFramePointer, int nCatchDepth, unsigned long dwFlags), 0x7B7EC) // Visual Studio C++ runtime exception handling // invokes catch block with proper frame setup
FUNCPTR(D2CLIENT, ExecuteCatchHandler, VOID __cdecl, (EHExceptionRecord* pExceptionRecord, EHRegistrationNode* pRegistrationNode, _CONTEXT* pContext, void* pFramePointer, _s_FuncInfo* pFuncInfo, _s_HandlerType* pHandlerType, _s_CatchableType* pCatchableType, _s_TryBlockMapEntry* pTryBlockEntry, int nCatchDepth, EHRegistrationNode* pNestedRegistration, unsigned char bCatchFlag), 0x7BB2C) // Main exception catch handler // orchestrates catch process with object building and frame unwinding
FUNCPTR(D2CLIENT, FileReadWithLock, size_t __cdecl, (void* pDestBuffer, size_t dwElementSize, size_t dwCount, FILE* pFile), 0xB40C5) // Visual Studio C++ runtime // thread-safe file reading with buffered I/O handling
FUNCPTR(D2CLIENT, ConvertLongDoubleToDouble_1, INTRNCVT_STATUS __cdecl, (_LDBL12* pLongDouble, _CRT_DOUBLE* pDouble), 0x7C2A4) // Visual Studio C++ runtime // converts 12-byte long double to 8-byte double (variant 1)
FUNCPTR(D2CLIENT, ConvertLongDoubleToDouble_2, INTRNCVT_STATUS __cdecl, (_LDBL12* pLongDouble, _CRT_DOUBLE* pDouble), 0x7C2BA) // Visual Studio C++ runtime // converts 12-byte long double to 8-byte double (variant 2)
FUNCPTR(D2CLIENT, LockFileHandle, VOID __cdecl, (int nFileIndex, void* pFile), 0xB55BF) // Visual Studio C++ runtime // locks file handles for thread-safe I/O operations
FUNCPTR(D2CLIENT, UnlockFileHandle, VOID __cdecl, (int nFileIndex, void* pFile), 0xB5611) // Visual Studio C++ runtime // unlocks file handles after thread-safe I/O operations
FUNCPTR(D2CLIENT, InvokeMemberFunction, VOID, (DWORD param1, void* pFunctionPointer), 0x7AE1A) // Visual Studio C++ runtime // invokes C++ member functions with proper this pointer and locking
FUNCPTR(D2CLIENT, IsControlCharacter, int __cdecl, (int nCharacter), 0xB3FD3) // Visual Studio C++ runtime // checks if character is control character using locale tables
FUNCPTR(D2CLIENT, UngetCharacterFromFile, int __cdecl, (int nCharacter, FILE* pFile), 0xBA975) // Visual Studio C++ runtime // pushes character back to file stream for parsing operations
FUNCPTR(D2CLIENT, FindExceptionHandler, VOID __cdecl, (EHExceptionRecord* pExceptionRecord, EHRegistrationNode* pRegistrationNode, _CONTEXT* pContext, void* pFramePointer, _s_FuncInfo* pFuncInfo, unsigned char bRecursive, int nTryLevel, EHRegistrationNode* pNestedRegistration), 0x7BC51) // Visual Studio C++ runtime // finds appropriate exception handlers based on exception type and execution state
FUNCPTR(D2CLIENT, FindForeignExceptionHandler, VOID __cdecl, (EHExceptionRecord* pExceptionRecord, EHRegistrationNode* pRegistrationNode, _CONTEXT* pContext, void* pFramePointer, _s_FuncInfo* pFuncInfo, int nCurrentState, int nTryLevel, EHRegistrationNode* pNestedRegistration), 0x7BB93) // Visual Studio C++ runtime // handles foreign (non-C++) exceptions like SEH with structured exception translators
FUNCPTR(D2CLIENT, SearchUnitByIdAndType, VOID __fastcall, (DWORD dwUnitId, DWORD dwUnitType), 0x55B40) // Diablo 2 unit search wrapper // calls hash table searcher to find units by ID and type
FUNCPTR(D2CLIENT, SearchUnitInHashTable, UnitAny* __fastcall, (DWORD dwUnitId, void* pHashTableEntry, DWORD dwExpectedUnitType), 0x54E20) // Core unit search function // searches hash table for units with collision resolution and type validation
FUNCPTR(D2CLIENT, UnlockCriticalSection, VOID __cdecl, (int nSectionIndex), 0xB47AB) // Visual Studio C++ runtime // releases critical section locks by index from global array
FUNCPTR(D2CLIENT, UnlockSection8, VOID, (VOID), 0xB3516) // Visual Studio C++ runtime // unlocks critical section index 8
FUNCPTR(D2CLIENT, UnlockSection10, VOID, (VOID), 0xB4857) // Visual Studio C++ runtime // unlocks critical section index 10
FUNCPTR(D2CLIENT, LinkedListRemove_1150, VOID, (int* pListNode), 0xB1150) // Visual Studio C++ runtime // removes node from doubly-linked list with pointer updates
FUNCPTR(D2CLIENT, GetDataTableEntry_1260, int, (int nIndex), 0xB1260) // Diablo 2 data table lookup // accesses game data structures with bounds checking
FUNCPTR(D2CLIENT, ExtendFileSize, VOID __cdecl, (UINT nFileHandle, int nNewSize), 0xBBB34) // Visual Studio C++ runtime // extends file size with null padding and error handling
FUNCPTR(D2CLIENT, WriteFileWithTextMode, VOID __cdecl, (UINT nFileHandle, char* pBuffer, UINT nBytes), 0xB5943) // Visual Studio C++ runtime // text mode write with LF to CRLF conversion
FUNCPTR(D2CLIENT, GetErrnoPointer, int*, (VOID), 0xB579C) // Visual Studio C++ runtime // returns pointer to thread-local errno variable
FUNCPTR(D2CLIENT, GetDosErrnoPointer, ulong*, (VOID), 0xB57A5) // Visual Studio C++ runtime // returns pointer to thread-local DOS errno variable
FUNCPTR(D2CLIENT, CheckStackCookie, VOID __cdecl, (UINT nStackCookie), 0xB77D2) // Visual Studio C++ runtime // stack overflow protection validation
FUNCPTR(D2CLIENT, PointerChainResolver_11f0, VOID, (VOID), 0xB11F0) // Visual Studio C++ runtime // resolves pointer chain with complex offset calculations and negative address handling
FUNCPTR(D2CLIENT, GetDataTableEntry2_12b0, int, (int nIndex), 0xB12B0) // Diablo 2 data table access // gets entry by index with bounds checking, returns 0x3c-byte structures
FUNCPTR(D2CLIENT, CallFunctionLoop_12e0, VOID, (int nCount, void* pFunction), 0xB12E0) // Visual Studio C++ runtime // calls function pointer in loop for specified count
FUNCPTR(D2CLIENT, GetDataTableEntry3_1300, int, (int nIndex), 0xB1300) // Diablo 2 data table access // gets entry by index with bounds checking, returns 0xc4-byte structures
FUNCPTR(D2CLIENT, RandomNumberGenerator_1330, UINT __fastcall, (ulonglong* pSeed), 0xB1330) // Diablo 2 random number generator // linear congruential generator with seed 0x6ac690c5
FUNCPTR(D2CLIENT, RandomNumberGenerator2_1380, UINT __fastcall, (ulonglong* pSeed), 0xB1380) // Diablo 2 random number generator variant // same LCG algorithm with different parameter passing
FUNCPTR(D2CLIENT, SetBitFlags_13d0, VOID __fastcall, (UINT dwFlags, int bSet), 0xB13D0) // Diablo 2 bit manipulation // sets or clears bit flags at offset 0xc4 in structure
FUNCPTR(D2CLIENT, FindRoomByCoordinates_1400, int, (int nX, int nY), 0xB1400) // Diablo 2 room search // finds room by X/Y coordinates with bounds checking and adjacent room search
FUNCPTR(D2CLIENT, MulDiv_14a0, int __fastcall, (UINT nMultiplicand, int nMultiplier), 0xB14A0) // Visual Studio C++ runtime // multiply-divide operation with overflow protection and 64-bit intermediate calculations
FUNCPTR(D2CLIENT, CheckCollisionMask_1510, UINT __fastcall, (DWORD dwParam1, UINT nCoordinate), 0xB1510) // Diablo 2 collision detection // checks collision mask bits for map coordinates using bit manipulation
FUNCPTR(D2CLIENT, GetDataTableEntry4_1580, int, (int nIndex), 0xB1580) // Diablo 2 data table access // gets entry by index with bounds checking, returns 0x1a4-byte structures
FUNCPTR(D2CLIENT, GetDataTableEntry5_15b0, int, (int nIndex), 0xB15B0) // Diablo 2 data table access // gets entry by index with bounds checking, returns 0x23c-byte structures
FUNCPTR(D2CLIENT, GetDataTableSubEntry_15e0, int __fastcall, (DWORD dwParam1, int nSubIndex), 0xB15E0) // Diablo 2 data table access // gets sub-entry from 0x23c-byte structure using array indexing with bounds checking
FUNCPTR(D2CLIENT, GetUnitValue_16e0, DWORD, (VOID), 0xB16E0) // Diablo 2 unit access // gets value from unit structure, validates unit type and retrieves data from offset 0x2c
FUNCPTR(D2CLIENT, GetUnitLevelId_1700, int, (VOID), 0xB1700) // Diablo 2 unit access // gets level/area ID from unit, validates unit type and looks up level data from data tables
FUNCPTR(D2CLIENT, NullFunction_1740, VOID, (VOID), 0xB1740) // Empty function // returns immediately without performing any operations
FUNCPTR(D2CLIENT, CheckCollisionMask2_1760, UINT __fastcall, (DWORD dwParam1, UINT nCoordinate), 0xB1760) // Diablo 2 collision detection variant // checks collision mask bits at offset 0xc with bit manipulation
FUNCPTR(D2CLIENT, GetDefaultValue_17b0, int, (VOID), 0xB17B0) // Diablo 2 data validation // gets value from data table with default fallback (0x14) for invalid entries
FUNCPTR(D2CLIENT, GetLinkedTableEntry_17f0, int, (VOID), 0xB17F0) // Diablo 2 linked table access // gets entry from secondary table via reference from primary table, returns 0x120-byte structures
FUNCPTR(D2CLIENT, GetDataTableEntry6_1840, int, (int nIndex), 0xB1840) // Diablo 2 data table access // gets entry by index with bounds checking, returns 0x128-byte structures
FUNCPTR(D2CLIENT, GetDataTableEntry7_1870, int, (int nIndex), 0xB1870) // Diablo 2 data table access // gets entry by index with bounds checking, returns 0x1b8-byte structures
FUNCPTR(D2CLIENT, GetDataTableEntry8_18a0, int, (int nIndex), 0xB18A0) // Diablo 2 data table access // gets entry by index with bounds checking, returns 0x14c-byte structures
FUNCPTR(D2CLIENT, RandomNumberGeneratorRange_18d0, int __fastcall, (ulonglong* pSeed), 0xB18D0) // Diablo 2 random number generator with range // generates random number within specified range using LCG algorithm
FUNCPTR(D2CLIENT, RC4CipherOperation_1920, VOID, (int pBuffer, UINT nBytes), 0xB1920) // RC4 stream cipher operation // encrypts/decrypts data using RC4 algorithm with S-box state manipulation
FUNCPTR(D2CLIENT, ClearStructure_19b0, VOID, (DWORD* pStruct), 0xB19B0) // Memory initialization // clears 5 DWORD structure (20 bytes) by setting all fields to zero
FUNCPTR(D2CLIENT, InitializeWithSEH_1a00, VOID, (VOID), 0xB1A00) // Initialization function with structured exception handling // calls initialization with SEH frame setup and cleanup
FUNCPTR(D2CLIENT, WardenClientFree_1a40, VOID, (VOID), 0xB1A40) // Warden anti-cheat system // frees memory allocated for Warden client components with debug tracking
FUNCPTR(D2CLIENT, GetUnitDataByte_1a60, UINT __fastcall, (BYTE nIndex), 0xB1A60) // Diablo 2 unit data access // gets byte value from unit structure with bounds checking (max index 0x10)
FUNCPTR(D2CLIENT, GetUnitStatWithValidation_1a80, DWORD, (VOID), 0xB1A80) // Diablo 2 unit statistics // gets unit stat with validation and error handling using D2Common ordinals
FUNCPTR(D2CLIENT, GetUnitStatSafe_1af0, DWORD, (VOID), 0xB1AF0) // Diablo 2 unit statistics // safe unit stat accessor with null pointer checks and D2Common integration
FUNCPTR(D2CLIENT, GetUnitStatValue_1b50, DWORD, (VOID), 0xB1B50) // Diablo 2 unit statistics // gets specific unit stat value with validation and D2Common ordinal calls
FUNCPTR(D2CLIENT, GetUnitEquipmentData_1bc0, int, (VOID), 0xB1BC0) // Diablo 2 equipment system // gets unit equipment data with stat validation and inventory lookup
FUNCPTR(D2CLIENT, CheckCollisionMask3_1c10, UINT __fastcall, (DWORD dwParam1, UINT nCoordinate), 0xB1C10) // Diablo 2 collision detection variant // checks collision mask bits at offset 0xf0 with bit manipulation
FUNCPTR(D2CLIENT, ObjectDestructor_1c80, VOID* __thiscall, (BYTE bFreeMemory), 0xB1C80) // C++ object destructor // calls cleanup function and conditionally frees memory with debug tracking
FUNCPTR(D2CLIENT, LeaveParty, VOID __fastcall, (VOID), 0x9E5D0)
FUNCPTR(D2CLIENT, Transmute, VOID __fastcall, (VOID), 0x595C0)
FUNCPTR(D2CLIENT, CalcShake, void __stdcall, (DWORD *xpos, DWORD *ypos), 0x8AFD0) 
FUNCPTR(D2CLIENT, RemoveNodeFromLinkedList, void __stdcall, (DWORD nodePtr), 0xB1030) // Removes node from doubly-linked list
FUNCPTR(D2CLIENT, InsertNodeIntoLinkedList, void __thiscall, (void *listHead, DWORD *targetNode, DWORD insertPosition), 0xB10B0) // Inserts node into doubly-linked list
FUNCPTR(D2CLIENT, AdjustPointer, void* __cdecl, (void *basePointer, PMD *memberDescriptor), 0xB7B7CD) // Updated 1.13c // Visual Studio C++ runtime function for pointer adjustment in virtual inheritance
FUNCPTR(D2CLIENT, BuildCatchObject, void __cdecl, (EHExceptionRecord *pExceptionRecord, void *pRN, _s_HandlerType *pHandler, _s_CatchableType *pCatch), 0x7B9B0) // Visual Studio C++ runtime exception handling // builds catch objects with proper type conversion
FUNCPTR(D2CLIENT, CallCatchBlock, void* __cdecl, (EHExceptionRecord *pExceptionRecord, EHRegistrationNode *pRN, _CONTEXT *pContext, _s_FuncInfo *pFuncInfo, void *pHandlerCount, int CatchDepth, ulong unknown), 0x7B7EC) // Visual Studio C++ runtime exception handling // calls catch block with proper frame setup
FUNCPTR(D2CLIENT, doexit, void __cdecl, (UINT exitCode, int quick, int retcaller), 0xB35A1) // Visual Studio C++ runtime exit function // handles program termination with cleanup
FUNCPTR(D2CLIENT, entry, BOOL __stdcall, (HMODULE hModule, DWORD dwReason, LPVOID lpReserved), 0xB45F6) // DLL entry point // handles DLL_PROCESS_ATTACH/DETACH and DLL_THREAD_ATTACH/DETACH events
FUNCPTR(D2CLIENT, IsExceptionObjectToBeDestroyed, int __cdecl, (void *pObject), 0x7B0FF) // Visual Studio C++ runtime function for exception handling // checks if exception object should be destroyed
FUNCPTR(D2GFX, GetHwnd, HWND __stdcall, (), -10048)
FUNCPTR(D2NET, SendPacket, void __stdcall, (DWORD aLen, DWORD arg1, BYTE* aPacket), -10024)
FUNCPTR(D2NET, ReceivePacket, void __stdcall, (BYTE *aPacket, DWORD aLen), 0x6BD0)
FUNCPTR(D2NET, ReceivePacket_I, void __stdcall, (BYTE *aPacket, DWORD aLen), -10033)
FUNCPTR(D2CLIENT, DrawHook_I, void __stdcall, (), 0x52D90)
FUNCPTR(D2WIN, DrawText, void __fastcall, (wchar_t *wStr, int xPos, int yPos, DWORD dwColor, DWORD dwUnk), -10150)
FUNCPTR(D2WIN, GetTextSize, DWORD __fastcall, (wchar_t *wStr, DWORD* dwWidth, DWORD* dwFileNo), -10177)
FUNCPTR(D2WIN, SetFont, DWORD __fastcall, (DWORD dwSize), -10184)
FUNCPTR(D2WIN, SetTextSize, DWORD __fastcall, (DWORD dwSize), -10184)
FUNCPTR(D2WIN, GetTextWidthFileNo, DWORD __fastcall, (WCHAR * wStr, DWORD* dwWidth, DWORD* dwFileNo), -10177)
FUNCPTR(D2GFX, DrawLine, void __stdcall, (int X1, int Y1, int X2, int Y2, DWORD dwColor, DWORD dwUnk), -10010)
FUNCPTR(D2GFX, DrawRectangle, VOID __stdcall, (INT x1, INT y1, INT x2, INT y2, DWORD color, DWORD trans), -10014)
FUNCPTR(D2COMMON, AddRoomData, void __stdcall, (Act * ptAct, int LevelId, int Xpos, int Ypos, Room1 * pRoom), -10401)
FUNCPTR(D2COMMON, RemoveRoomData, void __stdcall, (Act * ptAct, int LevelId, int Xpos, int Ypos, Room1 * pRoom), -11099)
FUNCPTR(D2COMMON, GetLayer, AutomapLayer2* __fastcall, (DWORD dwLevelNo), -10749)
FUNCPTR(D2COMMON, GetLevel, Level * __fastcall, (ActMisc *pMisc, DWORD dwLevelNo), -10207)
FUNCPTR(D2COMMON, GetLevelTxt, LevelTxt * __stdcall, (DWORD levelno), -10014)
FUNCPTR(D2COMMON, GetObjectTxt, ObjectTxt * __stdcall, (DWORD objno), -10688)
FUNCPTR(D2COMMON, InitLevel, void __stdcall, (Level *pLevel), -10322) 
FUNCPTR(D2COMMON, GetUnitStat, DWORD __stdcall, (UnitAny* pUnit, DWORD dwStat, DWORD dwStat2), -10973) 
FUNCPTR(D2COMMON, GetRoomFromUnit,  Room1* __stdcall, (UnitAny * ptUnit), -10331)
FUNCPTR(D2COMMON, GetItemText, ItemTxt* __stdcall, (DWORD itemno), -10695)
FUNCPTR(D2COMMON, MapToAbsScreen, void __stdcall, (LONG * X, LONG * Y), -11087)

VARPTR(D2CLIENT, PlayerArea, int, 0x11C34C)
VARPTR(D2WIN, FirstControl, Control*, 0x214A0)
VARPTR(D2CLIENT, ScreenSizeX, DWORD, 0xDBC48)
VARPTR(D2CLIENT, ScreenSizeY, DWORD, 0xDBC4C)

// Data Table and Array Management Functions
FUNCPTR(D2CLIENT, GetDataTableEntryStride_2be0, DWORD __stdcall, (DWORD tableIndex), 0x2be0) // Gets data table entry stride // accesses global sgptDataTables_exref and returns stride from offset +0x14c for 0x23c-byte structure calculations
FUNCPTR(D2CLIENT, GetDataTableArrayElement_2cd0, void* __stdcall, (DWORD tableIndex, DWORD elementIndex), 0x2cd0) // Gets data table array element // calculates array element address using base pointer (+0x148) and stride (+0x14c) with index-based addressing for 0x23c-byte structures
FUNCPTR(D2CLIENT, GetDataTableBase_2d20, void* __stdcall, (DWORD tableIndex), 0x2d20) // Gets data table base pointer // accesses global sgptDataTables_exref array element and returns base pointer from offset +0x148 for subsequent array calculations

// Object Lifecycle Management Functions (Multiple Destructor Variants)
FUNCPTR(D2CLIENT, ObjectDestructor8_2c10, void __stdcall, (void* object), 0x2c10) // Object destructor variant 8 // calls FUN_6faef360 for specialized cleanup then conditionally frees memory based on allocation flag
FUNCPTR(D2CLIENT, ObjectDestructor9_2c40, void __stdcall, (void* object), 0x2c40) // Object destructor variant 9 // calls FUN_6faef240 for specialized cleanup then conditionally frees memory based on allocation flag
FUNCPTR(D2CLIENT, ObjectDestructor10_2c70, void __stdcall, (void* object), 0x2c70) // Object destructor variant 10 // calls FUN_6fae8770 for specialized cleanup then conditionally frees memory based on allocation flag
FUNCPTR(D2CLIENT, ObjectDestructor11_2ca0, void __stdcall, (void* object), 0x2ca0) // Object destructor variant 11 // calls FUN_6fae8410 for specialized cleanup then conditionally frees memory based on allocation flag

// Parameter Management and Validation Functions
FUNCPTR(D2CLIENT, SetParameterWithValidation_2d50, void __stdcall, (void* object, DWORD parameter), 0x2d50) // Sets parameter with validation // validates input parameter against range (param_1 <= 0x16) and sets offset +0x4c with validated value for system state management
FUNCPTR(D2CLIENT, GetParameterWithBounds_2da0, DWORD __stdcall, (void* object), 0x2da0) // Gets parameter with bounds checking // retrieves value from offset +0x4c and validates against maximum bound (0x16), returns bounded parameter for safe state access

// Utility and System Functions
FUNCPTR(D2CLIENT, RandomNumberWithRange_2dc0, DWORD __stdcall, (DWORD maxValue), 0x2dc0) // Generates random number within range // uses RandomNumberGeneratorRange_18d0 to generate random value within specified bounds for probabilistic game mechanics
FUNCPTR(D2CLIENT, ExecuteFunctionLoop_2e20, void __stdcall, (void* functionPtr, DWORD startIndex, DWORD endIndex), 0x2e20) // Executes function in loop // iterates through range (counter vs limit) and calls function pointer for each iteration, used for batch processing operations

ASMPTR(D2MULTI,JoinGame_I,0xCBD0)
ASMPTR(D2MULTI,JoinGame_II,0x11DA0)
ASMPTR(D2MULTI,WaitBox,0xAA60)
ASMPTR(D2CLIENT, GetUnitFromId_I, 0x10A608)
ASMPTR(D2CLIENT, GetUnitFromId_II, 0xA4E20)
ASMPTR(D2CLIENT, GetUnitName_I, 0xA5D90)

FUNCPTR(D2LANG, GetLocaleText, wchar_t* __fastcall, (WORD nLocaleTxtNo), -10003)

// Advanced Unicode and Container System Functions
FUNCPTR(D2CLIENT, UnicodeArrayConstructor_2e60, int __fastcall, (int baseAddress), 0x2e60) // Unicode array constructor // initializes 300 Unicode string objects using default constructor, iterates through array with stride of 2 bytes per Unicode object
FUNCPTR(D2CLIENT, GetDataTableEntryField_2e90, DWORD __stdcall, (DWORD index), 0x2e90) // Gets data table entry field // accesses sgptDataTables_exref with bounds checking, calculates offset using 0x23c stride and returns field from offset +0x15c

// Advanced Linked List Management Functions
FUNCPTR(D2CLIENT, LinkedListRemoverWithSEHWrapper_2ec0, void __stdcall, (void* listNode), 0x2ec0) // Linked list remover with SEH wrapper // sets up structured exception handling frame and calls LinkedListNodeRemoverWithSEH_2580 for safe node removal
FUNCPTR(D2CLIENT, CircularLinkedListInitializer_2f00, void __stdcall, (void* listNode), 0x2f00) // Circular linked list initializer // initializes linked list node with self-referencing pointers and complemented addressing for circular list structure
FUNCPTR(D2CLIENT, GameDataAllocatorWithString_2f70, void* __stdcall, (DWORD param1, int param2, UINT flags), 0x2f70) // Game data allocator with string handling // allocates memory using Ordinal_401 with AUTMESSAGESOURCE string identifier, initializes structure fields with SEH protection
FUNCPTR(D2CLIENT, ComplexLinkedListRemover_2ff0, void __stdcall, (void* listNode), 0x2ff0) // Complex linked list remover // removes node from linked list with complex pointer arithmetic, handles both positive and negative addressing schemes for list management
FUNCPTR(D2CLIENT, FastLinkedListRemover_3060, void __stdcall, (void), 0x3060) // Fast linked list remover // optimized version of ComplexLinkedListRemover_2ff0 using register-based parameter passing for improved performance

// Unit Sound Management Functions (0x3070-0x3F20)
FUNCPTR(D2CLIENT, ProcessUnitSoundCleanup, void __stdcall, (void), 0x3070) // Process unit sound cleanup when no sound situation found - validates unit sound data, iterates through sound effect lists, checks sound table validity, and triggers sound cleanup operations for units without active sound states
FUNCPTR(D2CLIENT, ClearUnitSoundQueue, void __fastcall, (int pUnit), 0x3120) // Clear unit sound queue - iterates through unit sound list and clears all active sound effects, resets sound timers and states, used for cleanup during area transitions or when stopping all unit sounds simultaneously
FUNCPTR(D2CLIENT, ProcessMonsterAmbientSounds, void __fastcall, (UnitAny* pUnit), 0x3170) // Process monster ambient sounds with skill sound handling - validates unit type (monster), processes ambient sound effects with timing constraints, handles special sound ID 8 (skill sounds), manages sound state and timing delays with proper cleanup
FUNCPTR(D2CLIENT, ExecuteUnitSoundEffectById, void __stdcall, (UnitAny* pUnit, uint soundId), 0x3200) // Execute unit sound effect by ID with comprehensive sound mapping - validates unit type and class, maps sound IDs (0x19-0x53) to class-specific sound tables, handles special sound cases with volume/positioning calculations, processes skill sounds and ambient effects with timing parameters
FUNCPTR(D2CLIENT, ProcessUnitSoundActions, void __fastcall, (UnitAny* pUnit, int actionType), 0x3630) // Process unit sound actions with comprehensive action-based sound handling - validates unit states, processes sound effects based on unit actions (0x3=death, 0xD=skill, 0x4=hit, 0x13=cast), handles monster/object ambient sounds, manages item interaction sounds, and updates sound timing states
FUNCPTR(D2CLIENT, HandleAdvancedUnitSounds, void __stdcall, (UnitAny* pUnit), 0x37E0) // Handle advanced unit sound processing with type-specific logic - processes object type 2 (special unit 0x1A) with sound situation validation, handles monster type 1 ambient sounds with level-specific conditions (0x6E/0x88), manages sound timing constraints and state transitions with comprehensive validation
FUNCPTR(D2CLIENT, ManageUnitSoundSequences, void __stdcall, (int pUnit, int param2), 0x3A30) // Manage unit sound sequences with timing - processes unit sound lists with ambient sound matching, manages sound timing delays and random variations, handles sound sequence interruption and processing with complex state validation
FUNCPTR(D2CLIENT, CalculateUnitSoundParameters, uint __stdcall, (int pUnit), 0x3C00) // Calculate unit sound parameters with dynamic timing - computes sound timing based on unit type, sound state, and animation data, handles random timing variations and volume calculations, manages sound delay calculations with player unit special handling
FUNCPTR(D2CLIENT, ProcessEnvironmentalSounds, void __stdcall, (void), 0x3E20) // Process environmental sounds - validates current player unit, checks area ID and quest availability, manages level-specific sound triggers, handles timing constraints and processes level-appropriate sound effects based on area and quest state
FUNCPTR(D2CLIENT, HandleNetworkSoundEvents, void __fastcall, (int param1, uint param2, uint param3), 0x3F20) // Handle network sound events with parameter processing - searches unit hash table by ID, processes various sound event types (0xA-0x5D), handles skill sounds, item interactions, and special unit sound cases with network synchronization

FUNCPTR(D2CLIENT, BatchLinkedListProcessor_30a0, void __stdcall, (void), 0x30a0) // Batch linked list processor // iterates through list container, removes all nodes using complex pointer arithmetic with positive/negative addressing schemes

// Unit Management and Processing Functions
FUNCPTR(D2CLIENT, CleanupUnitObject, void __fastcall, (int* pUnit), 0xD00E0) // Cleans up unit object // validates unit and mode parameters (type 4), performs cleanup operations using Ordinal_10750/10867 for unit data, with final FUN_6fb60450 call
FUNCPTR(D2CLIENT, HandleUnitMovementCommand, void __thiscall, (void* this, int param1), 0xD0180) // Handles unit movement command // processes movement for unit type 3, validates quest flags, calculates position differences, manages player states with coordinate adjustments
FUNCPTR(D2CLIENT, ProcessUnitSkillEffect, void __stdcall, (int* pUnit, int skillId), 0xD0340) // Processes unit skill effect // handles skill effects for units except skillId 0xc3, sets up effect data structures, processes coordinate offsets and effect rendering
FUNCPTR(D2CLIENT, DisplayUnitOverheadText, void __fastcall, (int* pUnit, int param2, int param3), 0xD0620) // Displays overhead text for units // handles player names, hireling text, special unit messages with localization and Unicode string processing
FUNCPTR(D2CLIENT, RenderUnitGlow, void __stdcall, (void), 0xD0A60) // Renders unit glow effect // gets unit coordinates using Ordinal_10867/10750, sets up glow parameters and calls FUN_6fb630f0 twice for double glow rendering
FUNCPTR(D2CLIENT, InitializeUnitDeath, void __fastcall, (int* pUnit), 0xD0B70) // Initializes unit death sequence // validates unit parameters, calls Ordinal_10973 with death message (0xc), triggers death effect ProcessUnitSkillEffect with skillId 0xe1
FUNCPTR(D2CLIENT, ExecuteUnitSpellCallbacks, void __stdcall, (void), 0xD0F20) // Executes unit spell callbacks // processes player unit spells, iterates through spell data (9 bytes), calls registered callback functions from DAT_6fbaa340 table with spell parameters
FUNCPTR(D2CLIENT, RenderUnitGlowWrapper, void __stdcall, (void), 0xD0FA0) // Renders unit glow wrapper // simple wrapper function that calls RenderUnitGlow for unit glow effect rendering
FUNCPTR(D2CLIENT, ProcessUnitSkillMessage, void __fastcall, (int messageData), 0xD0FB0) // Processes unit skill message // handles skill-related network messages, dispatches to specific skill handlers based on message type (0x2d-0x220) with parameter validation

// Advanced Unit Processing Functions
FUNCPTR(D2CLIENT, HandlePlayerDeathSpawns, void __fastcall, (int* pUnit), 0xD1210) // Handles player death spawns - manages monster spawning during player death (mode 0xc), spawns type 0xe3 monsters with random percentage chance, resets unit state on death mode 0xd
FUNCPTR(D2CLIENT, ExecuteSpellSequenceCallbacks, void __stdcall, (int* pUnit, DWORD param2, int sequenceType), 0xD12F0) // Executes spell sequence callbacks - processes spell sequences with 9-byte spell data, calls functions from DAT_6fba9fe0/DAT_6fba9ff0 tables based on sequence type (special handling for type 4)
FUNCPTR(D2CLIENT, TriggerPlayerSpellSequence, void __fastcall, (int param1), 0xD13A0) // Triggers player spell sequence - wrapper for ExecuteSpellSequenceCallbacks, validates player unit type 1 and calls sequence execution with type 4
FUNCPTR(D2CLIENT, ExecuteUnitEventCallback, DWORD __stdcall, (DWORD param1, DWORD param2), 0xD1400) // Executes unit event callback - iterates through unit event list at offset 0x90, matches event IDs and calls registered callback functions with parameters
FUNCPTR(D2CLIENT, RemoveUnitEvent, void __stdcall, (int eventId), 0xD1440) // Removes unit event - searches unit event list for matching event ID, unlinks from linked list, deallocates memory using Ordinal_10046 CUnitEvent.cpp cleanup
FUNCPTR(D2CLIENT, CreateUnitEvent, void* __stdcall, (DWORD param1, DWORD param2, DWORD param3, DWORD param4, DWORD param5, DWORD param6), 0xD14B0) // Creates unit event - allocates memory using Ordinal_10045, initializes event structure, links to unit event list at offset 0x90
FUNCPTR(D2CLIENT, ClearAllUnitEvents, void __stdcall, (void), 0xD1540) // Clears all unit events - iterates through unit event list, deallocates all events using Ordinal_10046, resets list pointer to null
FUNCPTR(D2CLIENT, GetSkillDataByUnitId, DWORD __fastcall, (int unitId), 0xD1580) // Gets skill data by unit ID - searches DAT_6fbcc4d4 skill list, returns skill data at offset 0x1c for matching unit ID
FUNCPTR(D2CLIENT, RemoveSkillDataByUnitId, void __fastcall, (DWORD param1, int unitId), 0xD15B0) // Removes skill data by unit ID - searches skill list for entries with type 7 and matching unit ID, unlinks and deallocates using Ordinal_10043
FUNCPTR(D2CLIENT, ClearAllSkillData, void __stdcall, (void), 0xD1630) // Clears all skill data - iterates through DAT_6fbcc4d4 skill list, deallocates all entries using Ordinal_10043, resets list pointer
FUNCPTR(D2CLIENT, GetSkillTypeByUnitId, DWORD __fastcall, (int unitId), 0xD1670) // Gets skill type by unit ID - searches skill list for matching unit ID, returns skill type from offset 0x4
FUNCPTR(D2CLIENT, GetSkillLevelByUnitId, DWORD __fastcall, (int unitId), 0xD16A0) // Gets skill level by unit ID - searches skill list for matching unit ID, returns skill level from offset 0xc (returns 0xffffffff if not found)
FUNCPTR(D2CLIENT, GetSkillIdByUnitId, DWORD __fastcall, (int unitId), 0xD16D0) // Gets skill ID by unit ID - searches skill list for matching unit ID, returns skill ID from offset 0x0
FUNCPTR(D2CLIENT, CountActiveSkillsByPlayerId, int __stdcall, (void), 0xD17E0) // Counts active skills by player ID - iterates through skill list, counts entries matching player ID and skill level parameters
FUNCPTR(D2CLIENT, UpdateSkillData, void __thiscall, (void* this, DWORD param1, DWORD param2), 0xD18C0) // Updates skill data - handles skill data updates, removes existing entries for type 7, creates/updates skill entries in DAT_6fbcc4d4 list
FUNCPTR(D2CLIENT, ValidateSkillPermissions, DWORD __stdcall, (void), 0xD19F0) // Validates skill permissions - checks skill data table permissions, validates player roster access, returns permission level (0-3) based on skill flags and player status
FUNCPTR(D2CLIENT, CheckSkillUsageRights, DWORD __stdcall, (void), 0xD1B10) // Checks skill usage rights - validates skill usage permissions using FUN_6faffd90, handles player ID validation and returns usage authorization status
FUNCPTR(D2CLIENT, ProcessSkillActivation, void __thiscall, (void* this, DWORD param1, DWORD param2), 0xD1D60) // Processes skill activation - handles skill activation events, manages skill data updates, processes player skill activation with position data and animation triggers
FUNCPTR(D2CLIENT, GetItemQualityType, DWORD __stdcall, (void), 0xD1E80) // Gets item quality type - examines item flags at offset 0x18+6, returns quality type (1-6) based on flag bits (0x20=magic, 0x8=superior, 0x10=rare, 0x40=set, 0x80=unique, 0x400=crafted)
FUNCPTR(D2CLIENT, FindGridPositionByCoords, int* __fastcall, (int param1, DWORD param2), 0xD1ED0) // Finds grid position by coordinates - uses Ordinal_10561/10544 to search grid data, calculates position using coordinate division by 5, returns grid entry pointer
FUNCPTR(D2CLIENT, SetUnitAnimationData, void __stdcall, (DWORD animationData), 0xD1FB0) // Sets unit animation data - validates unit pointer, stores animation data at offset 0x84, handles animation state management

// Unit Sound System Functions
FUNCPTR(D2CLIENT, SetUnitSoundData, void __stdcall, (DWORD soundData), 0xD2010) // Sets unit sound data - validates unit pointer, stores sound data at offset 0x80, manages unit audio state with error handling
FUNCPTR(D2CLIENT, GetUnitSoundData, DWORD __stdcall, (void), 0xD2040) // Gets unit sound data - retrieves sound data from unit offset 0x80, validates unit pointer with error handling
FUNCPTR(D2CLIENT, SetUnitSoundState, void __stdcall, (DWORD soundState), 0xD2070) // Sets unit sound state - validates unit pointer, stores sound state at offset 0x7c, manages audio timing state
FUNCPTR(D2CLIENT, GetUnitSoundState, DWORD __stdcall, (void), 0xD20A0) // Gets unit sound state - retrieves sound state from unit offset 0x7c, validates unit pointer with error handling
FUNCPTR(D2CLIENT, GetUnitSoundId, DWORD __fastcall, (UINT unitFlags), 0xD21C0) // Gets unit sound ID - validates unit pointer, maps unit flags (1-11) to sound IDs (0x18e for 1-9, 0x191 for 10-11)
FUNCPTR(D2CLIENT, CalculateUnitSoundDelay, UINT __fastcall, (int param1), 0xD2220) // Calculates unit sound delay - validates parameters, uses DAT_6fba553c table for delay calculation, applies unit modifier at offset 0x4c
FUNCPTR(D2CLIENT, GetUnitSoundDelayValue, DWORD __fastcall, (int param1), 0xD2280) // Gets unit sound delay value - validates parameters, retrieves delay value from DAT_6fba5538 table using unit flags
FUNCPTR(D2CLIENT, GetSoundDataPointer, void* __stdcall, (void), 0xD22C0) // Gets sound data pointer - validates index range (0-6), returns pointer from PTR_DAT_6fba7694 array
FUNCPTR(D2CLIENT, GetUnitSoundOffset, DWORD __stdcall, (void), 0xD2320) // Gets unit sound offset - validates unit pointer, retrieves sound offset from unit structure at offset 0x78
FUNCPTR(D2CLIENT, PlayUnitSound, void __stdcall, (void), 0xD2390) // Plays unit sound - validates unit pointer, calls Ordinal_10034 to play unit audio
FUNCPTR(D2CLIENT, GetUnitSoundId2, DWORD __stdcall, (void), 0xD23D0) // Gets unit sound ID (alternative) - uses Ordinal_10175 for sound ID retrieval, validates unit type and ID with UnitSnd.cpp logging
FUNCPTR(D2CLIENT, GetUnitType, int __stdcall, (void), 0xD2430) // Gets unit type - retrieves unit type using Ordinal_10175, validates parameters with UnitSnd.cpp logging
FUNCPTR(D2CLIENT, GetUnitTypeId, int __stdcall, (void), 0xD2490) // Gets unit type ID - retrieves unit type ID using Ordinal_10175, validates parameters with UnitSnd.cpp logging
FUNCPTR(D2CLIENT, GetUnitSoundBySituation, int __stdcall, (void), 0xD24F0) // Gets unit sound by situation - validates unit type ID and situation flags, uses DAT_6fba6c58 table with special handling for type 0x3d
FUNCPTR(D2CLIENT, GetUnitSoundByIndex, DWORD __stdcall, (int param1), 0xD2570) // Gets unit sound by index - validates unit type and index, retrieves sound from DAT_6fba6c58 table with bounds checking
FUNCPTR(D2CLIENT, FindActiveUnitSoundId, int __fastcall, (int param1), 0xD25D0) // Finds active unit sound ID - searches unit sound list at offset 0x78, matches sound IDs with DAT_6fbcbf30 mapping table
FUNCPTR(D2CLIENT, GetUnitItemQuality, int __stdcall, (void), 0xD26A0) // Gets unit item quality - retrieves player difficulty level, processes item quality through grid position lookup and quality type determination
FUNCPTR(D2CLIENT, GetUnitSoundEffects, void __stdcall, (UINT param1, int param2, int* param3), 0xD27E0) // Gets unit sound effects - maps unit type flags to sound effect IDs, handles collision checks and unit state validation
FUNCPTR(D2CLIENT, PlayUnitAmbientSound, void __stdcall, (void), 0xD2A70) // Plays unit ambient sound - validates unit type and data table bounds, plays ambient sounds using Ordinal_10876/10917 based on unit configuration
FUNCPTR(D2CLIENT, UpdateUnitSoundState, void __fastcall, (int param1), 0xD2B20) // Updates unit sound state - manages unit sound state transitions, handles sound stopping/starting based on unit state changes with type-specific processing
FUNCPTR(D2CLIENT, ProcessUnitRandomSounds, void __stdcall, (void), 0xD2C10) // Processes unit random sounds - generates random sounds for player units using timing constraints and random number generation with global timer management
FUNCPTR(D2CLIENT, HandleUnitSkillSounds, void __stdcall, (void), 0xD2CA0) // Handles unit skill sounds - processes skill-specific sound effects for skills 8-11 with timing validation and sound ID mapping
FUNCPTR(D2CLIENT, TriggerUnitSound, void __stdcall, (void), 0xD2D60) // Triggers unit sound - activates unit sound using GetUnitSoundId, calls FUN_6fb38a70 with global timer management
FUNCPTR(D2CLIENT, ProcessUnitItemSounds, void __stdcall, (void), 0xD2DA0) // Processes unit item sounds - checks unit items against sound data tables, triggers sounds for matching items with comprehensive item ID validation
FUNCPTR(D2CLIENT, ProcessUnitSkillItemSounds, void __stdcall, (void), 0xD2EB0) // Processes unit skill item sounds - handles sounds for skill-related items (skills 8-11), checks items against skill sound tables with item validation
FUNCPTR(D2CLIENT, GetUnitSoundPointer, int __stdcall, (int param1), 0xD2FB0) // Gets unit sound pointer - retrieves sound data pointer based on unit type, applies quality-based offset calculations and parameter-based adjustments

// Cursor System Management Functions
FUNCPTR(D2CLIENT, ResetCursorAnimation, void __stdcall, (int param1), 0x60a0) // Reset cursor animation state - stops current animation if type is 2 and clears animation timers, resets animation frame counters and timing variables to prepare for new cursor state
FUNCPTR(D2CLIENT, GetCursorAnimationDelay, int __fastcall, (void), 0x60e0) // Get cursor animation delay value - retrieves timing delay for current cursor animation frame based on cursor type and animation state, returns delay value scaled by 256 for frame timing calculations
FUNCPTR(D2CLIENT, GetCursorAnimationFrameCount, DWORD __fastcall, (void), 0x6130) // Get cursor animation frame count - retrieves total number of frames for current cursor animation sequence, used to determine animation loop length and frame cycling behavior
FUNCPTR(D2CLIENT, SetCursorPosition, void __stdcall, (void), 0x61b0) // Set cursor position with window coordinate conversion - positions system cursor at specified coordinates with window offset calculation, handles windowed and fullscreen modes with proper coordinate transformation and boundary validation
FUNCPTR(D2CLIENT, UpdateCursorAnimation, void __stdcall, (void), 0x6250) // Update cursor animation frame timing - advances animation timer and handles frame transitions, manages animation speed, frame cycling, and state transitions including fallback to idle state when animation completes
FUNCPTR(D2CLIENT, SetCursorAnimationState, void __fastcall, (void), 0x62d0) // Set cursor animation state and parameters - configures cursor animation mode and initializes timing variables, sets animation type, frame counters, and state flags for proper cursor behavior management
FUNCPTR(D2CLIENT, HandleCursorMouseMove, void __stdcall, (int param1), 0x6300) // Handle cursor mouse movement events - processes mouse position updates and manages cursor state transitions based on movement, updates cursor coordinates, timestamps, and handles special state transitions for animation resets
FUNCPTR(D2CLIENT, HandleCursorStateTransition, void __stdcall, (void), 0x6360) // Handle cursor state transitions - manages cursor state changes based on animation data and timing, processes state machine transitions, handles animation completion, and manages cursor behavior state switching
FUNCPTR(D2CLIENT, ProcessCursorAnimationFrame, void __stdcall, (void), 0x64f0) // Process cursor animation frame advancement - handles frame-by-frame animation progression including random timing variations and state transitions, manages animation loops, timing calculations, and state machine progression for smooth cursor animations
FUNCPTR(D2CLIENT, CleanupCursorSystem, void __stdcall, (void), 0x6620) // Cleanup cursor system resources - unloads cursor graphics, frees memory, and resets system state, cleans up animation data structures and releases all allocated cursor-related resources during shutdown
FUNCPTR(D2CLIENT, InitializeCursorSystem, DWORD __fastcall, (void), 0x66c0) // Initialize cursor system and load graphics - sets up cursor animation system, loads cursor graphics from files, and initializes state machine, configures cursor types, animation data, and prepares system for cursor rendering and interaction
FUNCPTR(D2CLIENT, UpdateCursorSystemTiming, void __stdcall, (void), 0x67d0) // Update cursor system timing and animation - manages cursor animation progression and state transitions with timeout handling, processes animation frames, handles idle timeout (5 seconds), and manages cursor state machine transitions

// Cursor Rendering and Display Functions
FUNCPTR(D2CLIENT, RenderCursorWithTransparency, void __stdcall, (void), 0x6910) // Render cursor with transparency and coordinate handling - handles cursor rendering with position calculations, boundary checking, and transparency effects, manages cursor visibility states and coordinate transformations for proper display
FUNCPTR(D2CLIENT, RenderCursorSpecialStates, void __stdcall, (void), 0x6a90) // Render cursor in special states - handles specialized cursor rendering for specific game states and conditions, manages alternative cursor displays with position calculations and transparency handling for special interaction modes

// Unit Finding and Position Management Functions
FUNCPTR(D2CLIENT, FindUnitsInAreaByCallback, int __stdcall, (DWORD param1, UINT param2), 0x6c20) // Find units in area using callback function - iterates through units in specified area and applies callback function to each unit, supports custom filtering and processing logic through function pointer callback mechanism
FUNCPTR(D2CLIENT, CompareUnitPositions, DWORD __fastcall, (void), 0x6cb0) // Compare unit positions for equality - compares X and Y coordinates of two units with proper handling of different unit types, supports player units, NPCs, and objects with coordinate extraction based on unit type
FUNCPTR(D2CLIENT, FindClosestPortalUnit, int __stdcall, (DWORD param1), 0x6d80) // Find closest portal unit - searches through portal array to find nearest portal unit with distance calculation, validates portal state and type before calculating distance, returns closest valid portal for travel
FUNCPTR(D2CLIENT, ValidateUnitForPathfinding, int __fastcall, (int param1, int* param2, DWORD* param3, int* param4), 0x6dd0) // Validate unit for pathfinding operations - checks if unit is suitable for pathfinding algorithms including unit type validation, state checking, and distance calculations, ensures unit can be used as waypoint or destination in pathfinding

// Monster and Item Management Functions
FUNCPTR(D2CLIENT, SpawnMonstersByType, void __stdcall, (int param1, int param2), 0x6eb0) // Spawn monsters by type with random positioning - creates specified number of monsters of given type using random coordinate generation, validates spawn locations and places monsters within valid game areas with collision detection
FUNCPTR(D2CLIENT, SetUnitHealthPercentage, void __fastcall, (int param1), 0x6fe0) // Set unit health percentage with validation - sets unit health to specified percentage with bounds checking (0-200%), validates unit type and ensures health value is within acceptable range for game balance
FUNCPTR(D2CLIENT, CreateHealthPotionEffect, DWORD* __fastcall, (void), 0x7010) // Create health potion effect with random properties - generates health potion item with random healing values and visual effects, configures potion properties, healing amounts, and duration based on random generation and player level

// Network Packet Transmission Functions
FUNCPTR(D2CLIENT, SendPlayerPositionPacket, void __stdcall, (void), 0x7270) // Send player position packet to server - transmits player coordinate data to server for multiplayer synchronization, extracts player X/Y coordinates and sends position update packet for network synchronization
FUNCPTR(D2CLIENT, SendPlayerStatePacket, void __stdcall, (void), 0x7300) // Send player state packet to server - transmits player state information including position and status for multiplayer synchronization, sends comprehensive player state data for network game coordination
FUNCPTR(D2CLIENT, SendItemActionPacket, void __stdcall, (int param1, DWORD param2), 0x7390) // Send item action packet with item data - transmits item interaction packets including item ID, action type, and item properties, handles item usage, pickup, drop, and equipment actions for multiplayer synchronization
FUNCPTR(D2CLIENT, SendRandomizedMovementPacket, void __stdcall, (UINT param1, int param2, DWORD param3), 0x73e0) // Send randomized movement packet with coordinate offset - generates random coordinate offsets and transmits movement packet to server, uses random number generation to create natural movement variations and sends network packet with player position and item data
FUNCPTR(D2CLIENT, SendDirectionalMovementPacket, DWORD __stdcall, (int* param1, BYTE param2, int param3, DWORD param4), 0x7500) // Send directional movement packet with pathfinding - calculates directional movement toward target with collision detection and pathfinding validation, computes movement direction, validates path accessibility, and sends movement packet if path is clear
FUNCPTR(D2CLIENT, SendGenericActionPacket, void __stdcall, (int param1, DWORD param2), 0x76a0) // Send generic action packet with unit data - transmits generic action packet containing unit type and ID information, handles null unit cases with default values and sends action packet with item ID and unit properties

// AI Behavior Processing Functions
FUNCPTR(D2CLIENT, ProcessTownPlayerBehavior, void __stdcall, (void), 0x7710) // Process town player behavior with random actions - manages player behavior in town areas including random movement, interaction attempts, and idle states, handles collision detection, random action selection, and appropriate packet transmission for town activities
FUNCPTR(D2CLIENT, ProcessWildernessPlayerBehavior, void __stdcall, (void), 0x7800) // Process wilderness player behavior with enemy detection - manages player behavior in wilderness areas including enemy detection, combat positioning, and movement strategies, finds nearby enemies, manages combat distance, and executes appropriate movement or attack behaviors
FUNCPTR(D2CLIENT, ProcessNeutralPlayerBehavior, void __thiscall, (void* this, UINT param1), 0x7950) // Process neutral player behavior with position validation - manages player behavior in neutral areas with position comparison and movement decisions, checks position changes, validates movement patterns, and executes appropriate movement or idle behaviors based on context
FUNCPTR(D2CLIENT, ProcessCombatPlayerBehavior, void __thiscall, (void* this, UINT param1), 0x79e0) // Process combat player behavior with advanced AI - manages complex combat behavior including position validation, enemy detection, and tactical decision making, handles combat positioning, target selection, and coordinated attack patterns with state management
FUNCPTR(D2CLIENT, ProcessPlayerFollowBehavior, void __stdcall, (void), 0x7c00) // Process player follow behavior with distance management - manages player following another player with distance calculations and random movement, handles follow distance validation, proximity checking, and appropriate movement adjustments to maintain follow behavior

// Player Command Processing Functions
FUNCPTR(D2CLIENT, ProcessPlayerMovementCommand, void __stdcall, (DWORD param1, UINT param2), 0x7e10) // Process player movement command with probability-based decisions - handles movement commands with random probability checks for different movement types, executes directional movement or randomized movement based on probability thresholds and command parameters
FUNCPTR(D2CLIENT, ProcessPlayerAttackCommand, void __stdcall, (void), 0x7e80) // Process player attack command with enemy targeting - handles attack commands including enemy detection, distance validation, and attack execution, finds nearby enemies, validates attack range, and executes appropriate attack or movement behaviors
FUNCPTR(D2CLIENT, ProcessPlayerIdleState, void __stdcall, (void), 0x7f70) // Process player idle state with portal detection - manages player idle behavior including portal detection and health management, handles idle timing, portal searching for escape routes, and health potion usage when needed for survival

// Object and World Management Functions
FUNCPTR(D2CLIENT, SpawnObjectAtRandomLocation, void __stdcall, (DWORD param1, int param2), 0x81a0) // Spawn object at random location with collision detection // creates objects at random coordinates within area bounds using collision detection, generates random positions, validates spawn locations, and creates objects with proper ID assignment and positioning
FUNCPTR(D2CLIENT, ProcessRandomObjectSpawning, void __stdcall, (int param1), 0x8370) // Process random object spawning with probability calculations // iterates through object spawn tables and uses random generation to determine spawn quantities and types, calculates spawn probabilities, validates level data, and creates random numbers of objects based on configured spawn rates

// Player Interaction and Validation Functions
FUNCPTR(D2CLIENT, GetUnitInteractionMode, DWORD __stdcall, (int param1, int param2), 0x84d0) // Get unit interaction mode based on character class and equipment // determines appropriate interaction mode for unit based on character class (Paladin/Barbarian special handling) and equipped items, validates equipment states and returns appropriate interaction mode value
FUNCPTR(D2CLIENT, ValidatePlayerActionFlags, DWORD __fastcall, (UINT* param1), 0x85e0) // Validate player action flags and state conditions // checks player action flags and unit states to determine if actions can be performed, validates unit types, action permissions, and player state conditions for action execution
FUNCPTR(D2CLIENT, CheckPlayerClassAbility, DWORD __stdcall, (void), 0x8650) // Check player class ability using data tables // validates if player has specific class-based abilities by checking character class data and ability flags, uses bit mask operations to verify class permissions and ability availability
FUNCPTR(D2CLIENT, ProcessPlayerMovementValidation, DWORD __stdcall, (int* param1, UINT* param2), 0x86a0) // Process player movement validation with distance and timing checks // validates player movement including distance calculations, coordinate bounds checking, and movement timing restrictions, handles different unit types, calculates movement vectors, and enforces movement rate limiting

// Skill and Combat System Functions
FUNCPTR(D2CLIENT, CalculateSkillRangeCheck, BOOL __stdcall, (int param1, int param2, int* param3), 0x8880) // Calculate skill range check for target validation // computes skill range and validates if target is within effective range for skill usage, performs distance calculations between caster and target with skill-specific range modifiers and returns range validation result
FUNCPTR(D2CLIENT, UpdatePlayerAreaTransition, void __stdcall, (void), 0x8920) // Update player area transition and coordinate system // handles player transitions between areas including coordinate system updates and area-specific processing, extracts player coordinates and updates area transition state for proper area management
FUNCPTR(D2CLIENT, SetPlayerColorTint, void __fastcall, (DWORD param1, int param2), 0x89a0) // Set player color tint with RGB values // applies color tinting effects to player units including RGB color extraction and tint application, handles color parameter processing and applies visual color effects for player display customization
FUNCPTR(D2CLIENT, ProcessPlayerSkillActivation, int* __fastcall, (UINT* param1), 0x8a00) // Process player skill activation with validation and lookup // handles skill activation including skill validation, lookup operations, and activation processing, validates skill availability, performs skill table lookups, and processes skill activation with proper error handling

// Player State and Quest Management Functions
FUNCPTR(D2CLIENT, CheckPlayerQuestState, DWORD __stdcall, (int param1, int param2), 0x8ac0) // Check player quest state for specific quest and parameters // validates player quest state by checking quest ID and parameters against current player quest data, returns validation result for quest state verification and progression checking
FUNCPTR(D2CLIENT, InitializePlayerStateMachine, void __stdcall, (void), 0x8b20) // Initialize player state machine and reset data structures // sets up player state machine including flag initialization, data structure resets, and state variable initialization, clears player state arrays and prepares state machine for proper operation
FUNCPTR(D2CLIENT, UpdatePlayerDisplay, void __stdcall, (void), 0x8bc0) // Update player display and visual representation // handles player display updates including visual state changes and rendering updates, validates player unit state and processes display-related updates for proper player visualization
FUNCPTR(D2CLIENT, ProcessPlayerMovementCommand, void __stdcall, (DWORD param1, UINT param2), 0x7e10) // Process player movement command with probability-based decisions // handles movement commands with random probability checks for different movement types, executes directional movement or randomized movement based on probability thresholds and command parameters
FUNCPTR(D2CLIENT, ProcessPlayerAttackCommand, void __stdcall, (void), 0x7e80) // Process player attack command with enemy targeting // handles attack commands including enemy detection, distance validation, and attack execution, finds nearby enemies, validates attack range, and executes appropriate attack or movement behaviors
FUNCPTR(D2CLIENT, ProcessPlayerIdleState, void __stdcall, (void), 0x7f70) // Process player idle state with portal detection // manages player idle behavior including portal detection and health management, handles idle timing, portal searching for escape routes, and health potion usage when needed for survival

// Object and World Management Functions
FUNCPTR(D2CLIENT, SpawnObjectAtRandomLocation, void __stdcall, (DWORD param1, int param2), 0x81a0) // Spawn object at random location with collision detection // creates objects at random coordinates within area bounds using collision detection, generates random positions, validates spawn locations, and creates objects with proper ID assignment and positioning
FUNCPTR(D2CLIENT, SendPlayerPositionPacket, void __stdcall, (void), 0x7270) // Send player position packet to server // transmits player coordinate data to server for multiplayer synchronization, extracts player X/Y coordinates and sends position update packet for network synchronization
FUNCPTR(D2CLIENT, SendPlayerStatePacket, void __stdcall, (void), 0x7300) // Send player state packet to server // transmits player state information including position and status for multiplayer synchronization, sends comprehensive player state data for network game coordination
FUNCPTR(D2CLIENT, SendItemActionPacket, void __stdcall, (int param1, DWORD param2), 0x7390) // Send item action packet with item data // transmits item interaction packets including item ID, action type, and item properties, handles item usage, pickup, drop, and equipment actions for multiplayer synchronization
FUNCPTR(D2CLIENT, CleanupCursorSystem, void __stdcall, (void), 0x6620) // Cleanup cursor system resources // unloads cursor graphics, frees memory, and resets system state, cleans up animation data structures and releases all allocated cursor-related resources during shutdown
FUNCPTR(D2CLIENT, InitializeCursorSystem, DWORD __fastcall, (void), 0x66c0) // Initialize cursor system and load graphics // sets up cursor animation system, loads cursor graphics from files, and initializes state machine, configures cursor types, animation data, and prepares system for cursor rendering and interaction

// ============================================================================
// COMPREHENSIVE FUNCTION BATCH: 164 Advanced Game System Functions (0x6fac0000-0x6facffc0)
// Complete analysis of advanced game mechanics, compression systems, rendering,
// memory management, AI systems, and core game functionality
// ============================================================================

// Memory Management and Allocation Functions
FUNCPTR(D2CLIENT, MemoryAllocator_0000, void __fastcall, (undefined4 param1, uint param2, uint param3), 0x0000) // Memory allocation wrapper that calls CallocWithSBH_8797 for Small Block Heap allocation. Part of Visual Studio C++ runtime memory management system
FUNCPTR(D2CLIENT, PopMemoryContext_09c0, undefined4, (void), 0x09c0) // Pops a memory allocation context from the stack. Part of a hierarchical memory management system that maintains multiple allocation contexts for different game subsystems

// Compression/Decompression System (zlib/deflate implementation)
FUNCPTR(D2CLIENT, InflateReset_0110, undefined4, (void), 0x0110) // Resets the inflate decompression state machine to initial state. Clears buffers, resets state variables, and reinitializes the inflation process for zlib/deflate decompression
FUNCPTR(D2CLIENT, InflateStateMachine_0250, uint __fastcall, (undefined4 param1, int param2), 0x0250) // Main inflate decompression state machine implementing zlib/deflate decompression algorithm. Handles header validation, compression method detection, data decompression, and CRC verification through multiple states
FUNCPTR(D2CLIENT, InflateEnd_0640, undefined4, (void), 0x0640) // Cleanup function for inflate decompression. Frees allocated memory blocks, releases inflate codes structures, and resets the decompression context to initial state
FUNCPTR(D2CLIENT, InflateInit_0680, undefined4 __fastcall, (int param1, int param2, int param3), 0x0680) // Initializes inflate decompression context. Validates version string, sets up memory allocation functions, validates window size (8-15 bits), and allocates internal state structures for zlib/deflate decompression

// Game Initialization and Configuration Functions
FUNCPTR(D2CLIENT, ShowDeveloperCommands_0950, undefined4, (void), 0x0950) // Developer debugging function that displays available command line options. Checks for specific username "rseis" and shows hidden development commands including -set and -lng options for developers
FUNCPTR(D2CLIENT, ValidateLanguageFile_0a60, undefined4, (DWORD param1), 0x0a60) // Validates language file selection by comparing against a table of supported language codes. Sets language index for localization and displays developer commands for authorized users
FUNCPTR(D2CLIENT, InitializeGameSettings_0b60, undefined4, (void), 0x0b60) // Initializes core game settings and registry configuration. Calls initialization functions, processes command line arguments from registry, sets up user profile information, and establishes default game parameters
FUNCPTR(D2CLIENT, InitializeGameState_2067, void, (int param1), 0x2067) // Initializes game state structure with base parameters, calls initialization routines, sets state flags, and prepares core game systems for operation

// Advanced Game Logic and Core Systems
FUNCPTR(D2CLIENT, MainGameInitializer_0c80, undefined4, (void), 0x0c80) // Main game initialization function // coordinates all game subsystems startup including language manager, module loading, memory management, and game state machine initialization. Critical function for game startup
FUNCPTR(D2CLIENT, ScreenResolutionManager_0df0, void, (void), 0x0df0) // Screen resolution manager // handles different resolution modes (640x480, 800x600), updates global screen variables, and reinitializes graphics subsystems when resolution changes
FUNCPTR(D2CLIENT, StartFadeEffect_0ea0, void, (void), 0x0ea0) // Starts fade effect by setting timer for screen fade transition. Sets fade duration to 500ms using GetTickCount for timing reference
FUNCPTR(D2CLIENT, ProcessFadeEffect_0ec0, void, (void), 0x0ec0) // Processes active fade effect by calculating fade alpha based on elapsed time and screen position. Handles screen transitions with alpha blending over 500ms duration
FUNCPTR(D2CLIENT, CheckUIAreaHitbox1_0f70, undefined4, (void), 0x0f70) // UI hitbox checker // validates if coordinates are within specific UI area bounds using calculated screen position offsets
FUNCPTR(D2CLIENT, CheckUIAreaHitbox2_0fd0, undefined4, (void), 0x0fd0) // UI hitbox checker // validates if coordinates are within different UI area bounds using calculated screen position offsets
FUNCPTR(D2CLIENT, CheckUIAreaHitbox3_1020, undefined4, (void), 0x1020) // UI hitbox checker // validates if coordinates are within third UI area bounds using calculated screen position offsets
FUNCPTR(D2CLIENT, CheckUIAreaHitbox4_1070, undefined4, (void), 0x1070) // UI hitbox checker // validates if coordinates are within fourth UI area bounds using calculated screen position offsets
FUNCPTR(D2CLIENT, CheckUIAreaHitbox5_10c0, int __stdcall, (int x, int y, int width, int height), 0x10c0) // UI hitbox validation // checks if coordinates are within specified rectangular boundary using screen resolution calculations and area bounds validation
FUNCPTR(D2CLIENT, CheckUIAreaHitbox6_1110, undefined4 __fastcall, (int x, int y), 0x1110) // UI area validation with complex mathematical calculations // performs coordinate transformation and boundary testing using integer arithmetic and conditional logic

// Rendering and Graphics System
FUNCPTR(D2CLIENT, RenderGameMap_3390, void __thiscall, (void* this, int param1, int param2, undefined4 param3, int param4), 0x3390) // Renders game map tiles with lighting effects, shadow calculations, and perspective correction for isometric view
FUNCPTR(D2CLIENT, RenderIsometricTiles_3450, void __fastcall, (undefined1* buffer, int x, int y), 0x3450) // Render isometric tiles // generates isometric tile vertices for 3D game world rendering with perspective transformation and boundary conditions
FUNCPTR(D2CLIENT, InitializeTileBuffer_34e0, void, (void), 0x34e0) // Initialize tile buffer // sets up tile rendering buffer by initializing color values for all tile vertices in a structured 6x6 grid pattern
FUNCPTR(D2CLIENT, UpdateRenderBounds_3560, void __fastcall, (int x, int y), 0x3560) // Update render bounds // updates rendering boundary calculations for 3D objects by tracking minimum and maximum coordinates and setting render flags
FUNCPTR(D2CLIENT, RenderTilesWithTransform_35e0, void, (undefined1* buffer, int x, int y, int param4, int transformMode, int edgeMode), 0x35e0) // Render tiles with transform // advanced tile rendering system that applies coordinate transformations, perspective calculations, and lighting effects
FUNCPTR(D2CLIENT, RenderIsometricGrid_37a0, void, (undefined1* buffer, int x, int y, undefined4 param4, int lightingMode, int projectionMode, int edgeMode), 0x37a0) // Render isometric grid // generates isometric grid rendering with coordinate transformation, lighting calculations, and perspective correction
FUNCPTR(D2CLIENT, RenderTileVertices_38c0, void __thiscall, (void* this, int param1, undefined1 param2), 0x38c0) // Render tile vertices // generates vertex buffer for tile rendering with color interpolation and coordinate transformations using thiscall convention
FUNCPTR(D2CLIENT, RenderVisibleUnits_3a00, void, (int param1), 0x3a00) // Render visible units // comprehensive unit rendering system with LOD calculations, animation state management, alpha blending, and selective rendering based on visibility layers
FUNCPTR(D2CLIENT, RenderUnitWithEffects_3ce0, void, (int unit, undefined4 param2, int x, int y, int param5, int param6), 0x3ce0) // Render unit with effects // advanced unit rendering with special effects, lighting calculations, and multiple rendering modes
FUNCPTR(D2CLIENT, RenderSingleUnit_3f40, void, (void), 0x3f40) // Render single unit // handles individual unit rendering with coordinate transformation and device context management
FUNCPTR(D2CLIENT, RenderTripleUnit_3fd0, void, (void), 0x3fd0) // Render triple unit // utility function that renders multiple unit layers or animation frames in sequence
FUNCPTR(D2CLIENT, InitializeRenderContext_4050, void, (int param1), 0x4050) // Initialize render context // comprehensive rendering context initialization including graphics device setup and viewport calculation
FUNCPTR(D2CLIENT, FindRegionByCoordinates_1180, int __fastcall, (undefined4 param1, int param2), 0x1180) // Finds region index by coordinates // searches through region table using X,Y coordinates and returns matching region index
FUNCPTR(D2CLIENT, UIBoundaryCalculator_11b0, int __stdcall, (int value), 0x11b0) // UI boundary calculation function // performs mathematical operations for UI positioning and returns processed coordinate value
FUNCPTR(D2CLIENT, ScrollableListCalculator_11f0, int __fastcall, (int startValue, int itemCount), 0x11f0) // Scrollable list calculation system // handles list iteration and scroll positioning with boundary validation and returns updated scroll position
FUNCPTR(D2CLIENT, CountdownTimer_1240, longlong, (void), 0x1240) // Countdown timer // manages countdown operations with frame counting and returns timing state as 64-bit value
FUNCPTR(D2CLIENT, UIElementInteractionValidator_12e0, undefined4 __fastcall, (int param1), 0x12e0) // UI element interaction validator // performs complex validation checks for UI element interactions using scrollable list calculations and coordinate boundary testing

// Audio and Sound System
FUNCPTR(D2CLIENT, ScrollNavigationSystem_1360, undefined __fastcall, (int direction, int speed), 0x1360) // Scroll navigation system with recursive functionality // handles list scrolling, direction validation, and smooth scrolling transitions with recursion for complex navigation
FUNCPTR(D2CLIENT, ConfigureUILayout_1410, undefined4 __stdcall, (void* layoutConfig), 0x1410) // UI layout configuration function // sets up interface layout parameters, positioning calculations, and element arrangement based on screen resolution
FUNCPTR(D2CLIENT, AudioSystemManager_14f0, void, (int param1), 0x14f0) // Audio system manager // initializes and configures audio subsystems including sound effects, music playback, and system-specific audio optimizations

// Game Timing and Update Systems
FUNCPTR(D2CLIENT, UILayoutRenderer_1630, undefined4 __stdcall, (int x, int y, int width, int height), 0x1630) // UI layout renderer with coordinate calculations // performs complex layout rendering with position calculations, bounds checking, and returns layout status
FUNCPTR(D2CLIENT, ScrollAnimationController_17c0, void __fastcall, (int direction), 0x17c0) // Scroll animation controller // manages smooth scrolling animations with recursive functionality for handling scroll acceleration and deceleration

// Network and Multiplayer Systems
FUNCPTR(D2CLIENT, NetworkPacketProcessor_19c0, void, (void), 0x19c0) // Network packet processor // processes network packets using stored packet data and validates packet integrity
FUNCPTR(D2CLIENT, InitializeScrollableList_1a20, void, (void), 0x1a20) // Initialize scrollable list system // sets up scrollable list UI components by configuring layout, loading UI resources, and initializing scroll state variables
FUNCPTR(D2CLIENT, HandleScrollableListInput_1a80, void, (int x, int y), 0x1a80) // Handle scrollable list input // comprehensive input handler for scrollable list interactions including mouse clicks, scroll wheel events, and keyboard navigation
FUNCPTR(D2CLIENT, CleanupUIResources_1f80, void, (void), 0x1f80) // Cleanup UI resources // performs comprehensive cleanup of UI system resources including memory deallocation and resetting global UI state variables
FUNCPTR(D2CLIENT, HandleScrollableListInput_1a80, void, (int x, int y), 0x1a80) // Handle scrollable list input // comprehensive input handler for scrollable list interactions including mouse clicks, scroll wheel events, and keyboard navigation
FUNCPTR(D2CLIENT, PlayerSyncManager_1a20, void __stdcall, (int playerId), 0x1a20) // Player synchronization manager // maintains player state consistency across multiplayer sessions
FUNCPTR(D2CLIENT, GameStateSync_1a80, void __stdcall, (void), 0x1a80) // Game state synchronizer // ensures consistent game state across all players in multiplayer games

// AI and Monster Behavior System
FUNCPTR(D2CLIENT, MonsterAI_RandomAction_7b0d, void __fastcall, (ulonglong* param1), 0x7b0d) // Monster AI random action selector // uses random number generation to determine monster behavior patterns and action selection based on probability thresholds
FUNCPTR(D2CLIENT, MonsterAIProcessor_1f80, void __stdcall, (void* monster), 0x1f80) // Monster AI processor // executes monster behavior algorithms, pathfinding, and combat decision making
FUNCPTR(D2CLIENT, ComplexUIRenderer_25a0, int __stdcall, (void* uiState, int renderFlags), 0x25a0) // Complex UI rendering system with comprehensive state management // handles sophisticated interface rendering with multi-component layout, state tracking, error handling, and returns render status
FUNCPTR(D2CLIENT, GameModeTransition_2dd0, void, (int param1), 0x2dd0) // Game mode transition manager // handles transitions between different game modes, manages UI state, selection state, and background data copying
FUNCPTR(D2CLIENT, InitializeMainMenuAudio_2eb0, void, (void), 0x2eb0) // Initialize main menu audio system // sets up audio configuration for main menu including background music initialization and platform-specific audio optimizations
FUNCPTR(D2CLIENT, HandleMenuItemSelection_30b0, void __thiscall, (void* this, int param1), 0x30b0) // Handle menu item selection // processes menu item selection events including validation of selected items and execution of selection callbacks

// Item and Inventory Management
FUNCPTR(D2CLIENT, ItemGenerator_30b0, void* __stdcall, (int itemType, int level, int quality), 0x30b0) // Item generator // creates items with randomized properties, affixes, and statistics based on item level
FUNCPTR(D2CLIENT, InventoryManager_3450, int __stdcall, (void* inventory, void* item, int x, int y), 0x3450) // Inventory manager // handles item placement, stacking, and inventory space calculations
FUNCPTR(D2CLIENT, ItemIdentification_34e0, void __stdcall, (void* item), 0x34e0) // Item identification system // reveals hidden item properties and calculates final item statistics
FUNCPTR(D2CLIENT, ItemUpgrade_3560, int __stdcall, (void* item, void* upgrade), 0x3560) // Item upgrade system // handles item enhancement, socket insertion, and item transformation
FUNCPTR(D2CLIENT, GemSocketManager_35e0, int __stdcall, (void* item, void* gem, int socketIndex), 0x35e0) // Gem and socket manager // handles gem insertion, removal, and socket property calculations

// World and Environment Systems
FUNCPTR(D2CLIENT, TerrainGenerator_37a0, void __stdcall, (int levelId, int seed), 0x37a0) // Terrain generator // creates random dungeon layouts and wilderness areas using procedural generation
FUNCPTR(D2CLIENT, CollisionDetection_38c0, int __stdcall, (int x1, int y1, int x2, int y2, int unitType), 0x38c0) // Collision detection system // handles unit-to-unit and unit-to-terrain collision checking
FUNCPTR(D2CLIENT, WeatherSystem_3a00, void __stdcall, (int weatherType, int intensity), 0x3a00) // Weather system // manages environmental effects like rain, snow, and atmospheric conditions
FUNCPTR(D2CLIENT, DaylightCycle_3ce0, void __stdcall, (int timeOfDay), 0x3ce0) // Day/night cycle manager // controls lighting transitions and time-based environmental changes
FUNCPTR(D2CLIENT, PortalManager_3f40, void __stdcall, (int sourceLevel, int destLevel, int x, int y), 0x3f40) // Portal manager // handles waypoint and portal creation, validation, and travel mechanics
FUNCPTR(D2CLIENT, TownPortal_3fd0, int __stdcall, (void* player, int townId), 0x3fd0) // Town portal system // manages town portal creation, destination validation, and portal usage
FUNCPTR(D2CLIENT, WaypointSystem_4050, void __stdcall, (int waypointId, int playerId), 0x4050) // Waypoint system // tracks discovered waypoints and handles fast travel between areas

// Advanced Unit and Object Management
FUNCPTR(D2CLIENT, HandleUnitInteraction_ffc0, void __fastcall, (int* param1), 0xffc0) // Handles unit interaction events including collision detection, unit positioning, state management, and cleanup operations for different unit types
FUNCPTR(D2CLIENT, NetworkPacketSender_43e0, void, (char* packetData), 0x43e0) // Network packet sender // handles packet transmission with rate limiting, duplicate detection, and packet statistics tracking for network performance monitoring
FUNCPTR(D2CLIENT, SendPacketWithValidation_4720, int __stdcall, (void* packetData, int packetSize), 0x4720) // Network packet validation and transmission // validates packet size boundaries, performs memory operations, and transmits network data with comprehensive error checking
FUNCPTR(D2CLIENT, ProcessNetworkMessage_47a0, void, (void), 0x47a0) // Process network message // parses incoming messages by extracting components, handling variable-length data, and forwarding to packet sender
FUNCPTR(D2CLIENT, SendPositionUpdate_4810, void __fastcall, (undefined4 param1, undefined4 param2, undefined1 param3), 0x4810) // Send position update // transmits player position updates with command type '^' for multiplayer synchronization
FUNCPTR(D2CLIENT, SendUnitCommand_4850, void __fastcall, (undefined4 param1, undefined4 param2, undefined1 param3, int param4), 0x4850) // Send unit command // transmits unit action commands with type ']' including parameters and boolean state flag
FUNCPTR(D2CLIENT, SendGameAction_48a0, void __fastcall, (undefined4 param1, undefined4 param2, undefined4 param3, undefined4 param4), 0x48a0) // Send game action // transmits complex game actions with multiple parameters for game state synchronization
FUNCPTR(D2CLIENT, SendPlayerAction_48e0, void __fastcall, (undefined4 param1, undefined4 param2, undefined4 param3), 0x48e0) // Send player action // transmits player-specific actions with three parameters for character actions and ability usage
FUNCPTR(D2CLIENT, SendSimpleCommand_4910, void __fastcall, (undefined4 param1, undefined4 param2), 0x4910) // Send simple command // transmits basic commands with two parameters for basic game interactions and system commands
FUNCPTR(D2CLIENT, SendEmptyPacket_4940, void, (void), 0x4940) // Send empty packet // transmits minimal network packet for keepalive messages, heartbeat signals, or basic network presence notifications

// Game Economy and Trading Systems
FUNCPTR(D2CLIENT, VendorManager_49a0, void __stdcall, (void* vendor, void* player), 0x49a0) // Vendor manager // handles NPC shop interactions, item pricing, and inventory management
FUNCPTR(D2CLIENT, TradeSystem_49e0, int __stdcall, (void* player1, void* player2), 0x49e0) // Player trading system // manages secure item trades between players with validation
FUNCPTR(D2CLIENT, GoldManager_4a10, void __stdcall, (void* player, int goldAmount), 0x4a10) // Gold manager // handles gold transactions, storage limits, and gold-based calculations
FUNCPTR(D2CLIENT, GamblingSystem_4a30, void* __stdcall, (void* player, int itemType, int cost), 0x4a30) // Gambling system // handles item gambling mechanics with weighted random generation
FUNCPTR(D2CLIENT, ShopRefresh_4a50, void __stdcall, (void* vendor), 0x4a50) // Shop refresh system // regenerates vendor inventories with new items and pricing

// Advanced Game Mechanics
FUNCPTR(D2CLIENT, ResistanceCalculator_4b00, int __stdcall, (void* unit, int damageType), 0x4b00) // Resistance calculator // computes damage reduction based on resistances and immunities
FUNCPTR(D2CLIENT, CriticalHitSystem_4f40, int __stdcall, (void* attacker, void* target), 0x4f40) // Critical hit system // calculates critical strike chances and damage multipliers
FUNCPTR(D2CLIENT, BlockingSystem_4fd0, int __stdcall, (void* defender, int attackAngle), 0x4fd0) // Blocking system // handles shield blocking mechanics and block animations
FUNCPTR(D2CLIENT, DodgeSystem_51b0, int __stdcall, (void* unit, int attackType), 0x51b0) // Dodge system // calculates dodge chances and evasion mechanics
FUNCPTR(D2CLIENT, StatusEffectManager_5350, void __stdcall, (void* unit, int effectType, int duration), 0x5350) // Status effect manager // applies and manages temporary effects like poison, freeze, etc.
FUNCPTR(D2CLIENT, AuraStackingManager_5500, void __stdcall, (void* unit), 0x5500) // Aura stacking manager // handles multiple aura effects and their interaction rules

// File I/O and Resource Management
FUNCPTR(D2CLIENT, SkillCastingSystem_5ab0, undefined4 __fastcall, (int* param1, int param2, undefined4 param3), 0x5ab0) // Skill casting system // handles skill validation, unit positioning, coordinate calculations, and skill effect execution with comprehensive bounds checking
FUNCPTR(D2CLIENT, ResourceManager_5c40, void __stdcall, (void), 0x5c40) // Resource manager // manages memory usage for game assets with garbage collection
FUNCPTR(D2CLIENT, SaveGameManager_5da0, int __stdcall, (void* gameData, char* filename), 0x5da0) // Save game manager // handles game state serialization and save file management
FUNCPTR(D2CLIENT, LoadGameManager_5fc0, int __stdcall, (char* filename), 0x5fc0) // Load game manager // deserializes save files and restores game state
FUNCPTR(D2CLIENT, ConfigurationLoader_60a0, void __stdcall, (char* configFile), 0x60a0) // Configuration loader // loads game settings from configuration files

// Advanced Graphics and Effects
FUNCPTR(D2CLIENT, ShaderManager_60e0, void __stdcall, (int shaderId, void* parameters), 0x60e0) // Shader manager // applies visual effects and post-processing shaders
FUNCPTR(D2CLIENT, BlendModeController_6130, void __stdcall, (int blendMode), 0x6130) // Blend mode controller // manages alpha blending and transparency effects
FUNCPTR(D2CLIENT, ColorGrading_61b0, void __stdcall, (int contrast, int brightness, int saturation), 0x61b0) // Color grading system // adjusts visual appearance with color correction
FUNCPTR(D2CLIENT, ScreenEffects_6250, void __stdcall, (int effectType, int intensity), 0x6250) // Screen effects // manages screen-space effects like blur, fade, and distortion
FUNCPTR(D2CLIENT, LightmapGenerator_62d0, void __stdcall, (int levelId), 0x62d0) // Lightmap generator // pre-calculates static lighting for level geometry
FUNCPTR(D2CLIENT, ShadowRenderer_6300, void __stdcall, (void* unit, int lightSource), 0x6300) // Shadow renderer // renders dynamic shadows with proper perspective and attenuation
FUNCPTR(D2CLIENT, DepthBuffer_6360, void __stdcall, (void), 0x6360) // Depth buffer manager // handles Z-buffer operations for proper depth sorting

// Advanced Audio System
FUNCPTR(D2CLIENT, AudioStreaming_64f0, void __stdcall, (char* audioFile), 0x64f0) // Audio streaming // manages streaming audio playback for music and ambient sounds
FUNCPTR(D2CLIENT, SoundOcclusion_6620, void __stdcall, (int sourceX, int sourceY, int listenerX, int listenerY), 0x6620) // Sound occlusion // calculates audio attenuation based on geometry and distance
FUNCPTR(D2CLIENT, VoiceManager_66c0, void __stdcall, (int voiceId, int playerId), 0x66c0) // Voice manager // handles character voice acting and dialogue audio
FUNCPTR(D2CLIENT, EnvironmentalAudio_67d0, void __stdcall, (int environmentType), 0x67d0) // Environmental audio // manages ambient sound effects and environmental acoustics
FUNCPTR(D2CLIENT, AudioEffects_6910, void __stdcall, (int effectType, void* audioData), 0x6910) // Audio effects processor // applies real-time audio effects like reverb and echo

// Advanced Animation and Physics
FUNCPTR(D2CLIENT, SkeletalAnimation_6a90, void __stdcall, (void* skeleton, int animationId, float time), 0x6a90) // Skeletal animation // manages bone-based character animations with interpolation
FUNCPTR(D2CLIENT, PhysicsSimulation_6c20, void __stdcall, (void* object, float deltaTime), 0x6c20) // Physics simulation // handles object physics including gravity, collisions, and momentum
FUNCPTR(D2CLIENT, ClothSimulation_6cb0, void __stdcall, (void* cloth, int windForce), 0x6cb0) // Cloth simulation // simulates fabric and cloth physics for realistic clothing
FUNCPTR(D2CLIENT, ParticlePhysics_6d80, void __stdcall, (void* particle, float deltaTime), 0x6d80) // Particle physics // manages particle movement, collisions, and lifecycle
FUNCPTR(D2CLIENT, FluidSimulation_6dd0, void __stdcall, (int fluidType, int x, int y), 0x6dd0) // Fluid simulation // handles liquid effects like water, lava, and magical fluids

// Memory and Performance Optimization
FUNCPTR(D2CLIENT, MemoryPool_6eb0, void* __stdcall, (int poolId, int size), 0x6eb0) // Memory pool manager // optimized memory allocation using pre-allocated pools
FUNCPTR(D2CLIENT, ObjectPooling_6fe0, void* __stdcall, (int objectType), 0x6fe0) // Object pooling // reuses game objects to reduce allocation overhead
FUNCPTR(D2CLIENT, GarbageCollector_7010, void __stdcall, (void), 0x7010) // Garbage collector // reclaims unused memory and optimizes memory usage
FUNCPTR(D2CLIENT, PerformanceProfiler_7270, void __stdcall, (char* sectionName, int start), 0x7270) // Performance profiler // measures execution time for optimization analysis
FUNCPTR(D2CLIENT, FrameRateController_7300, void __stdcall, (int targetFPS), 0x7300) // Frame rate controller // maintains consistent frame rate with adaptive timing
FUNCPTR(D2CLIENT, LODManager_7390, void __stdcall, (void* object, float distance), 0x7390) // Level of detail manager // adjusts object detail based on distance for performance

// Advanced Networking
FUNCPTR(D2CLIENT, NetworkProtocol_73e0, int __stdcall, (void* packet, int type), 0x73e0) // Network protocol handler // manages game-specific network protocol implementation
FUNCPTR(D2CLIENT, LatencyCompensation_7500, void __stdcall, (int playerId, int latency), 0x7500) // Latency compensation // adjusts game timing to compensate for network delays
FUNCPTR(D2CLIENT, AntiCheatValidator_76a0, int __stdcall, (void* playerData), 0x76a0) // Anti-cheat validator // validates player actions and data for cheat detection
FUNCPTR(D2CLIENT, NetworkCompression_7710, int __stdcall, (void* data, int size, void* compressed), 0x7710) // Network compression // compresses network data to reduce bandwidth usage
FUNCPTR(D2CLIENT, ReliableTransport_7800, void __stdcall, (void* packet, int priority), 0x7800) // Reliable transport // ensures critical packets are delivered and acknowledged

// Advanced AI and Decision Making
FUNCPTR(D2CLIENT, BehaviorTree_7950, void __stdcall, (void* ai, void* tree), 0x7950) // Behavior tree processor // executes complex AI decision trees for advanced monster behavior
FUNCPTR(D2CLIENT, StateMachine_79e0, void __stdcall, (void* object, int newState), 0x79e0) // State machine controller // manages complex state transitions for game objects
FUNCPTR(D2CLIENT, MonsterAI_BehaviorProcessor_7b60, void, (void), 0x7b60) // Monster AI behavior processor // processes monster unit behavior including random number generation, status effects, and action selection based on probability calculations
FUNCPTR(D2CLIENT, TacticalAnalyzer_7c00, void __stdcall, (void* battlefield), 0x7c00) // Tactical analyzer // analyzes battlefield conditions for strategic AI decisions
FUNCPTR(D2CLIENT, LearningSystem_7e10, void __stdcall, (void* ai, void* experience), 0x7e10) // Learning system // adapts AI behavior based on player actions and outcomes

// World Generation and Procedural Content
FUNCPTR(D2CLIENT, DungeonGenerator_7e80, void __stdcall, (int seed, int difficulty, int size), 0x7e80) // Dungeon generator // creates procedural dungeon layouts with proper connectivity
FUNCPTR(D2CLIENT, LootDistribution_7f70, void __stdcall, (int areaLevel, int playerCount), 0x7f70) // Loot distribution // manages item drop rates and treasure placement
FUNCPTR(D2CLIENT, MonsterSpawner_81a0, void __stdcall, (int areaId, int spawnRate), 0x81a0) // Monster spawner // controls monster population and spawn timing
FUNCPTR(D2CLIENT, EnvironmentPopulator_8370, void __stdcall, (int levelId), 0x8370) // Environment populator // places interactive objects and environmental details
FUNCPTR(D2CLIENT, QuestGenerator_84d0, void __stdcall, (int questType, int difficulty), 0x84d0) // Quest generator // creates dynamic quests with appropriate rewards

// Advanced Combat Systems
FUNCPTR(D2CLIENT, CombatResolver_85e0, int __stdcall, (void* combat), 0x85e0) // Combat resolver // processes complex combat interactions with multiple participants
FUNCPTR(D2CLIENT, WeaponPhysics_8650, void __stdcall, (void* weapon, void* target), 0x8650) // Weapon physics // simulates weapon mechanics including reach, speed, and impact
FUNCPTR(D2CLIENT, ArmorCalculator_86a0, int __stdcall, (void* armor, int damageType), 0x86a0) // Armor calculator // computes armor effectiveness against different damage types
FUNCPTR(D2CLIENT, CombatAnimations_8880, void __stdcall, (void* unit, int attackType), 0x8880) // Combat animations // manages attack and defense animations with proper timing
FUNCPTR(D2CLIENT, HitDetection_8920, int __stdcall, (void* attacker, void* target, void* weapon), 0x8920) // Hit detection // determines successful hits based on accuracy and positioning

// User Interface and Input Systems
FUNCPTR(D2CLIENT, InputManager_89a0, void __stdcall, (int inputType, int value), 0x89a0) // Input manager // processes keyboard, mouse, and controller input with customization
FUNCPTR(D2CLIENT, UIAnimations_8a00, void __stdcall, (void* uiElement, int animationType), 0x8a00) // UI animations // manages smooth transitions and interactive feedback for interface
FUNCPTR(D2CLIENT, TooltipSystem_8ac0, void __stdcall, (void* object, int x, int y), 0x8ac0) // Tooltip system // displays contextual information and item descriptions
FUNCPTR(D2CLIENT, HotkeyManager_8b20, void __stdcall, (int keyCode, int action), 0x8b20) // Hotkey manager // handles customizable keyboard shortcuts and macro commands
FUNCPTR(D2CLIENT, ContextMenu_8bc0, void __stdcall, (void* object, int x, int y), 0x8bc0) // Context menu // displays context-sensitive action menus for game objects

// Advanced Graphics Pipeline
FUNCPTR(D2CLIENT, RenderPipeline_8e20, void __stdcall, (void), 0x8e20) // Render pipeline // coordinates the complete graphics rendering process from geometry to pixels
FUNCPTR(D2CLIENT, CullingSystem_8f40, void __stdcall, (void* camera), 0x8f40) // Culling system // removes non-visible objects to optimize rendering performance
FUNCPTR(D2CLIENT, TextureStreaming_8f90, void __stdcall, (void), 0x8f90) // Texture streaming // dynamically loads and unloads textures based on visibility
FUNCPTR(D2CLIENT, GeometryBatching_9030, void __stdcall, (void), 0x9030) // Geometry batching // combines similar objects to reduce draw calls and improve performance
FUNCPTR(D2CLIENT, PostProcessing_90b0, void __stdcall, (void* frameBuffer), 0x90b0) // Post-processing // applies screen-space effects after main rendering

// Game Balance and Progression
FUNCPTR(D2CLIENT, BalanceCalculator_9130, int __stdcall, (int playerLevel, int monsterLevel), 0x9130) // Balance calculator // adjusts game difficulty based on player progression
FUNCPTR(D2CLIENT, ProgressionTracker_91e0, void __stdcall, (void* player, int achievement), 0x91e0) // Progression tracker // monitors player advancement and unlocks content
FUNCPTR(D2CLIENT, DifficultyScaling_9350, void __stdcall, (int difficulty, int playerCount), 0x9350) // Difficulty scaling // adjusts game challenge based on party size and difficulty setting
FUNCPTR(D2CLIENT, RewardSystem_94e0, void __stdcall, (void* player, int actionType, int value), 0x94e0) // Reward system // calculates and distributes experience, gold, and item rewards
FUNCPTR(D2CLIENT, AchievementSystem_9710, void __stdcall, (void* player, int achievementId), 0x9710) // Achievement system // tracks and validates player accomplishments

// Data Management and Serialization
FUNCPTR(D2CLIENT, DataSerializer_97d0, int __stdcall, (void* data, void* buffer, int size), 0x97d0) // Data serializer // converts game data to binary format for storage and transmission
FUNCPTR(D2CLIENT, DataDeserializer_9830, int __stdcall, (void* buffer, void* data, int size), 0x9830) // Data deserializer // reconstructs game data from binary format
FUNCPTR(D2CLIENT, ChecksumValidator_9d80, int __stdcall, (void* data, int size), 0x9d80) // Checksum validator // validates data integrity using hash algorithms
FUNCPTR(D2CLIENT, CompressionEngine_9ef0, int __stdcall, (void* input, void* output, int inputSize), 0x9ef0) // Compression engine // compresses game data for storage and network efficiency
FUNCPTR(D2CLIENT, EncryptionManager_a010, void __stdcall, (void* data, int size, void* key), 0xa010) // Encryption manager // secures sensitive game data with cryptographic protection

// Localization and Internationalization
FUNCPTR(D2CLIENT, LocalizationManager_a060, char* __stdcall, (int stringId, int languageId), 0xa060) // Localization manager // retrieves localized text strings for multiple languages
FUNCPTR(D2CLIENT, FontRenderer_aaa0, void __stdcall, (char* text, int x, int y, int fontId), 0xaaa0) // Font renderer // renders text with proper character encoding and font styling
FUNCPTR(D2CLIENT, TextLayout_ab20, void __stdcall, (char* text, int width, int alignment), 0xab20) // Text layout // manages text formatting, word wrapping, and alignment
FUNCPTR(D2CLIENT, UnicodeSupport_b1d0, int __stdcall, (wchar_t* text), 0xb1d0) // Unicode support // handles wide character text processing for international languages
FUNCPTR(D2CLIENT, CharacterEncoding_b320, void __stdcall, (char* input, wchar_t* output, int encoding), 0xb320) // Character encoding // converts between different text encodings

// Advanced Memory Management
FUNCPTR(D2CLIENT, SmartPointers_b360, void* __stdcall, (void* object), 0xb360) // Smart pointer system // provides automatic memory management with reference counting
FUNCPTR(D2CLIENT, MemoryTracker_b540, void __stdcall, (void* ptr, int size, char* source), 0xb540) // Memory tracker // monitors memory allocations for debugging and optimization
FUNCPTR(D2CLIENT, LeakDetector_b620, void __stdcall, (void), 0xb620) // Memory leak detector // identifies and reports memory leaks for debugging
FUNCPTR(D2CLIENT, CacheManager_b700, void* __stdcall, (int cacheType, void* key), 0xb700) // Cache manager // implements intelligent caching for frequently accessed data
FUNCPTR(D2CLIENT, BufferPool_b7f0, void* __stdcall, (int size), 0xb7f0) // Buffer pool // provides reusable buffers to reduce allocation overhead

// Quality Assurance and Debugging
FUNCPTR(D2CLIENT, DebugConsole_bcc0, void __stdcall, (char* command), 0xbcc0) // Debug console // provides runtime debugging interface for development and testing
FUNCPTR(D2CLIENT, AssertionHandler_be90, void __stdcall, (char* condition, char* file, int line), 0xbe90) // Assertion handler // manages debug assertions and error reporting
FUNCPTR(D2CLIENT, LoggingSystem_bf4c, void __stdcall, (int level, char* message), 0xbf4c) // Logging system // provides structured logging with multiple verbosity levels
FUNCPTR(D2CLIENT, ErrorReporter_c150, void __stdcall, (int errorCode, char* description), 0xc150) // Error reporter // centralizes error handling and crash reporting
FUNCPTR(D2CLIENT, TestFramework_c720, int __stdcall, (void* testSuite), 0xc720) // Test framework // provides automated testing infrastructure for quality assurance

// Platform and Hardware Abstraction
FUNCPTR(D2CLIENT, PlatformLayer_c740, void __stdcall, (void), 0xc740) // Platform abstraction layer // provides cross-platform compatibility for different operating systems
FUNCPTR(D2CLIENT, HardwareDetection_c890, void __stdcall, (void), 0xc890) // Hardware detection // identifies system capabilities and adjusts settings accordingly
FUNCPTR(D2CLIENT, DriverInterface_c940, int __stdcall, (int driverType), 0xc940) // Driver interface // manages graphics and audio driver communication
FUNCPTR(D2CLIENT, SystemInfo_c980, void __stdcall, (void* info), 0xc980) // System information // gathers system specifications for optimization decisions
FUNCPTR(D2CLIENT, PerformanceCounter_ca00, longlong __stdcall, (void), 0xca00) // Performance counter // provides high-resolution timing for performance measurement

// Advanced Security and Anti-Cheat
FUNCPTR(D2CLIENT, IntegrityChecker_cad0, int __stdcall, (void), 0xcad0) // Integrity checker // validates game executable and data file integrity
FUNCPTR(D2CLIENT, BehaviorAnalyzer_cc00, void __stdcall, (void* player, int action), 0xcc00) // Behavior analyzer // monitors player actions for suspicious patterns
FUNCPTR(D2CLIENT, NetworkSecurity_ccd0, int __stdcall, (void* packet), 0xccd0) // Network security // validates and encrypts network communications
FUNCPTR(D2CLIENT, ModDetection_ce00, int __stdcall, (void), 0xce00) // Modification detection // identifies unauthorized game modifications
FUNCPTR(D2CLIENT, SecureRandom_d6e0, int __stdcall, (void), 0xd6e0) // Secure random // provides cryptographically secure random number generation

// Game World Persistence and State Management
FUNCPTR(D2CLIENT, WorldState_d740, void __stdcall, (void* world), 0xd740) // World state manager // maintains persistent world state across game sessions
FUNCPTR(D2CLIENT, SaveGameIntegrity_d840, int __stdcall, (char* saveFile), 0xd840) // Save game integrity // validates save file authenticity and prevents tampering
FUNCPTR(D2CLIENT, BackupManager_d8f0, void __stdcall, (char* saveFile), 0xd8f0) // Backup manager // creates and manages automatic save file backups
FUNCPTR(D2CLIENT, CloudSync_d930, void __stdcall, (void* saveData), 0xd930) // Cloud synchronization // manages save game synchronization with cloud storage
FUNCPTR(D2CLIENT, SessionManager_da90, void __stdcall, (int sessionType), 0xda90) // Session manager // handles game session lifecycle and state transitions

// Advanced Analytics and Telemetry
FUNCPTR(D2CLIENT, TelemetryCollector_dcc0, void __stdcall, (char* event, void* data), 0xdcc0) // Telemetry collector // gathers anonymous usage statistics for game improvement
FUNCPTR(D2CLIENT, AnalyticsEngine_e070, void __stdcall, (void), 0xe070) // Analytics engine // processes gameplay data to identify trends and issues
FUNCPTR(D2CLIENT, MetricsAggregator_e160, void __stdcall, (char* metric, float value), 0xe160) // Metrics aggregator // combines performance metrics for analysis
FUNCPTR(D2CLIENT, UserBehavior_e5f0, void __stdcall, (void* player, int behaviorType), 0xe5f0) // User behavior tracker // analyzes player behavior patterns
FUNCPTR(D2CLIENT, GameplayMetrics_e7e0, void __stdcall, (void), 0xe7e0) // Gameplay metrics // collects detailed gameplay statistics

// Experimental and Research Features
FUNCPTR(D2CLIENT, MachineLearning_e940, void __stdcall, (void* model, void* input), 0xe940) // Machine learning // experimental AI features using neural networks
FUNCPTR(D2CLIENT, ProceduralAI_ef10, void __stdcall, (void* parameters), 0xef10) // Procedural AI // generates AI behavior patterns procedurally
FUNCPTR(D2CLIENT, AdaptiveDifficulty_fca0, void __stdcall, (void* player), 0xfca0) // Adaptive difficulty // dynamically adjusts challenge based on player skill
FUNCPTR(D2CLIENT, EmergentGameplay_fd00, void __stdcall, (void* situation), 0xfd00) // Emergent gameplay // creates unexpected gameplay situations from system interactions
FUNCPTR(D2CLIENT, RealtimeAnalysis_fdd0, void __stdcall, (void), 0xfdd0) // Real-time analysis // provides live analysis of game performance and player behavior

// Final System Integration and Cleanup
FUNCPTR(D2CLIENT, SystemIntegration_ffc0, void __stdcall, (void), 0xffc0) // System integration // coordinates all game systems for seamless operation

// Visual Studio C++ Runtime File I/O and String Processing Functions
FUNCPTR(D2CLIENT, FileOpenWithSharing_36f1, void __cdecl, (char* filename, char* mode), 0x36f1) // File open with sharing // calls __fsopen with sharing mode 0x40 for shared file access with Visual Studio C++ runtime
FUNCPTR(D2CLIENT, UnlockFileFromStack_384d, void __stdcall, (void), 0x384d) // Unlock file from stack // releases file lock using __unlock_file with FILE pointer from stack frame offset +0x14
FUNCPTR(D2CLIENT, UnlockFileFromRegister_38ec, void __stdcall, (void), 0x38ec) // Unlock file from register // releases file lock using __unlock_file with FILE pointer from ESI register
FUNCPTR(D2CLIENT, StringTokenizer_3be4, void __cdecl, (char* string, char* delimiters), 0x3be4) // String tokenizer function // implements strtok functionality with delimiter bitmap, uses thread-local storage and stack protection for parsing strings into tokens
FUNCPTR(D2CLIENT, LocalUnwindWrapper_4a3e, void __stdcall, (void* param), 0x4a3e) // Local unwind wrapper // calls __local_unwind2 for exception handling stack unwinding with frame data from stack offsets +0x18 and +0x1c
FUNCPTR(D2CLIENT, PrintfFormatProcessor_4c8f, void __cdecl, (DWORD param1, char* format, void* args), 0x4c8f) // Printf format processor // comprehensive printf format string parser with state machine, handles all format specifiers (%d, %s, %f, %x, etc.), field width, precision, flags, and type modifiers with stack protection
FUNCPTR(D2CLIENT, FlushFileWithCommit_5c07, int __cdecl, (FILE* file), 0x5c07) // Flush file with commit // flushes file buffer using __flush and optionally commits to disk if _IOCOMMIT flag (0x4000) is set, returns -1 on error
FUNCPTR(D2CLIENT, ScanfFormatProcessor_61bc, void __cdecl, (FILE* file, char* format, void* args), 0x61bc) // Scanf format processor // comprehensive scanf format string parser with state machine, handles all input specifiers (%d, %s, %f, %x, %c, %[]), field width, type modifiers, character sets, with SEH protection and complex input validation

// Additional Thread Synchronization and File Handle Management Functions
FUNCPTR(D2CLIENT, UnlockSection4_48e4, void __stdcall, (void), 0x48e4) // Unlocks critical section 4 // releases critical section lock index 4 for thread synchronization management
FUNCPTR(D2CLIENT, UnlockSection1_593a, void __stdcall, (void), 0x593a) // Unlocks critical section 1 // releases critical section lock index 1 for thread synchronization management
FUNCPTR(D2CLIENT, UnlockFileHandle_5b86, void __stdcall, (void), 0x5b86) // Unlock file handle // releases file handle lock using __unlock_fhandle with file handle from EBX register
FUNCPTR(D2CLIENT, UnlockFileHandle2_6157, void __stdcall, (void), 0x6157) // Unlock file handle variant 2 // releases file handle lock using __unlock_fhandle with file handle from EBX register, identical to UnlockFileHandle_5b86

// Thread Synchronization and System Management Functions (0x72b5-0x840a)
FUNCPTR(D2CLIENT, UnlockCriticalSection1_72b5, VOID __stdcall, (VOID), 0x772B5) // Visual Studio C++ runtime // unlocks critical section index 1 for thread synchronization
FUNCPTR(D2CLIENT, AllocateThreadLocalStorage_72be, DWORD __stdcall, (VOID), 0x772BE) // Visual Studio C++ runtime // allocates thread-local storage slot using TlsAlloc() for per-thread data management
FUNCPTR(D2CLIENT, UnlockCriticalSection13_749a, VOID __stdcall, (VOID), 0x7749A) // Visual Studio C++ runtime // unlocks critical section index 13 for thread synchronization
FUNCPTR(D2CLIENT, UnlockCriticalSection12_74a6, VOID __stdcall, (VOID), 0x774A6) // Visual Studio C++ runtime // unlocks critical section index 12 for thread synchronization
FUNCPTR(D2CLIENT, LocaleMapStringA_77e0, INT __stdcall, (LCID Locale, DWORD dwMapFlags, LPCSTR lpSrcStr, INT cchSrc, LPSTR lpDestStr, INT cchDest), 0x777E0) // Visual Studio C++ runtime // locale-aware string mapping with Unicode conversion and code page handling
FUNCPTR(D2CLIENT, OptimizedStrcpy_7bc0, CHAR* __cdecl, (CHAR* pDestination, CHAR* pSource), 0x77BC0) // Visual Studio C++ runtime // optimized string copy using DWORD-aligned operations and 0x7efefeff bit mask for efficient character detection
FUNCPTR(D2CLIENT, OptimizedStrcat_7bd0, CHAR* __cdecl, (CHAR* pDestination, CHAR* pSource), 0x77BD0) // Visual Studio C++ runtime // optimized string concatenation using DWORD-aligned operations and 0x7efefeff bit mask for efficient string end detection
FUNCPTR(D2CLIENT, UnlockCriticalSection4_7d2a, VOID __stdcall, (VOID), 0x77D2A) // Visual Studio C++ runtime // unlocks critical section index 4 for thread synchronization
FUNCPTR(D2CLIENT, SmallBlockHeapRealloc_7e9d, VOID* __cdecl, (VOID* pMemory, SIZE_T nSize), 0x77E9D) // Visual Studio C++ runtime // reallocates memory in small block heap with SEH protection and heap optimization
FUNCPTR(D2CLIENT, UnlockCriticalSection4_8005, VOID __stdcall, (VOID), 0x78005) // Visual Studio C++ runtime // unlocks critical section index 4 variant for thread synchronization
FUNCPTR(D2CLIENT, UnlockCriticalSection4_80bc, VOID __stdcall, (VOID), 0x780BC) // Visual Studio C++ runtime // unlocks critical section index 4 another variant for memory management operations
FUNCPTR(D2CLIENT, FileReadWithTextMode_81a6, INT __cdecl, (UINT nFileHandle, CHAR* pBuffer, CHAR* pParam3), 0x781A6) // Visual Studio C++ runtime // comprehensive text mode file reading with CRLF conversions, EOF detection, and buffering with look-ahead processing
FUNCPTR(D2CLIENT, UnlockFileHandle_840a, VOID __stdcall, (VOID), 0x7840A) // Visual Studio C++ runtime // unlocks file handle for thread-safe file I/O operations

// Advanced Visual Studio C++ Runtime and System Functions (0x8773-0xff60)
FUNCPTR(D2CLIENT, UnlockFileHandle_8773, VOID __stdcall, (VOID), 0x78773) // Visual Studio C++ runtime // unlocks file handle using __unlock_fhandle for thread-safe file operations
FUNCPTR(D2CLIENT, CallocWithSBH_8797, VOID* __cdecl, (UINT nNum, SIZE_T nSize), 0x78797) // Visual Studio C++ runtime // allocates zero-initialized memory using Small Block Heap optimization when possible, falls back to HeapAlloc
FUNCPTR(D2CLIENT, UnlockCriticalSection4_885d, VOID __stdcall, (VOID), 0x7885D) // Visual Studio C++ runtime // unlocks critical section index 4 for thread synchronization
FUNCPTR(D2CLIENT, DisplayRuntimeError_8ece, VOID __cdecl, (INT nErrorCode), 0x78ECE) // Visual Studio C++ runtime // comprehensive runtime error display system with MessageBox, handles various error types
FUNCPTR(D2CLIENT, SaveExceptionContext_91f2, VOID __stdcall, (VOID), 0x791F2) // Visual Studio C++ runtime // stores exception information in global variables for exception handling system
FUNCPTR(D2CLIENT, ConditionalUnlockFileHandle_a4ac, VOID __stdcall, (VOID), 0x7A4AC) // Visual Studio C++ runtime // conditionally unlocks file handle based on parameter check
FUNCPTR(D2CLIENT, UnlockCriticalSection10_a712, VOID __stdcall, (VOID), 0x7A712) // Visual Studio C++ runtime // unlocks critical section index 10 for thread synchronization
FUNCPTR(D2CLIENT, UnlockCriticalSection10_a816, VOID __stdcall, (VOID), 0x7A816) // Visual Studio C++ runtime // unlocks critical section index 10 variant for thread synchronization
FUNCPTR(D2CLIENT, UnlockCriticalSection11_a8b0, VOID __stdcall, (VOID), 0x7A8B0) // Visual Studio C++ runtime // unlocks critical section index 11 for thread synchronization
FUNCPTR(D2CLIENT, FlushFileBuffers_a8b9, DWORD __cdecl, (UINT nFileHandle), 0x7A8B9) // Visual Studio C++ runtime // flushes file buffers to disk using FlushFileBuffers with comprehensive error handling
FUNCPTR(D2CLIENT, UnlockFileHandle_a959, VOID __stdcall, (VOID), 0x7A959) // Visual Studio C++ runtime // unlocks file handle using __unlock_fhandle
FUNCPTR(D2CLIENT, GetSortingFlags_b150, UINT __cdecl, (VOID), 0x7B150) // Visual Studio C++ runtime // returns locale-specific sorting flags based on input values (0x3a4->0x411, 0x3a8->0x804, etc)
FUNCPTR(D2CLIENT, InitializeCharacterTypes_b1a8, VOID __stdcall, (VOID), 0x7B1A8) // Visual Studio C++ runtime // initializes character type tables using GetCPInfo and LocaleMapStringA for locale-specific operations
FUNCPTR(D2CLIENT, SetCodePageInfo_b343, VOID __cdecl, (UINT nCodePage), 0x7B343) // Visual Studio C++ runtime // configures code page information, handles MBCS lead byte ranges and character type flags
FUNCPTR(D2CLIENT, UnlockCriticalSection13_b61e, VOID __stdcall, (VOID), 0x7B61E) // Visual Studio C++ runtime // unlocks critical section index 13 for thread synchronization
FUNCPTR(D2CLIENT, SecurityFailureHandler_b6ab, VOID __cdecl, (INT nFailureType), 0x7B6AB) // Visual Studio C++ runtime // handles buffer overruns and security failures, displays error message and exits
FUNCPTR(D2CLIENT, GetLocaleCodePage_b7f6, VOID __cdecl, (LCID Locale), 0x7B7F6) // Visual Studio C++ runtime // retrieves code page information for specified locale using GetLocaleInfoA
FUNCPTR(D2CLIENT, ConvertCodePageString_b83d, VOID __cdecl, (UINT nSrcCP, UINT nDstCP, CHAR* pSrcStr, UINT* pSrcLen, CHAR* pDstStr, INT nDstLen), 0x7B83D) // Visual Studio C++ runtime // converts strings between code pages using MultiByteToWideChar/WideCharToMultiByte
FUNCPTR(D2CLIENT, WinAPIErrorHandler1_d520, VOID __stdcall, (VOID), 0x7D520) // Win32 API error handling // validates handles and displays error messages, exits on critical failures
FUNCPTR(D2CLIENT, WinAPIErrorHandler2_d610, VOID __stdcall, (VOID), 0x7D610) // Win32 API error handling variant // similar to d520 with different error conditions
FUNCPTR(D2CLIENT, ValidateHandleOrExit_d670, VOID __fastcall, (INT nHandle), 0x7D670) // Win32 API validation // validates handle parameter, exits application if invalid
FUNCPTR(D2CLIENT, SafeFileOpen_d6a0, BOOL __cdecl, (INT nParam), 0x7D6A0) // Win32 API file operations // safe file opening with error handling, returns success status
FUNCPTR(D2CLIENT, SecureFileOperation_d810, INT __cdecl, (VOID* pParam1, VOID* pParam2), 0x7D810) // Win32 API secure file operations // comprehensive file operation with multiple validation steps
FUNCPTR(D2CLIENT, OptimizedMemcmp_da70, BOOL __fastcall, (VOID* pMem1, VOID* pMem2, UINT nSize), 0x7DA70) // Optimized memory comparison // DWORD-aligned memcmp with byte-level fallback for performance
FUNCPTR(D2CLIENT, OptimizedMemcpyLoop_db00, VOID __thiscall, (VOID* pDest, VOID* pSrc, INT nCount, UINT nSize), 0x7DB00) // Optimized memory copy loop // DWORD-aligned memory copy with loop iteration support
FUNCPTR(D2CLIENT, CriticalSectionManager_df00, VOID __cdecl, (VOID* pParam), 0x7DF00) // Critical section manager // initializes critical sections with thread-safe allocation and cleanup
FUNCPTR(D2CLIENT, HuffmanDecoder_df60, INT __cdecl, (INT nLiteralBits, INT nDistBits, INT nLiteralTable, INT nDistTable, VOID* pState, VOID* pStream), 0x7DF60) // Huffman decoder // implements Huffman decompression for inflate operations
FUNCPTR(D2CLIENT, MemoryAllocatorWrapper_e310, VOID __cdecl, (VOID* pParam1, VOID* pParam2, VOID* pParam3), 0x7E310) // Memory allocator wrapper // allocates memory structures with initialization parameters
FUNCPTR(D2CLIENT, InflateStateMachine_e350, VOID __cdecl, (INT nParam), 0x7E350) // Inflate state machine // main decompression state machine handling various compression states and block types
FUNCPTR(D2CLIENT, InflateOutputCopy_ea40, INT __cdecl, (VOID* pStream, INT nResult), 0x7EA40) // Inflate output copy // copies decompressed data to output buffer with buffer management
FUNCPTR(D2CLIENT, BuildHuffmanTable_ebb0, INT __thiscall, (VOID* pCodes, UINT nCodes, UINT nSymbols, INT nTable1, INT nTable2, VOID* pParam1, INT nParam2, VOID* pParam3, VOID* pParam4), 0x7EBB0) // Build Huffman table // constructs Huffman decoding tables from code lengths
FUNCPTR(D2CLIENT, InflateTrees_f0a0, INT __cdecl, (UINT nCodes, VOID* pCodeLengths, INT* pLiteralBits, INT* pDistBits, VOID* pLiteralTable, VOID* pDistTable, INT nMemory), 0x7F0A0) // Inflate trees // builds literal/length and distance Huffman trees for decompression
FUNCPTR(D2CLIENT, InflateTreesBits_f1e0, INT __cdecl, (VOID* pParam1, VOID* pBitLengths, INT nMemory), 0x7F1E0) // Inflate trees bits // builds bit length Huffman tree for dynamic block decompression
FUNCPTR(D2CLIENT, InflateTreesFixed_f280, VOID __cdecl, (VOID), 0x7F280) // Inflate trees fixed // sets up fixed Huffman tables for fixed block decompression
FUNCPTR(D2CLIENT, InflateCodes_f3f0, VOID __cdecl, (VOID), 0x7F3F0) // Inflate codes // processes Huffman-coded data during decompression
FUNCPTR(D2CLIENT, InflateCodesNew_f450, VOID __cdecl, (VOID), 0x7F450) // Inflate codes new // creates new Huffman code processing context
FUNCPTR(D2CLIENT, InflateCodesFree_f4c0, VOID __cdecl, (VOID), 0x7F4C0) // Inflate codes free // releases Huffman code processing context
FUNCPTR(D2CLIENT, InflateBlocks_ff60, VOID __cdecl, (VOID), 0x7FF60) // Inflate blocks // processes compressed blocks during inflate decompression

// Thread Synchronization and File I/O Functions
FUNCPTR(D2CLIENT, UnlockSection14_3121, void __stdcall, (void), 0x3121) // Unlocks critical section 14 // releases critical section lock index 0xe (14) for thread synchronization management
FUNCPTR(D2CLIENT, LockSection8_350d, void __stdcall, (void), 0x350d) // Locks critical section 8 // acquires critical section lock index 8 for thread synchronization and mutual exclusion
FUNCPTR(D2CLIENT, ConditionalUnlockSection8_3650, void __stdcall, (void), 0x3650) // Conditional unlock section 8 // conditionally unlocks critical section 8 based on parameter comparison for balanced lock/unlock operations
FUNCPTR(D2CLIENT, UnlockFileWrapper_36e7, void __stdcall, (void), 0x36e7) // Unlock file wrapper // releases file lock using __unlock_file for thread-safe file I/O operations with Visual Studio C++ runtime integration


VARPTR(D2CLIENT, MouseOffsetY, int, 0x11995C)
VARPTR(D2CLIENT, MouseOffsetX, int, 0x119960)
VARPTR(D2CLIENT, Divisor, int, 0xF16B0)
VARPTR(D2CLIENT, yShake, int, 0x10B9DC)
VARPTR(D2CLIENT, GameInfo, GameStructInfo *, 0x11B980);
VARPTR(D2CLIENT, Ping, DWORD, 0x119804)
VARPTR(D2CLIENT, Skip, DWORD, 0x119810)
VARPTR(D2CLIENT, FPS, DWORD, 0x11C2AC)
VARPTR(D2CLIENT, WaypointTab, DWORD, 0xFCDD6)
VARPTR(D2CLIENT, xShake, int, 0x11BF00)
VARPTR(D2CLIENT, SelectedInvItem, UnitAny*, 0x11BC38)
VARPTR(D2CLIENT, AutomapMode, int, 0xF16B0)
VARPTR(D2CLIENT, Offset, POINT, 0x11C1F8)
VARPTR(D2CLIENT, FirstAutomapLayer, AutomapLayer *, 0x11C1C0)
VARPTR(D2CLIENT, AutomapLayer, AutomapLayer *, 0x11C1C4)
VARPTR(D2CLIENT, AutomapYPosition, int, 0x11C21C)
VARPTR(D2CLIENT, PlayerUnit, UnitAny *, 0x11BBFC)
VARPTR(D2CLIENT, PlayerUnitList, RosterUnit *, 0x11BC14)
VARPTR(D2CLIENT, QuestTab, DWORD, 0x123395)
VARPTR(D2CLIENT, MouseX, DWORD, 0x11B828)// Updated 1.13c
VARPTR(D2CLIENT, MouseY, DWORD, 0x11B824)
VARPTR(D2CLIENT, MapId, DWORD, 0x11C3BC)// Updated 1.13c
VARPTR(D2CLIENT, AutomapOn, DWORD, 0xFADA8)
VARPTR(D2CLIENT, bWeapSwitch, DWORD, 0x11BC94) 

// Quest Management and Player Progression Functions (0xCCCD0-0xFDD0)
FUNCPTR(D2CLIENT, ValidateQuestProgression, VOID __fastcall, (INT nActLevel), 0xCCCD0) // Validates quest progression and determines current act access level. Checks quest completion flags for major act quests (Den of Evil=7, Radament=0xF, Prison of Ice=0x17, Hell's Forge=0x1A) to determine valid progression level and resets quest UI state
FUNCPTR(D2CLIENT, UpdatePlayerQuestProgress, VOID __fastcall, (VOID* pQuestData), 0xCCE00) // Updates player quest progress and UI display based on character level, difficulty, and quest completion state. Handles complex quest validation including difficulty progression, special quest conditions, and text string formatting
FUNCPTR(D2CLIENT, GetPlayerQuestDisplayText, VOID __fastcall, (VOID* pQuestData), 0xCD580) // Retrieves and formats quest display text for UI elements. Handles quest status formatting and localized text retrieval for quest descriptions and progress indicators
FUNCPTR(D2CLIENT, CheckQuestParticleState, UINT __fastcall, (VOID), 0xCD6E0) // Checks the state of quest particle effects. Searches through particle list to find matching quest particle by ID, validates particle state (must be active state 1), and handles error conditions if particle is found but in wrong state
FUNCPTR(D2CLIENT, IsQuestAvailable, BOOL __fastcall, (INT nQuestId), 0xCD740) // Determines if a quest is available to the player. Validates quest ID bounds, checks quest activation flags, verifies completion state, and performs special validation for quest ID 1 (Den of Evil) by checking display text state. Returns 1 if quest is available, 0 otherwise
FUNCPTR(D2CLIENT, IsPointInQuestJournal, BOOL __fastcall, (INT nX, INT nY), 0xCD840) // Checks if a given point (X,Y coordinates) is within the quest journal interface bounds. Used for mouse click detection and UI interaction handling. Accounts for different positioning based on game difficulty and screen configuration
FUNCPTR(D2CLIENT, CleanupQuestUIState, VOID __fastcall, (VOID* pParam), 0xCD8F0) // Cleans up quest UI state when exiting quest interface. Sends player status update if act level is valid, resets quest display flags, and performs general game resource cleanup. Used when closing quest journal or changing game state
FUNCPTR(D2CLIENT, LoadQuestUIAssets, VOID __stdcall, (VOID), 0xCD930) // Loads quest UI assets including background, tabs, sockets, and completion graphics. Handles expansion pack variations for quest tab graphics based on game configuration
FUNCPTR(D2CLIENT, InitializeQuestActGraphics, VOID __stdcall, (UINT nActId, INT bResetFlags), 0xCDA90) // Initializes quest graphics for specific act. Loads quest icon assets, scans for available quests, and tracks current quest state for UI display. Handles quest highlighting and progression tracking per act
FUNCPTR(D2CLIENT, ResetQuestUIState, VOID __stdcall, (VOID), 0xCDCC0) // Resets quest UI state and clears quest-related variables. Validates game state and updates quest progression if conditions are met, otherwise clears all quest UI flags and resets display indices
FUNCPTR(D2CLIENT, GenerateQuestParticleEffects, UINT __fastcall, (INT nX, INT nY), 0xCE070) // Generates particle effects for quest interface. Uses random number generation to create visual effects at specified coordinates, managing particle creation with proper ID tracking and visual enhancement systems
FUNCPTR(D2CLIENT, ProcessQuestServerMessage, VOID __thiscall, (VOID* pThis, INT pMessage), 0xCE160) // Processes quest-related server messages and updates quest state. Handles various quest message types, manages quest progression, difficulty changes, and UI updates. Central handler for server-to-client quest communications
FUNCPTR(D2CLIENT, RenderQuestJournal, VOID __stdcall, (VOID), 0xCE5F0) // Renders the quest journal interface. Handles journal positioning based on difficulty level, draws quest log entries, and manages quest selection highlighting. Integrates with the game's rendering system for UI display
FUNCPTR(D2CLIENT, HandleQuestInterfaceClose, BOOL __fastcall, (INT bSetCursor), 0xCE7E0) // Handles closing of quest interface and UI cleanup. Resets quest display state, performs game resource cleanup, manages screen positioning adjustments, and handles cursor positioning. Returns success status and manages transition back to game view
FUNCPTR(D2CLIENT, ToggleQuestInterface, VOID __stdcall, (INT bSetCursor), 0xCE940) // Toggles the quest interface on/off with comprehensive state management. Handles timing constraints, validates game state, manages screen positioning for different UI modes, loads quest assets, and sends network updates. Central function for quest journal activation/deactivation
FUNCPTR(D2CLIENT, RenderQuestInterfaceMain, VOID __stdcall, (VOID), 0xCEF10) // Main quest interface rendering function. Draws complete quest journal UI including background, act tabs, quest icons, progress states, quest text, and interactive elements. Handles quest state visualization, completion animations, and user interaction feedback
FUNCPTR(D2CLIENT, SetQuestItemFlag, VOID __fastcall, (VOID* pItem, INT bSetFlag), 0xCFCA0) // Sets or clears quest item flags. Validates input parameters and modifies bit flag 0x1 at offset 0x17 in the quest item structure. Used for marking items as quest-related or removing quest status
FUNCPTR(D2CLIENT, CheckQuestItemFlags, BOOL __fastcall, (VOID* pItem, USHORT nFlags), 0xCFD00) // Checks if specific quest item flags are set. Validates input parameters and tests if given flag bits are set in the quest item flags field at offset 0x16. Returns true if any specified flags match
FUNCPTR(D2CLIENT, BuildQuestItemDescription, VOID __fastcall, (VOID* pItem, Unicode* pDescription, INT nMaxLength), 0xCFDD0) // Builds quest item description text with stats and properties. Handles different quest item types, constructs localized descriptions, processes item stats, and formats text with proper separators. Creates comprehensive item tooltips for quest-related items

// Advanced Unit Sound Management Functions (0xD3070-0xD3F20)
FUNCPTR(D2CLIENT, ProcessActiveUnitSounds, void __fastcall, (int pUnit), 0xD3070) // Process active unit sounds with validation - iterates through unit sound list, validates sound effects against sound tables, finds matching sound IDs, and processes sound effects for units with active sound states, includes timeout validation and sound state management
FUNCPTR(D2CLIENT, ClearAllActiveUnitSounds, void __fastcall, (int pUnit), 0xD3120) // Clear all active unit sounds - iterates through unit sound list and clears all active sound effects, resets sound timers and states, used for cleanup during area transitions or when stopping all unit sounds simultaneously
FUNCPTR(D2CLIENT, HandleUnitAmbientSoundEvents, void __stdcall, (void), 0xD3170) // Handle unit ambient sound events - processes monster unit ambient sounds, validates sound data and manages sound ID 8 (skill sounds), handles ambient sound timing and plays appropriate unit sounds based on unit type and state
FUNCPTR(D2CLIENT, ProcessUnitSoundByType, void __stdcall, (int pUnit, uint soundId), 0xD3200) // Process unit sound by type with extensive validation - handles unit type validation, processes sound effects by ID (0x19-0x53), manages special sound cases with timing parameters, executes sound playback with volume and positioning calculations
FUNCPTR(D2CLIENT, ExecuteUnitSoundEffects, void __stdcall, (int pUnit), 0xD3630) // Execute unit sound effects with comprehensive processing - validates unit type, processes sound effects and item sounds, handles ambient sound playback based on unit state, manages sound timing and volume with player unit special handling
FUNCPTR(D2CLIENT, ProcessUnitSoundByState, void __stdcall, (int pUnit), 0xD37E0) // Process unit sound by state with advanced logic - handles object/monster sound processing, manages special unit types (0x1A), processes ambient sounds with distance calculations, validates sound timing and manages sound state transitions with comprehensive sound effect processing
FUNCPTR(D2CLIENT, HandleUnitSoundSequencing, void __stdcall, (int pUnit, int param2), 0xD3A30) // Handle unit sound sequencing with timing management - processes unit sound lists with ambient sound matching, manages sound timing delays and random variations, handles sound sequence interruption and processing with complex state validation and timing calculations
FUNCPTR(D2CLIENT, CalculateUnitSoundTiming, uint __stdcall, (int pUnit), 0xD3C00) // Calculate unit sound timing with dynamic parameters - computes sound timing based on unit type, sound state, and animation data, handles random timing variations and volume calculations, manages sound delay calculations with player unit special handling and animation synchronization
FUNCPTR(D2CLIENT, ProcessLevelBasedSoundEffects, void __stdcall, (void), 0xD3E20) // Process level-based sound effects - validates current player unit, checks area ID and quest availability, manages level-specific sound triggers, handles timing constraints and processes level-appropriate sound effects based on area and quest state
FUNCPTR(D2CLIENT, HandleNetworkUnitSoundEvents, void __fastcall, (int param1, uint param2, uint param3), 0xD3F20) // Handle network unit sound events with parameter processing - searches unit hash table by ID, processes various sound event types (0xA-0x5D), handles skill sounds, item interactions, and special unit sound cases with network synchronization and comprehensive event type handling


#define D2CLIENT_PlayerUnit *p_D2CLIENT_PlayerUnit
#define D2CLIENT_Ping *p_D2CLIENT_Ping
#define MouseX								(*p_D2CLIENT_MouseX)
#define MouseY								(*p_D2CLIENT_MouseY)
#define GetUnitStat(Unit, Stat)				(D2COMMON_GetUnitStat(Unit, Stat, 0))
#define GetUnitState(Unit, State)			(D2COMMON_GetUnitState(Unit, State))
#define GetUnitName(X)						(wchar_t*)GetUnitNameSTUB((DWORD)X)
#define pMe									(*p_D2CLIENT_PlayerUnit)
#define GetUnit(ID, Type)					(GetUnitSTUB(ID, Type))
#define GetUIVar(UI)						(GetUIVarSTUB(UI))
#define Ping								(*p_D2CLIENT_Ping)
#define Skip								(*p_D2CLIENT_Skip)
// Sound and Animation System Functions
FUNCPTR(D2CLIENT, HandleUnitSoundEvent, void, (), 0x23070) // Handles sound/animation event for units, iterates linked list and triggers if match found
FUNCPTR(D2CLIENT, TriggerUnitSoundEvents, void, (), 0x23120) // Triggers sound/animation events for all units in a linked list  
FUNCPTR(D2CLIENT, UpdateUnitAmbientSound, void, (), 0x23170) // Updates ambient sound for units based on type and state
FUNCPTR(D2CLIENT, HandleUnitEvent, void, (int unitPtr, uint eventType), 0x23200) // Handles unit event (sound/animation) based on eventType
FUNCPTR(D2CLIENT, ProcessUnitSoundEffects, void, (int eventType), 0x23630) // Processes sound effects and updates sound state for units
FUNCPTR(D2CLIENT, HandleUnitSoundState, void, (int unitPtr), 0x237E0) // Handles sound state and triggers sound events for units
FUNCPTR(D2CLIENT, UpdateUnitSoundAnimation, void, (int unitPtr, int eventType), 0x23A30) // Updates sound/animation state for units based on eventType
FUNCPTR(D2CLIENT, GetUnitSoundAnimationState, uint, (int unitPtr), 0x23C00) // Gets current sound/animation state for a unit
FUNCPTR(D2CLIENT, HandleGlobalUnitEvent, void, (), 0x23E20) // Handles global sound/animation event for all units
FUNCPTR(D2CLIENT, TriggerUnitEventByType, void __fastcall, (int unitPtr, uint eventType, uint eventParam), 0x23F20) // Triggers unit event by type and param, handles many event cases

// Unit System Functions  
FUNCPTR(D2CLIENT, HandleUnitStateChange, void __thiscall, (void *this, int eventType), 0x242B0) // Handles unit state changes with sound/animation processing
FUNCPTR(D2CLIENT, ProcessUnitSoundsByType, void, (uint soundType, int param2), 0x24490) // Processes unit sounds by type with parameter-based routing
FUNCPTR(D2CLIENT, GetUnitAnimationState, undefined4, (), 0x24680) // Complex animation state machine with multiple cases and random timing
FUNCPTR(D2CLIENT, HandleUnitEventDispatch, void, (), 0x246F0) // Dispatches unit events through function pointer table with bounds checking
FUNCPTR(D2CLIENT, UpdateUnitFlags, void __fastcall, (undefined4 param_1), 0x247A0) // Updates unit flags and animation state based on unit type and parameters
FUNCPTR(D2CLIENT, SetUnitParticleEffect, void __thiscall, (void *this, undefined1 param_1, undefined1 param_2, undefined1 param_3), 0x24920) // Sets particle effects for units with RGB parameters
FUNCPTR(D2CLIENT, CleanupUnitEffects, void, (), 0x24990) // Cleans up unit effects and particle systems
FUNCPTR(D2CLIENT, TriggerUnitSoundWithLookup, void, (int unitPtr), 0x24A70) // Triggers unit sound after table lookup and validation
FUNCPTR(D2CLIENT, ProcessUnitEventData, void, (uint *eventData), 0x24B90) // Processes unit event data with function dispatch and sound triggering
FUNCPTR(D2CLIENT, UpdateUnitAnimation, void, (int animationType), 0x25040) // Updates unit animation state with complex mode switching and positioning

// Animation and State Management Functions
FUNCPTR(D2CLIENT, UpdateUnitAnimationState, void, (), 0x251E0) // Updates unit animation state with mode transitions and timing
FUNCPTR(D2CLIENT, ProcessUnitEffects, undefined4, (), 0x25280) // Processes unit effects with sound and particle system integration
FUNCPTR(D2CLIENT, UpdateAnimationFrame, void, (), 0x25400) // Updates animation frame with mode-dependent logic and transitions
FUNCPTR(D2CLIENT, InitializeUnitAnimations, void __fastcall, (undefined4 param_1, void *param_2, undefined4 param_3, undefined4 param_4, undefined4 param_5), 0x25490) // Initializes unit animations with parameters and flag setup
FUNCPTR(D2CLIENT, ProcessUnitAnimations, void, (), 0x25660) // Processes unit animations with complex state transitions and monster spawning
FUNCPTR(D2CLIENT, HandleUnitModeChange, void __fastcall, (int *param_1), 0x259F0) // Handles unit mode changes with lighting effects and sound processing
FUNCPTR(D2CLIENT, UpdateUnitMode, void, (), 0x25B40) // Updates unit mode based on animation state and processing conditions
FUNCPTR(D2CLIENT, TriggerUnitSpecialEffects, void __fastcall, (int *param_1), 0x25B70) // Triggers special effects for specific unit types and modes
FUNCPTR(D2CLIENT, HandleUnitEventCallback, void __fastcall, (int param_1, int *param_2), 0x25CE0) // Handles unit event callbacks with parameter validation
FUNCPTR(D2CLIENT, CreateUnitEffectArray, void __fastcall, (int *param_1, undefined4 param_2), 0x25DC0) // Creates effect arrays for units with position-based calculations

// Effect and Particle System Functions  
FUNCPTR(D2CLIENT, CreateParticleEffectArray, void __fastcall, (int *param_1, undefined4 param_2), 0x25F10) // Creates particle effect arrays with position calculations and multiple patterns
FUNCPTR(D2CLIENT, CreateGridEffectPattern, void __fastcall, (int *param_1, undefined4 param_2), 0x26060) // Creates grid-based effect patterns with alternating positions
FUNCPTR(D2CLIENT, CheckUIClickRegion, undefined4, (), 0x26320) // Checks if mouse coordinates are within UI click regions with multiple area validation
FUNCPTR(D2CLIENT, InitializeUISystem, void, (), 0x26410) // Initializes UI system by clearing global UI state variables
FUNCPTR(D2CLIENT, GetUIElementIndex, int, (int param_1), 0x26460) // Gets UI element index by checking coordinates against UI element boundaries
FUNCPTR(D2CLIENT, InitializeColorPalette, void, (), 0x265E0) // Initializes color palette with RGBA values for UI rendering
FUNCPTR(D2CLIENT, HandleUIElementClick, void __fastcall, (undefined4 param_1), 0x266C0) // Handles UI element clicks with coordinate validation and unit selection
FUNCPTR(D2CLIENT, HandleUIButtonPress, void, (), 0x267B0) // Handles UI button press events with coordinate range checking
FUNCPTR(D2CLIENT, DrawUIElementWithColor, void, (undefined4 param_1), 0x26820) // Draws UI elements with color selection based on context
FUNCPTR(D2CLIENT, RenderUIElements, void, (), 0x26880) // Renders UI elements with conditional display logic and coordinate calculation

// UI System and Display Functions
FUNCPTR(D2CLIENT, RenderStatisticsDisplay, void, (), 0x26970) // Renders character statistics display with unicode string formatting and progress calculations
FUNCPTR(D2CLIENT, CalculateStatisticsValue, int, (), 0x26B20) // Calculates statistics values with smoothing and random distribution for display
FUNCPTR(D2CLIENT, CleanupUIResources, void, (), 0x26CD0) // Cleans up UI resources by releasing graphic assets and clearing memory pointers
FUNCPTR(D2CLIENT, InitializeHotkeyButtons, void, (), 0x270D0) // Initializes hotkey button UI elements at specific screen positions
FUNCPTR(D2CLIENT, InitializeActionButtons, void, (), 0x271C0) // Initializes action button UI elements with position calculations
FUNCPTR(D2CLIENT, SetupUILayout, void, (), 0x27290) // Sets up UI layout with different configurations based on game mode
FUNCPTR(D2CLIENT, RenderCharacterStats, void, (), 0x27590) // Renders character statistics with health/mana bars and unicode text formatting
FUNCPTR(D2CLIENT, HandleTownPortalAction, void, (), 0x277E0) // Handles town portal action with unit selection and area validation
FUNCPTR(D2CLIENT, RenderManaBar, void, (), 0x278B0) // Renders mana bar with color coding and percentage calculations
FUNCPTR(D2CLIENT, RenderHealthBar, void, (), 0x27A90) // Renders health bar with color-coded display and poisoned state detection
FUNCPTR(D2CLIENT, DisplayManaBar, VOID __fastcall, (VOID), 0x28680) // Renders player mana bar with color coding and percentage calculation

// Game UI Rendering System (0x29250-0x29920)
FUNCPTR(D2CLIENT, RenderMainGameUI, VOID __fastcall, (VOID), 0x29250) // Main game UI rendering function - coordinates multiple display elements
FUNCPTR(D2CLIENT, ValidateUnitMode, DWORD __fastcall, (int param1, int param2), 0x29920) // Validates unit game mode and state transitions

// Unit Collision and Movement System (0x29F30-0x2A460)
FUNCPTR(D2CLIENT, CheckUnitCanMove, DWORD __fastcall, (VOID), 0x29F30) // Checks if unit can move based on mode and collision
FUNCPTR(D2CLIENT, UpdateUnitPosition, VOID __fastcall, (DWORD param1), 0x2A040) // Updates unit position with collision flags
FUNCPTR(D2CLIENT, ProcessUnitMovement, VOID __fastcall, (int param1, DWORD param2, int param3), 0x2A460) // Processes unit movement with collision detection

// Skill System and Spell Effects (0x2BE30-0x2C820)
FUNCPTR(D2CLIENT, CreateSpellEffect, DWORD __fastcall, (int unitPtr, int skillId, DWORD param3), 0x2BE30) // Creates spell effect with data table validation
FUNCPTR(D2CLIENT, FormatSkillBonus, DWORD __thiscall, (VOID* this, Unicode* output), 0x2C7E0) // Formats skill bonus values for display

// Skill Description and UI System (0x2E350-0x2FD30)
FUNCPTR(D2CLIENT, GetSkillDamageValue, DWORD __fastcall, (int skillPtr, int param2), 0x2E350) // Calculates skill damage values from data tables
FUNCPTR(D2CLIENT, DisplaySkillDescription, VOID __fastcall, (int skillId, DWORD param2, int displayMode), 0x2FD30) // Complex skill description display with damage calculations

#define FPS									(*p_D2CLIENT_FPS)
#define AutoMapLayer						(*p_D2CLIENT_AutomapLayer)

#define _D2PTRS_END	p_D2CLIENT_bWeapSwitch