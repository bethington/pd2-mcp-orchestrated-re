"""
Ghidra Analysis Cache Manager
Provides persistent storage and retrieval of Ghidra analysis results using Redis and Dgraph
"""

import asyncio
import json
import hashlib
import os
import aioredis
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import structlog

logger = structlog.get_logger()

class GhidraAnalysisCache:
    """
    Manages persistent storage and retrieval of Ghidra analysis results
    """
    
    def __init__(self, redis_url: str = "redis://redis:6379", 
                 dgraph_url: str = "http://dgraph-alpha:8080"):
        """
        Initialize cache manager
        
        Args:
            redis_url: Redis connection URL for fast caching
            dgraph_url: Dgraph URL for knowledge graph storage
        """
        self.redis_url = redis_url
        self.dgraph_url = dgraph_url
        self.redis = None
        self.session = None
        
        # Core binaries that should have persistent projects
        self.core_binaries = [
            "D2Client.dll", "D2Common.dll", "D2Game.dll", 
            "Game.exe", "D2Win.dll", "D2Lang.dll", "D2Net.dll",
            "D2Launch.dll", "D2CMP.dll", "Fog.dll", "Storm.dll"
        ]
        
        # Cache expiration settings
        self.cache_ttl = 86400 * 7  # 7 days for Redis
        self.hash_ttl = 86400 * 30  # 30 days for file hashes
    
    async def initialize(self):
        """Initialize Redis and HTTP connections"""
        try:
            self.redis = aioredis.from_url(self.redis_url)
            await self.redis.ping()
            logger.info("Redis connection established", url=self.redis_url)
            
            self.session = aiohttp.ClientSession()
            logger.info("Cache manager initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize cache manager", error=str(e))
            raise
    
    async def close(self):
        """Clean up connections"""
        if self.redis:
            await self.redis.close()
        if self.session:
            await self.session.close()
    
    def _get_file_hash(self, binary_path: str) -> str:
        """
        Generate unique hash for file based on path, size, and modification time
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            SHA256 hash string
        """
        try:
            if not os.path.exists(binary_path):
                # For container paths, use path and current time as fallback
                hash_input = f"{binary_path}:{datetime.now().isoformat()}"
                return hashlib.sha256(hash_input.encode()).hexdigest()
            
            stat = os.stat(binary_path)
            hash_input = f"{binary_path}:{stat.st_size}:{stat.st_mtime}"
            return hashlib.sha256(hash_input.encode()).hexdigest()
            
        except Exception as e:
            logger.warning("Failed to get file hash", binary_path=binary_path, error=str(e))
            # Fallback to path-only hash
            return hashlib.sha256(binary_path.encode()).hexdigest()
    
    def should_preserve_project(self, binary_path: str) -> bool:
        """
        Check if this binary should have a persistent Ghidra project
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            True if project should be preserved
        """
        binary_name = os.path.basename(binary_path).lower()
        return any(core.lower() in binary_name for core in self.core_binaries)
    
    def get_persistent_project_name(self, binary_path: str) -> str:
        """
        Generate consistent project name for persistent storage
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Consistent project name
        """
        binary_name = os.path.basename(binary_path)
        file_hash = self._get_file_hash(binary_path)[:8]
        return f"persistent_{binary_name}_{file_hash}"
    
    async def needs_reanalysis(self, binary_path: str) -> bool:
        """
        Check if file has changed since last analysis
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            True if file needs reanalysis
        """
        try:
            current_hash = self._get_file_hash(binary_path)
            stored_hash_key = f"ghidra_hash:{binary_path}"
            stored_hash = await self.redis.get(stored_hash_key)
            
            if stored_hash is None:
                logger.info("No previous analysis found", binary_path=binary_path)
                return True
            
            needs_update = current_hash != stored_hash.decode()
            if needs_update:
                logger.info("File changed since last analysis", 
                          binary_path=binary_path,
                          old_hash=stored_hash.decode()[:8],
                          new_hash=current_hash[:8])
            
            return needs_update
            
        except Exception as e:
            logger.error("Error checking file hash", binary_path=binary_path, error=str(e))
            return True  # Err on side of reanalysis
    
    async def store_analysis_results(self, binary_path: str, analysis_data: Dict[str, Any]):
        """
        Store analysis results in Redis and Dgraph
        
        Args:
            binary_path: Path to the analyzed binary
            analysis_data: Complete analysis results
        """
        try:
            # Add metadata to analysis data
            enhanced_data = {
                **analysis_data,
                "binary_path": binary_path,
                "cache_timestamp": datetime.now().isoformat(),
                "file_hash": self._get_file_hash(binary_path),
                "binary_name": os.path.basename(binary_path)
            }
            
            # Store in Redis for fast access
            file_hash = self._get_file_hash(binary_path)
            redis_key = f"ghidra_analysis:{file_hash}"
            
            await self.redis.setex(
                redis_key, 
                self.cache_ttl,
                json.dumps(enhanced_data, default=str)
            )
            
            # Store file hash for change detection
            hash_key = f"ghidra_hash:{binary_path}"
            await self.redis.setex(hash_key, self.hash_ttl, file_hash)
            
            logger.info("Analysis results cached", 
                       binary_path=binary_path,
                       functions_count=len(enhanced_data.get("functions", [])),
                       cache_key=redis_key)
            
            # Store in Dgraph for knowledge graph (async, non-blocking)
            asyncio.create_task(self._store_in_dgraph(binary_path, enhanced_data))
            
        except Exception as e:
            logger.error("Failed to store analysis results", 
                        binary_path=binary_path, error=str(e))
    
    async def get_cached_analysis(self, binary_path: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached analysis results
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Cached analysis data or None if not found
        """
        try:
            file_hash = self._get_file_hash(binary_path)
            redis_key = f"ghidra_analysis:{file_hash}"
            
            cached_data = await self.redis.get(redis_key)
            if cached_data:
                analysis_data = json.loads(cached_data)
                logger.info("Retrieved cached analysis", 
                           binary_path=binary_path,
                           functions_count=len(analysis_data.get("functions", [])),
                           cache_age=analysis_data.get("cache_timestamp"))
                return analysis_data
            
            logger.info("No cached analysis found", binary_path=binary_path)
            return None
            
        except Exception as e:
            logger.error("Failed to retrieve cached analysis", 
                        binary_path=binary_path, error=str(e))
            return None
    
    async def _store_in_dgraph(self, binary_path: str, analysis_data: Dict[str, Any]):
        """
        Store analysis results in Dgraph knowledge graph
        
        Args:
            binary_path: Path to the analyzed binary
            analysis_data: Analysis results to store
        """
        try:
            # Create knowledge graph mutation
            binary_name = os.path.basename(binary_path)
            
            # Build graph structure
            mutations = []
            
            # Binary node
            binary_uid = f"binary_{hashlib.md5(binary_path.encode()).hexdigest()[:8]}"
            mutations.append({
                "uid": f"_:{binary_uid}",
                "dgraph.type": "Binary",
                "name": binary_name,
                "path": binary_path,
                "analysis_timestamp": analysis_data.get("cache_timestamp"),
                "file_hash": analysis_data.get("file_hash"),
                "total_functions": len(analysis_data.get("functions", []))
            })
            
            # Function nodes and relationships
            functions = analysis_data.get("functions", [])
            for i, func in enumerate(functions[:100]):  # Limit to prevent oversized mutations
                func_uid = f"func_{binary_uid}_{i}"
                mutations.append({
                    "uid": f"_:{func_uid}",
                    "dgraph.type": "Function",
                    "name": func.get("name", ""),
                    "address": func.get("address", ""),
                    "signature": func.get("signature", ""),
                    "is_export": func.get("is_export", False),
                    "binary": {"uid": f"_:{binary_uid}"}
                })
            
            # Send mutation to Dgraph
            mutation = {
                "set": mutations
            }
            
            async with self.session.post(
                f"{self.dgraph_url}/mutate",
                json=mutation,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status == 200:
                    logger.info("Analysis stored in Dgraph", 
                               binary_path=binary_path,
                               functions_stored=len(mutations)-1)
                else:
                    logger.warning("Failed to store in Dgraph", 
                                 status=response.status,
                                 binary_path=binary_path)
                    
        except Exception as e:
            logger.error("Error storing in Dgraph", 
                        binary_path=binary_path, error=str(e))
    
    async def list_cached_analyses(self) -> Dict[str, Any]:
        """
        List all cached analysis results
        
        Returns:
            Dictionary with cached analyses information
        """
        try:
            pattern = "ghidra_analysis:*"
            keys = []
            
            # Scan for keys (better than KEYS for large datasets)
            cursor = 0
            while True:
                cursor, batch_keys = await self.redis.scan(cursor, match=pattern, count=100)
                keys.extend(batch_keys)
                if cursor == 0:
                    break
            
            analyses = []
            for key in keys:
                try:
                    data_raw = await self.redis.get(key)
                    if data_raw:
                        data = json.loads(data_raw)
                        analyses.append({
                            "binary_path": data.get("binary_path", "Unknown"),
                            "binary_name": data.get("binary_name", "Unknown"),
                            "analysis_date": data.get("cache_timestamp", "Unknown"),
                            "functions_count": len(data.get("functions", [])),
                            "file_hash": data.get("file_hash", "Unknown")[:8],
                            "cache_key": key.decode() if isinstance(key, bytes) else key
                        })
                except Exception as e:
                    logger.warning("Error processing cache key", key=key, error=str(e))
                    continue
            
            # Sort by analysis date (most recent first)
            analyses.sort(key=lambda x: x.get("analysis_date", ""), reverse=True)
            
            return {
                "total_cached": len(analyses),
                "cached_analyses": analyses
            }
            
        except Exception as e:
            logger.error("Failed to list cached analyses", error=str(e))
            return {"error": str(e)}
    
    async def clear_analysis_cache(self, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Clear cached analysis results
        
        Args:
            binary_path: Specific file to clear, or None for all
            
        Returns:
            Results of the clear operation
        """
        try:
            if binary_path:
                # Clear specific file
                file_hash = self._get_file_hash(binary_path)
                analysis_key = f"ghidra_analysis:{file_hash}"
                hash_key = f"ghidra_hash:{binary_path}"
                
                deleted_count = 0
                deleted_count += await self.redis.delete(analysis_key)
                deleted_count += await self.redis.delete(hash_key)
                
                logger.info("Cleared specific analysis cache", 
                           binary_path=binary_path, deleted_keys=deleted_count)
                
                return {
                    "success": True,
                    "binary_path": binary_path,
                    "deleted_keys": deleted_count
                }
            else:
                # Clear all cached analyses
                analysis_keys = []
                hash_keys = []
                
                # Get analysis keys
                cursor = 0
                while True:
                    cursor, batch_keys = await self.redis.scan(
                        cursor, match="ghidra_analysis:*", count=100)
                    analysis_keys.extend(batch_keys)
                    if cursor == 0:
                        break
                
                # Get hash keys
                cursor = 0
                while True:
                    cursor, batch_keys = await self.redis.scan(
                        cursor, match="ghidra_hash:*", count=100)
                    hash_keys.extend(batch_keys)
                    if cursor == 0:
                        break
                
                # Delete all keys
                total_deleted = 0
                if analysis_keys:
                    total_deleted += await self.redis.delete(*analysis_keys)
                if hash_keys:
                    total_deleted += await self.redis.delete(*hash_keys)
                
                logger.info("Cleared all analysis cache", 
                           deleted_keys=total_deleted,
                           analysis_keys=len(analysis_keys),
                           hash_keys=len(hash_keys))
                
                return {
                    "success": True,
                    "deleted_keys": total_deleted,
                    "analysis_entries": len(analysis_keys),
                    "hash_entries": len(hash_keys)
                }
                
        except Exception as e:
            logger.error("Failed to clear analysis cache", error=str(e))
            return {"error": str(e)}
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics and health information
        
        Returns:
            Cache statistics
        """
        try:
            # Redis info
            redis_info = await self.redis.info()
            
            # Count cached items
            analysis_count = 0
            cursor = 0
            while True:
                cursor, keys = await self.redis.scan(cursor, match="ghidra_analysis:*", count=100)
                analysis_count += len(keys)
                if cursor == 0:
                    break
            
            hash_count = 0
            cursor = 0
            while True:
                cursor, keys = await self.redis.scan(cursor, match="ghidra_hash:*", count=100)
                hash_count += len(keys)
                if cursor == 0:
                    break
            
            return {
                "redis_connected": True,
                "redis_version": redis_info.get("redis_version", "Unknown"),
                "total_memory": redis_info.get("used_memory_human", "Unknown"),
                "cached_analyses": analysis_count,
                "file_hashes": hash_count,
                "cache_ttl_days": self.cache_ttl // 86400,
                "hash_ttl_days": self.hash_ttl // 86400
            }
            
        except Exception as e:
            logger.error("Failed to get cache stats", error=str(e))
            return {"error": str(e)}