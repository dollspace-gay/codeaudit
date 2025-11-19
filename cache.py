"""
Result caching system for code analysis.

Caches analysis results using SHA-256 file hashing to avoid re-analyzing
unchanged files. Cache is stored in ~/.cache/codeaudit/ directory.
"""

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class ResultCache:
    """Cache for code analysis results.

    Stores analysis results keyed by file hash (SHA-256) with metadata
    including file modification time for cache invalidation.
    """

    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize result cache.

        Args:
            cache_dir: Optional custom cache directory. Defaults to ~/.cache/codeaudit/
        """
        if cache_dir is None:
            cache_dir = Path.home() / ".cache" / "codeaudit"

        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        logger.debug("Cache directory: %s", self.cache_dir)

    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA-256 hash of file contents.

        Args:
            file_path: Path to file to hash

        Returns:
            SHA-256 hash as hexadecimal string

        Raises:
            IOError: If file cannot be read
        """
        sha256 = hashlib.sha256()

        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)

        return sha256.hexdigest()

    def _get_cache_path(self, file_hash: str) -> Path:
        """Get cache file path for given file hash.

        Args:
            file_hash: SHA-256 hash of file

        Returns:
            Path to cache file
        """
        return self.cache_dir / f"{file_hash}.json"

    def get(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Retrieve cached analysis result if valid.

        Validates cache by checking file modification time. Returns None
        if cache doesn't exist or is invalidated.

        Args:
            file_path: Path to file being analyzed

        Returns:
            Cached analysis result or None if cache miss/invalid
        """
        try:
            # Compute current file hash
            file_hash = self._compute_file_hash(file_path)
            cache_path = self._get_cache_path(file_hash)

            # Check if cache exists
            if not cache_path.exists():
                logger.debug("Cache miss (no cache): %s", file_path.name)
                return None

            # Read cached data
            with open(cache_path, 'r', encoding='utf-8') as f:
                cached_data = json.load(f)

            # Validate cache: check file modification time
            cached_mtime = cached_data.get('mtime')
            current_mtime = file_path.stat().st_mtime

            if cached_mtime != current_mtime:
                logger.debug("Cache invalidated (mtime changed): %s", file_path.name)
                return None

            logger.info("Cache hit: %s", file_path.name)
            return cached_data.get('result')

        except (IOError, json.JSONDecodeError, KeyError) as e:
            logger.warning("Cache read error for %s: %s", file_path.name, e)
            return None

    def set(self, file_path: Path, result: Dict[str, Any]) -> None:
        """Store analysis result in cache.

        Stores result with file hash, modification time, and timestamp.

        Args:
            file_path: Path to analyzed file
            result: Analysis result dictionary to cache
        """
        try:
            # Compute file hash
            file_hash = self._compute_file_hash(file_path)
            cache_path = self._get_cache_path(file_hash)

            # Prepare cached data
            cached_data = {
                'file_path': str(file_path),
                'file_hash': file_hash,
                'mtime': file_path.stat().st_mtime,
                'timestamp': datetime.now().isoformat(),
                'result': result
            }

            # Write to cache
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cached_data, f, indent=2)

            logger.debug("Cached result for: %s (hash: %s)", file_path.name, file_hash[:8])

        except (IOError, OSError) as e:
            logger.warning("Cache write error for %s: %s", file_path.name, e)

    def clear(self) -> int:
        """Clear all cached results.

        Returns:
            Number of cache entries removed
        """
        count = 0
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
                count += 1

            logger.info("Cleared %d cached result%s", count, '' if count == 1 else 's')

        except (IOError, OSError) as e:
            logger.error("Error clearing cache: %s", e)

        return count

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics (size, entry count, etc.)
        """
        try:
            cache_files = list(self.cache_dir.glob("*.json"))
            total_size = sum(f.stat().st_size for f in cache_files)

            return {
                'cache_dir': str(self.cache_dir),
                'entry_count': len(cache_files),
                'total_size_bytes': total_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2)
            }

        except (IOError, OSError) as e:
            logger.error("Error getting cache stats: %s", e)
            return {
                'cache_dir': str(self.cache_dir),
                'entry_count': 0,
                'total_size_bytes': 0,
                'total_size_mb': 0.0,
                'error': str(e)
            }
