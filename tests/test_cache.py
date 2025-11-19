"""
Tests for cache.py module.
"""
# pylint: disable=unused-argument,import-outside-toplevel
# Fixtures needed for test setup, imports isolated to test specific functionality

import json
import time

from cache import ResultCache


class TestResultCache:
    """Test ResultCache class."""

    def test_initialization_default_directory(self):
        """Test that ResultCache initializes with default cache directory."""
        cache = ResultCache()
        assert cache.cache_dir is not None
        assert cache.cache_dir.exists()
        assert cache.cache_dir.name == "codeaudit"

    def test_initialization_custom_directory(self, tmp_path):
        """Test that ResultCache initializes with custom directory."""
        custom_cache_dir = tmp_path / "custom_cache"
        cache = ResultCache(cache_dir=custom_cache_dir)

        assert cache.cache_dir == custom_cache_dir
        assert cache.cache_dir.exists()

    def test_compute_file_hash(self, tmp_path):
        """Test SHA-256 file hashing."""
        cache = ResultCache(cache_dir=tmp_path)

        # Create a test file
        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): pass")

        # Compute hash
        file_hash = cache._compute_file_hash(test_file)

        # Hash should be 64 character hex string (SHA-256)
        assert isinstance(file_hash, str)
        assert len(file_hash) == 64
        assert all(c in '0123456789abcdef' for c in file_hash)

    def test_compute_file_hash_consistency(self, tmp_path):
        """Test that same file produces same hash."""
        cache = ResultCache(cache_dir=tmp_path)

        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): pass")

        hash1 = cache._compute_file_hash(test_file)
        hash2 = cache._compute_file_hash(test_file)

        assert hash1 == hash2

    def test_compute_file_hash_different_content(self, tmp_path):
        """Test that different content produces different hash."""
        cache = ResultCache(cache_dir=tmp_path)

        test_file = tmp_path / "test.py"

        test_file.write_text("def hello(): pass")
        hash1 = cache._compute_file_hash(test_file)

        test_file.write_text("def goodbye(): pass")
        hash2 = cache._compute_file_hash(test_file)

        assert hash1 != hash2

    def test_cache_miss_no_cache_file(self, tmp_path):
        """Test cache miss when no cache file exists."""
        cache = ResultCache(cache_dir=tmp_path / "cache")

        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): pass")

        result = cache.get(test_file)
        assert result is None

    def test_cache_set_and_get(self, tmp_path):
        """Test storing and retrieving cache."""
        cache = ResultCache(cache_dir=tmp_path / "cache")

        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): pass")

        # Store result
        analysis_result = {
            'file': str(test_file),
            'issues': [],
            'summary': {'total_issues': 0}
        }
        cache.set(test_file, analysis_result)

        # Retrieve result
        cached_result = cache.get(test_file)

        assert cached_result is not None
        assert cached_result == analysis_result

    def test_cache_invalidation_on_file_modification(self, tmp_path):
        """Test that cache is invalidated when file is modified."""
        cache = ResultCache(cache_dir=tmp_path / "cache")

        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): pass")

        # Cache initial result
        initial_result = {'file': str(test_file), 'issues': []}
        cache.set(test_file, initial_result)

        # Verify cache hit
        assert cache.get(test_file) == initial_result

        # Modify file (ensure different mtime)
        time.sleep(0.01)  # Ensure mtime changes
        test_file.write_text("def goodbye(): pass")

        # Cache should be invalidated
        assert cache.get(test_file) is None

    def test_cache_stores_metadata(self, tmp_path):
        """Test that cache stores file metadata."""
        cache = ResultCache(cache_dir=tmp_path / "cache")

        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): pass")

        analysis_result = {'file': str(test_file), 'issues': []}
        cache.set(test_file, analysis_result)

        # Read cache file directly to verify metadata
        file_hash = cache._compute_file_hash(test_file)
        cache_path = cache._get_cache_path(file_hash)

        with open(cache_path, 'r', encoding='utf-8') as f:
            cached_data = json.load(f)

        assert 'file_path' in cached_data
        assert 'file_hash' in cached_data
        assert 'mtime' in cached_data
        assert 'timestamp' in cached_data
        assert 'result' in cached_data
        assert cached_data['result'] == analysis_result

    def test_clear_cache(self, tmp_path):
        """Test clearing all cache entries."""
        cache = ResultCache(cache_dir=tmp_path / "cache")

        # Create multiple cache entries
        for i in range(3):
            test_file = tmp_path / f"test{i}.py"
            test_file.write_text(f"def func{i}(): pass")
            cache.set(test_file, {'file': str(test_file), 'issues': []})

        # Verify caches exist
        assert len(list(cache.cache_dir.glob("*.json"))) == 3

        # Clear cache
        count = cache.clear()

        # Verify all caches cleared
        assert count == 3
        assert len(list(cache.cache_dir.glob("*.json"))) == 0

    def test_get_stats(self, tmp_path):
        """Test getting cache statistics."""
        cache = ResultCache(cache_dir=tmp_path / "cache")

        # Initially empty
        stats = cache.get_stats()
        assert stats['entry_count'] == 0
        assert stats['total_size_bytes'] == 0

        # Add some cache entries
        for i in range(2):
            test_file = tmp_path / f"test{i}.py"
            test_file.write_text(f"def func{i}(): pass")
            cache.set(test_file, {'file': str(test_file), 'issues': []})

        # Check stats
        stats = cache.get_stats()
        assert stats['entry_count'] == 2
        assert stats['total_size_bytes'] > 0
        assert stats['total_size_mb'] >= 0  # Can be 0.0 for small files
        assert 'cache_dir' in stats

    def test_cache_handles_read_errors(self, tmp_path):
        """Test that cache gracefully handles read errors."""
        cache = ResultCache(cache_dir=tmp_path / "cache")

        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): pass")

        # Create invalid cache file
        file_hash = cache._compute_file_hash(test_file)
        cache_path = cache._get_cache_path(file_hash)
        cache_path.write_text("invalid json")

        # Should return None on read error
        result = cache.get(test_file)
        assert result is None

    def test_cache_handles_write_errors(self, tmp_path):
        """Test that cache gracefully handles write errors."""
        # Create cache with invalid directory
        invalid_dir = tmp_path / "nonexistent" / "nested" / "cache"
        cache = ResultCache(cache_dir=invalid_dir)

        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): pass")

        # Writing to invalid directory should not crash
        # (directory gets created in __init__)
        cache.set(test_file, {'file': str(test_file), 'issues': []})

        # Verify cache was created
        assert invalid_dir.exists()


class TestCacheIntegration:
    """Integration tests for cache with CodeAnalyzer."""

    def test_cache_reduces_analysis_calls(self, tmp_path, mock_env_with_api_key, mock_gemini_api):
        """Test that cache prevents redundant AI analysis calls."""
        from unittest.mock import Mock, patch
        from codeaudit import CodeAnalyzer

        # Create analyzer with cache
        with patch('codeaudit.PromptEngine'):
            with patch('codeaudit.FrameworkDetector'):
                analyzer = CodeAnalyzer(enable_cache=True)
                analyzer.cache = ResultCache(cache_dir=tmp_path / "cache")

        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): pass")

        # Mock AI response
        mock_response = Mock()
        mock_response.text = json.dumps({
            'issues': [],
            'summary': {'total_issues': 0}
        })

        analyzer.model.generate_content = Mock(return_value=mock_response)

        # First analysis - should call AI
        result1 = analyzer.analyze_code_file(test_file)
        assert analyzer.model.generate_content.call_count == 1
        assert 'issues' in result1

        # Second analysis - should use cache
        result2 = analyzer.analyze_code_file(test_file)
        assert analyzer.model.generate_content.call_count == 1  # Still 1, not 2
        assert result1 == result2

    def test_cache_disabled_when_flag_false(self, mock_env_with_api_key, mock_gemini_api):
        """Test that cache is disabled when enable_cache=False."""
        from unittest.mock import patch
        from codeaudit import CodeAnalyzer

        with patch('codeaudit.PromptEngine'):
            with patch('codeaudit.FrameworkDetector'):
                analyzer = CodeAnalyzer(enable_cache=False)

        assert analyzer.cache is None
