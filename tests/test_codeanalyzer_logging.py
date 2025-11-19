"""
Integration tests for logging in CodeAnalyzer.

Tests verify that:
- CodeAnalyzer logs initialization events
- Analysis operations are logged
- Errors and warnings are logged appropriately
- Framework detection is logged
"""
# pylint: disable=unused-argument,unused-variable,import-outside-toplevel
# Fixtures needed for test setup, variables for side effects, imports to isolate tests

import logging
from io import StringIO
from pathlib import Path
from unittest.mock import patch, Mock

import pytest


class TestCodeAnalyzerLogging:
    """Test that CodeAnalyzer uses logging correctly."""

    @pytest.fixture
    def log_capture(self):
        """Fixture to capture log messages."""
        # Create a string buffer
        log_buffer = StringIO()
        handler = logging.StreamHandler(log_buffer)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))

        # Add handler to root logger
        logger = logging.getLogger()
        logger.addHandler(handler)
        original_level = logger.level
        logger.setLevel(logging.DEBUG)

        yield log_buffer

        # Cleanup
        logger.removeHandler(handler)
        logger.setLevel(original_level)

    def test_initialization_logs_success(self, mock_env_with_api_key, mock_gemini_api, log_capture):
        """Test that successful initialization logs INFO messages."""
        with patch('codeaudit.PromptEngine'), patch('codeaudit.FrameworkDetector'):
            from codeaudit import CodeAnalyzer

            analyzer = CodeAnalyzer()

            logs = log_capture.getvalue()

            # Check for successful initialization logs
            assert "INFO" in logs
            assert "Gemini AI configured successfully" in logs
            assert "Prompt template system initialized successfully" in logs

    def test_initialization_logs_error_without_api_key(self, log_capture):
        """Test that missing API key logs ERROR."""
        with patch.dict('os.environ', {}, clear=True):
            with pytest.raises(SystemExit):
                from codeaudit import CodeAnalyzer
                analyzer = CodeAnalyzer()

        logs = log_capture.getvalue()
        assert "ERROR" in logs
        assert "GEMINI_API_KEY environment variable not found" in logs

    def test_initialization_logs_warning_on_prompt_system_failure(
        self, mock_env_with_api_key, mock_gemini_api, log_capture
    ):
        """Test that prompt system failure logs WARNING."""
        with patch('codeaudit.PromptEngine', side_effect=Exception("Template error")):
            with patch('codeaudit.FrameworkDetector'):
                from codeaudit import CodeAnalyzer

                analyzer = CodeAnalyzer()

                logs = log_capture.getvalue()
                assert "WARNING" in logs
                assert "Could not initialize prompt system" in logs
                assert "Falling back to basic prompts" in logs

    def test_analyze_file_logs_framework_detection(
        self, mock_env_with_api_key, mock_gemini_api, temp_test_file, log_capture
    ):
        """Test that framework detection is logged."""
        with patch('codeaudit.FrameworkDetector') as mock_detector_class:
            mock_detector = Mock()
            mock_detector.detect_frameworks.return_value = ['django', 'flask']
            mock_detector_class.return_value = mock_detector
            mock_detector_class.get_threat_models_for_frameworks.return_value = ['web', 'api']

            with patch('codeaudit.PromptEngine') as mock_engine:
                mock_engine_instance = Mock()
                mock_engine_instance.get_prompt.return_value = "test prompt"
                mock_engine.return_value = mock_engine_instance

                with patch('codeaudit.FewShotExamples') as mock_examples:
                    mock_examples.get_security_examples.return_value = []

                    from codeaudit import CodeAnalyzer

                    analyzer = CodeAnalyzer()
                    analyzer.analyze_code_file(temp_test_file)

                    logs = log_capture.getvalue()

                    # Check for framework detection logs (DEBUG level)
                    assert "Detected frameworks" in logs or "DEBUG" in logs

    def test_analyze_file_logs_success(
        self, mock_env_with_api_key, mock_gemini_api, temp_test_file, log_capture
    ):
        """Test that successful file analysis logs INFO."""
        with patch('codeaudit.PromptEngine'), patch('codeaudit.FrameworkDetector'):
            from codeaudit import CodeAnalyzer

            analyzer = CodeAnalyzer()
            result = analyzer.analyze_code_file(temp_test_file)

            logs = log_capture.getvalue()

            # Should log successful analysis
            assert "INFO" in logs
            assert "Successfully analyzed" in logs or "issues found" in logs

    def test_analyze_file_logs_error_on_json_decode_failure(
        self, mock_env_with_api_key, temp_test_file, log_capture
    ):
        """Test that JSON decode errors are logged."""
        with patch('google.generativeai.configure'):
            with patch('google.generativeai.GenerativeModel') as mock_model:
                # Setup mock to return invalid JSON
                mock_response = Mock()
                mock_response.text = "Not valid JSON!"

                mock_instance = Mock()
                mock_instance.generate_content.return_value = mock_response
                mock_model.return_value = mock_instance

                with patch('codeaudit.PromptEngine'), patch('codeaudit.FrameworkDetector'):
                    from codeaudit import CodeAnalyzer

                    analyzer = CodeAnalyzer()
                    result = analyzer.analyze_code_file(temp_test_file)

                    logs = log_capture.getvalue()

                    # Should log JSON decode error
                    assert "ERROR" in logs
                    assert "JSON decode error" in logs
                    assert result.get('error') is not None

    def test_save_results_logs_success(
        self, mock_env_with_api_key, mock_gemini_api, tmp_path, log_capture
    ):
        """Test that saving results logs INFO."""
        with patch('codeaudit.PromptEngine'), patch('codeaudit.FrameworkDetector'):
            from codeaudit import CodeAnalyzer

            analyzer = CodeAnalyzer()
            results = [{'file': 'test.py', 'issues': []}]
            output_file = tmp_path / "results.json"

            analyzer.save_results_json(results, output_file)

            logs = log_capture.getvalue()
            assert "INFO" in logs
            assert "Results saved to" in logs

    def test_save_results_logs_error_on_failure(
        self, mock_env_with_api_key, mock_gemini_api, log_capture
    ):
        """Test that save failures log ERROR."""
        with patch('codeaudit.PromptEngine'), patch('codeaudit.FrameworkDetector'):
            from codeaudit import CodeAnalyzer

            analyzer = CodeAnalyzer()
            results = [{'file': 'test.py', 'issues': []}]

            # Try to save to invalid path
            invalid_path = Path("/invalid/path/that/does/not/exist/results.json")
            analyzer.save_results_json(results, invalid_path)

            logs = log_capture.getvalue()
            assert "ERROR" in logs
            assert "Error saving results" in logs


class TestMainFunctionLogging:
    """Test that main() function uses logging correctly."""

    @pytest.fixture
    def log_capture(self):
        """Fixture to capture log messages."""
        log_buffer = StringIO()
        handler = logging.StreamHandler(log_buffer)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter('%(levelname)s:%(message)s'))

        logger = logging.getLogger()
        logger.addHandler(handler)
        original_level = logger.level
        logger.setLevel(logging.DEBUG)

        yield log_buffer

        logger.removeHandler(handler)
        logger.setLevel(original_level)

    def test_main_logs_startup(
        self, mock_env_with_api_key, mock_gemini_api, log_capture
    ):
        """Test that main() logs startup information."""
        with patch('codeaudit.PromptEngine'), patch('codeaudit.FrameworkDetector'):
            with patch('sys.argv', ['codeaudit.py', 'nonexistent_path']):
                from codeaudit import main

                # main() will return early when no files found
                main()

                logs = log_capture.getvalue()
                assert "Starting CodeAudit analysis" in logs
                assert "Target path:" in logs

    def test_main_logs_no_files_warning(
        self, mock_env_with_api_key, mock_gemini_api, tmp_path, log_capture
    ):
        """Test that main() logs warning when no files found."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        with patch('codeaudit.PromptEngine'), patch('codeaudit.FrameworkDetector'):
            with patch('sys.argv', ['codeaudit.py', str(empty_dir)]):
                from codeaudit import main

                main()

                logs = log_capture.getvalue()
                assert "WARNING" in logs
                assert "No supported code files found" in logs
