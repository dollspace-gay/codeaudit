"""
Tests for logging configuration and functionality.

Tests verify that:
- Logging is configured correctly
- Log levels are respected
- Log messages are formatted properly
- Environment variables control log level
"""
# pylint: disable=import-outside-toplevel  # Imports isolated to test module loading

import logging
import os
from io import StringIO
from unittest.mock import patch

import pytest


class TestLoggingSetup:
    """Test logging configuration and setup."""

    def test_setup_logging_default_level(self):
        """Test that default log level is INFO."""
        # Import here to avoid circular imports
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

        # Clear any existing handlers
        logging.root.handlers = []

        with patch.dict(os.environ, {}, clear=True):
            from codeaudit import setup_logging
            logger = setup_logging()

            assert logging.INFO in (logger.level, logging.root.level)

    def test_setup_logging_custom_level_debug(self):
        """Test that LOG_LEVEL environment variable sets DEBUG level."""
        logging.root.handlers = []

        with patch.dict(os.environ, {'LOG_LEVEL': 'DEBUG'}):
            from codeaudit import setup_logging
            logger = setup_logging()

            # Check that either logger or root has DEBUG level
            assert logging.DEBUG in (logger.level, logging.root.level)

    def test_setup_logging_custom_level_warning(self):
        """Test that LOG_LEVEL environment variable sets WARNING level."""
        logging.root.handlers = []

        with patch.dict(os.environ, {'LOG_LEVEL': 'WARNING'}):
            from codeaudit import setup_logging
            logger = setup_logging()

            assert logging.WARNING in (logger.level, logging.root.level)

    def test_setup_logging_custom_level_error(self):
        """Test that LOG_LEVEL environment variable sets ERROR level."""
        logging.root.handlers = []

        with patch.dict(os.environ, {'LOG_LEVEL': 'ERROR'}):
            from codeaudit import setup_logging
            logger = setup_logging()

            assert logging.ERROR in (logger.level, logging.root.level)

    def test_setup_logging_invalid_level_defaults_to_info(self):
        """Test that invalid LOG_LEVEL defaults to INFO."""
        logging.root.handlers = []

        with patch.dict(os.environ, {'LOG_LEVEL': 'INVALID_LEVEL'}):
            from codeaudit import setup_logging
            logger = setup_logging()

            # Should default to INFO for invalid level
            assert logging.INFO in (logger.level, logging.root.level)

    def test_setup_logging_case_insensitive(self):
        """Test that LOG_LEVEL is case insensitive."""
        logging.root.handlers = []

        with patch.dict(os.environ, {'LOG_LEVEL': 'debug'}):
            from codeaudit import setup_logging
            logger = setup_logging()

            assert logging.DEBUG in (logger.level, logging.root.level)


class TestLoggingMessages:
    """Test that log messages are emitted correctly."""

    @pytest.fixture
    def captured_logs(self):
        """Fixture to capture log output."""
        # Create a string buffer to capture logs
        log_buffer = StringIO()
        handler = logging.StreamHandler(log_buffer)
        handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))

        # Get the logger and add handler
        logger = logging.getLogger('test_logger')
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        yield logger, log_buffer

        # Cleanup
        logger.removeHandler(handler)

    def test_debug_message(self, captured_logs):
        """Test that DEBUG messages are logged."""
        logger, log_buffer = captured_logs

        logger.debug("Test debug message")

        output = log_buffer.getvalue()
        assert "DEBUG" in output
        assert "Test debug message" in output

    def test_info_message(self, captured_logs):
        """Test that INFO messages are logged."""
        logger, log_buffer = captured_logs

        logger.info("Test info message")

        output = log_buffer.getvalue()
        assert "INFO" in output
        assert "Test info message" in output

    def test_warning_message(self, captured_logs):
        """Test that WARNING messages are logged."""
        logger, log_buffer = captured_logs

        logger.warning("Test warning message")

        output = log_buffer.getvalue()
        assert "WARNING" in output
        assert "Test warning message" in output

    def test_error_message(self, captured_logs):
        """Test that ERROR messages are logged."""
        logger, log_buffer = captured_logs

        logger.error("Test error message")

        output = log_buffer.getvalue()
        assert "ERROR" in output
        assert "Test error message" in output

    def test_critical_message(self, captured_logs):
        """Test that CRITICAL messages are logged."""
        logger, log_buffer = captured_logs

        logger.critical("Test critical message")

        output = log_buffer.getvalue()
        assert "CRITICAL" in output
        assert "Test critical message" in output

    def test_log_level_filtering(self):
        """Test that log level filtering works correctly."""
        log_buffer = StringIO()
        handler = logging.StreamHandler(log_buffer)
        handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))

        logger = logging.getLogger('test_filter_logger')
        logger.addHandler(handler)
        logger.setLevel(logging.WARNING)  # Only WARNING and above

        logger.debug("Should not appear")
        logger.info("Should not appear")
        logger.warning("Should appear")
        logger.error("Should appear")

        output = log_buffer.getvalue()

        assert "Should not appear" not in output
        assert "Should appear" in output
        assert output.count("Should appear") == 2

        logger.removeHandler(handler)


class TestLoggingFormat:
    """Test log message formatting."""

    def test_log_format_includes_timestamp(self):
        """Test that log format includes timestamp."""
        log_buffer = StringIO()
        handler = logging.StreamHandler(log_buffer)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))

        logger = logging.getLogger('test_format_logger')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        logger.info("Test message")

        output = log_buffer.getvalue()

        # Check format components
        assert "INFO" in output
        assert "Test message" in output
        assert "test_format_logger" in output
        # Check for timestamp pattern (YYYY-MM-DD HH:MM:SS)
        import re
        assert re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', output)

        logger.removeHandler(handler)

    def test_log_format_string_interpolation(self):
        """Test that format string interpolation works."""
        log_buffer = StringIO()
        handler = logging.StreamHandler(log_buffer)
        handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))

        logger = logging.getLogger('test_interpolation_logger')
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        # Test format string interpolation
        count = 42
        filename = "test.py"
        logger.info("Processing file %s with %d issues", filename, count)

        output = log_buffer.getvalue()
        assert "Processing file test.py with 42 issues" in output

        logger.removeHandler(handler)


class TestLoggingIntegration:
    """Integration tests for logging in the application."""

    def test_logger_returns_correct_instance(self):
        """Test that setup_logging returns a logger instance."""
        logging.root.handlers = []

        from codeaudit import setup_logging
        logger = setup_logging()

        assert isinstance(logger, logging.Logger)
        assert logger.name == 'codeaudit'  # Module name when imported

    def test_multiple_setup_calls_are_idempotent(self):
        """Test that calling setup_logging multiple times is safe."""
        logging.root.handlers = []

        from codeaudit import setup_logging

        logger1 = setup_logging()
        logger2 = setup_logging()

        # Both should be valid logger instances
        assert isinstance(logger1, logging.Logger)
        assert isinstance(logger2, logging.Logger)

        # Should have same name
        assert logger1.name == logger2.name
