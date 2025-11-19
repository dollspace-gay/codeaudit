"""
Pytest configuration and shared fixtures.

Provides common fixtures for testing the CodeAudit application.
"""

import os
import pytest
from pathlib import Path
from unittest.mock import Mock, patch


@pytest.fixture
def temp_test_file(tmp_path):
    """
    Create a temporary test file for analysis.

    Args:
        tmp_path: pytest built-in fixture for temporary directory

    Returns:
        Path to temporary test file
    """
    test_file = tmp_path / "test_code.py"
    test_file.write_text("""
def vulnerable_function(user_input):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query
""")
    return test_file


@pytest.fixture
def mock_gemini_api():
    """
    Mock the Gemini AI API for testing.

    Returns:
        Mock object configured for Gemini API
    """
    with patch('google.generativeai.configure') as mock_configure:
        with patch('google.generativeai.GenerativeModel') as mock_model:
            # Setup mock response
            mock_response = Mock()
            mock_response.text = '{"issues": [], "summary": {"total_issues": 0, "high_severity": 0, "medium_severity": 0, "low_severity": 0, "maintainability_score": "8"}}'

            mock_instance = Mock()
            mock_instance.generate_content.return_value = mock_response
            mock_model.return_value = mock_instance

            yield {
                'configure': mock_configure,
                'model': mock_model,
                'instance': mock_instance,
                'response': mock_response
            }


@pytest.fixture
def mock_env_with_api_key():
    """
    Mock environment with GEMINI_API_KEY set.

    Yields:
        Dictionary of environment variables
    """
    with patch.dict(os.environ, {'GEMINI_API_KEY': 'test_api_key_12345'}):
        yield os.environ


@pytest.fixture
def sample_python_code():
    """
    Sample Python code with known vulnerabilities.

    Returns:
        String containing vulnerable Python code
    """
    return """
import pickle
import os

def load_user_data(user_file):
    # Pickle deserialization vulnerability
    with open(user_file, 'rb') as f:
        data = pickle.load(f)
    return data

def execute_command(cmd):
    # Command injection vulnerability
    os.system(cmd)

def query_database(username):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return query
"""


@pytest.fixture
def sample_javascript_code():
    """
    Sample JavaScript code with known vulnerabilities.

    Returns:
        String containing vulnerable JavaScript code
    """
    return """
function setHTML(userInput) {
    // XSS vulnerability
    document.getElementById('content').innerHTML = userInput;
}

function merge(target, source) {
    // Prototype pollution
    for (let key in source) {
        target[key] = source[key];
    }
}

async function findUser(username) {
    // NoSQL injection
    const user = await db.collection('users').findOne({ username: username });
    return user;
}
"""


@pytest.fixture(autouse=True)
def reset_logging():
    """
    Reset logging configuration before each test.

    This fixture runs automatically before each test to ensure
    a clean logging state.
    """
    import logging
    # Store original handlers
    original_handlers = logging.root.handlers[:]

    yield

    # Restore original handlers
    logging.root.handlers = original_handlers


@pytest.fixture
def mock_prompt_engine():
    """
    Mock the PromptEngine for testing.

    Returns:
        Mock PromptEngine instance
    """
    with patch('codeaudit.PromptEngine') as mock:
        mock_instance = Mock()
        mock_instance.get_prompt.return_value = "Test prompt"
        mock.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_framework_detector():
    """
    Mock the FrameworkDetector for testing.

    Returns:
        Mock FrameworkDetector instance
    """
    with patch('codeaudit.FrameworkDetector') as mock:
        mock_instance = Mock()
        mock_instance.detect_frameworks.return_value = []
        mock.get_threat_models_for_frameworks.return_value = []
        mock.return_value = mock_instance
        yield mock_instance
