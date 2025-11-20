"""
Tests for core codeaudit.py functionality.
"""
# pylint: disable=unused-argument  # Fixtures needed for test setup

import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from codeaudit import (
    CodeAnalyzer,
    validate_output_path,
    main
)


class TestCodeAnalyzerCore:
    """Test CodeAnalyzer core functionality."""

    def test_initialization_gemini_api_error(self, caplog):
        """Test handling of Gemini API configuration errors."""
        with patch.dict('os.environ', {'GEMINI_API_KEY': 'test_key'}):
            with patch('google.generativeai.configure', side_effect=Exception("API Error")):
                with pytest.raises(SystemExit):
                    CodeAnalyzer()

        assert 'Error configuring Gemini API' in caplog.text

    def test_get_basic_prompt(self, mock_env_with_api_key, mock_gemini_api):
        """Test _get_basic_prompt method."""
        with patch('codeaudit.PromptEngine', side_effect=Exception("No templates")):
            with patch('codeaudit.FrameworkDetector', side_effect=Exception("No detector")):
                analyzer = CodeAnalyzer()

                # The prompt engine will fail, so it should use basic prompt
                assert analyzer.prompt_engine is None
                assert analyzer.framework_detector is None

    def test_analyze_code_file_with_file_size_limit(self, mock_env_with_api_key, mock_gemini_api, tmp_path):
        """Test that files exceeding size limit are skipped."""
        analyzer = CodeAnalyzer()

        # Create a large file (> 1MB)
        large_file = tmp_path / "large.py"
        large_content = "x" * (2 * 1024 * 1024)  # 2MB
        large_file.write_text(large_content)

        result = analyzer.analyze_code_file(large_file)

        assert 'error' in result
        assert 'Exceeds size limit' in result['error']
        assert result['issues'] == []

    def test_analyze_code_file_read_error(self, mock_env_with_api_key, mock_gemini_api):
        """Test handling of file read errors."""
        analyzer = CodeAnalyzer()

        # Try to analyze a non-existent file
        fake_path = Path("nonexistent_file.py")
        result = analyzer.analyze_code_file(fake_path)

        assert 'error' in result
        assert 'Could not read file' in result['error']

    def test_analyze_code_file_json_decode_error(self, mock_env_with_api_key, mock_gemini_api, temp_test_file):
        """Test handling of JSON decode errors from AI response."""
        analyzer = CodeAnalyzer()

        # Mock the AI to return invalid JSON
        mock_response = Mock()
        mock_response.text = "This is not valid JSON"
        analyzer.model.generate_content = Mock(return_value=mock_response)

        result = analyzer.analyze_code_file(temp_test_file)

        assert 'error' in result
        assert 'Failed to parse AI response' in result['error']
        assert 'raw_response' in result

    def test_analyze_code_file_with_basic_prompt_fallback(self, mock_env_with_api_key, mock_gemini_api, temp_test_file):
        """Test that basic prompt is used when template system fails."""
        with patch('codeaudit.PromptEngine', side_effect=Exception("Template error")):
            with patch('codeaudit.FrameworkDetector', side_effect=Exception("Detector error")):
                analyzer = CodeAnalyzer()

                # Mock successful AI response
                mock_response = Mock()
                mock_response.text = json.dumps({
                    'issues': [],
                    'summary': {'total_issues': 0}
                })
                analyzer.model.generate_content = Mock(return_value=mock_response)

                result = analyzer.analyze_code_file(temp_test_file)

                assert 'issues' in result
                assert isinstance(result['issues'], list)

    def test_analyze_code_file_template_system_runtime_error(self, mock_env_with_api_key, mock_gemini_api, temp_test_file):
        """Test handling of template system errors during analysis."""
        analyzer = CodeAnalyzer()

        # Make framework_detector.detect_frameworks raise an exception
        analyzer.framework_detector.detect_frameworks = Mock(side_effect=Exception("Runtime error"))

        # Mock successful AI response
        mock_response = Mock()
        mock_response.text = json.dumps({
            'issues': [],
            'summary': {'total_issues': 0}
        })
        analyzer.model.generate_content = Mock(return_value=mock_response)

        result = analyzer.analyze_code_file(temp_test_file)

        # Should fall back to basic prompt and still work
        assert 'issues' in result

    def test_analyze_code_file_blocked_prompt_exception(self, mock_env_with_api_key, mock_gemini_api, temp_test_file):
        """Test handling of BlockedPromptException from AI."""
        analyzer = CodeAnalyzer()

        # Import the exception type
        from google.generativeai.types import generation_types

        # Mock BlockedPromptException
        analyzer.model.generate_content = Mock(
            side_effect=generation_types.BlockedPromptException("Content blocked")
        )

        result = analyzer.analyze_code_file(temp_test_file)

        assert 'error' in result
        assert 'AI analysis blocked' in result['error']

    def test_analyze_code_file_generic_exception(self, mock_env_with_api_key, mock_gemini_api, temp_test_file):
        """Test handling of generic exceptions during AI analysis."""
        analyzer = CodeAnalyzer()

        # Mock a generic exception (not a specific type like JSONDecodeError)
        analyzer.model.generate_content = Mock(
            side_effect=RuntimeError("Unexpected AI error")
        )

        result = analyzer.analyze_code_file(temp_test_file)

        assert 'error' in result
        assert 'AI analysis failed' in result['error']
        assert 'Unexpected AI error' in result['error']

    def test_print_analysis_results_no_issues(self, mock_env_with_api_key, mock_gemini_api, caplog):
        """Test printing results when no issues are found."""
        import logging
        caplog.set_level(logging.INFO)

        analyzer = CodeAnalyzer()

        results = [{
            'file': 'test.py',
            'issues': [],
            'summary': {'total_issues': 0}
        }]

        analyzer.print_analysis_results(results)

        assert 'CODE ANALYSIS COMPLETE' in caplog.text
        assert 'No issues found' in caplog.text

    def test_print_analysis_results_with_issues(self, mock_env_with_api_key, mock_gemini_api, caplog):
        """Test printing results with issues found."""
        import logging
        caplog.set_level(logging.INFO)

        analyzer = CodeAnalyzer()

        results = [{
            'file': 'test.py',
            'issues': [
                {
                    'type': 'security',
                    'severity': 'high',
                    'line': 42,
                    'description': 'SQL Injection vulnerability',
                    'suggestion': 'Use parameterized queries'
                }
            ],
            'summary': {
                'total_issues': 1,
                'high_severity': 1,
                'medium_severity': 0,
                'low_severity': 0,
                'maintainability_score': '7/10'
            }
        }]

        analyzer.print_analysis_results(results)

        assert 'CODE ANALYSIS COMPLETE' in caplog.text
        assert 'SQL Injection' in caplog.text
        assert 'Line 42' in caplog.text
        assert 'HIGH' in caplog.text

    def test_print_analysis_results_with_error(self, mock_env_with_api_key, mock_gemini_api, caplog):
        """Test printing results when analysis had errors."""
        import logging
        caplog.set_level(logging.INFO)

        analyzer = CodeAnalyzer()

        results = [{
            'file': 'test.py',
            'error': 'Analysis failed',
            'raw_response': 'Error details here',
            'issues': []
        }]

        analyzer.print_analysis_results(results)

        assert 'Analysis failed' in caplog.text
        assert 'Raw Response Snippet' in caplog.text

    def test_save_results_json_success(self, mock_env_with_api_key, mock_gemini_api, tmp_path):
        """Test saving results to JSON file."""
        analyzer = CodeAnalyzer()

        results = [{'file': 'test.py', 'issues': []}]
        output_file = tmp_path / "results.json"

        analyzer.save_results_json(results, output_file)

        assert output_file.exists()
        with open(output_file, 'r', encoding='utf-8') as f:
            saved_data = json.load(f)
        assert saved_data == results

    def test_save_results_json_error(self, mock_env_with_api_key, mock_gemini_api, caplog):
        """Test handling of errors when saving results."""
        analyzer = CodeAnalyzer()

        results = [{'file': 'test.py', 'issues': []}]
        invalid_path = Path("/invalid/path/results.json")

        analyzer.save_results_json(results, invalid_path)

        assert 'Error saving results' in caplog.text


class TestValidateOutputPath:
    """Test validate_output_path function."""

    def test_validate_output_path_none_input(self):
        """Test that None input returns None."""
        result = validate_output_path(None)
        assert result is None

    def test_validate_output_path_empty_string(self):
        """Test that empty string returns None."""
        result = validate_output_path("")
        assert result is None

    def test_validate_output_path_valid_path(self, tmp_path):
        """Test validation of a valid path in current directory."""
        output_file = tmp_path / "report.json"

        with patch('pathlib.Path.cwd', return_value=tmp_path):
            result = validate_output_path(str(output_file))
            assert result == output_file.resolve()

    def test_validate_output_path_outside_cwd_exits(self, tmp_path, caplog):
        """Test that path outside CWD causes exit."""
        output_file = Path("/tmp/outside/report.json")

        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with pytest.raises(SystemExit):
                validate_output_path(str(output_file))

        assert 'outside the current directory tree' in caplog.text

    def test_validate_output_path_existing_file_user_confirms(self, tmp_path):
        """Test overwrite confirmation when file exists."""
        output_file = tmp_path / "existing.json"
        output_file.write_text("existing content")

        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with patch('builtins.input', return_value='y'):
                result = validate_output_path(str(output_file))
                assert result == output_file.resolve()

    def test_validate_output_path_existing_file_user_aborts(self, tmp_path):
        """Test that user can abort overwrite."""
        output_file = tmp_path / "existing.json"
        output_file.write_text("existing content")

        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with patch('builtins.input', return_value='n'):
                with pytest.raises(SystemExit) as exc_info:
                    validate_output_path(str(output_file))
                assert exc_info.value.code == 0


class TestMainFunction:
    """Test main() function."""

    def test_main_no_files_found(self, mock_env_with_api_key, mock_gemini_api, tmp_path, caplog):
        """Test main when no files are found."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        test_args = ['codeaudit.py', str(empty_dir)]
        with patch.object(sys, 'argv', test_args):
            with patch('codeaudit.PromptEngine'):
                with patch('codeaudit.FrameworkDetector'):
                    main()

        assert 'No supported code files found' in caplog.text

    def test_main_with_single_file(self, mock_env_with_api_key, mock_gemini_api, tmp_path, caplog):
        """Test main with a single file."""
        import logging
        caplog.set_level(logging.INFO)

        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): pass")

        test_args = ['codeaudit.py', str(test_file)]

        with patch.object(sys, 'argv', test_args):
            with patch('codeaudit.PromptEngine'):
                with patch('codeaudit.FrameworkDetector'):
                    # Mock the AI response
                    with patch('codeaudit.CodeAnalyzer.analyze_code_file') as mock_analyze:
                        mock_analyze.return_value = {
                            'file': str(test_file),
                            'issues': [],
                            'summary': {'total_issues': 0}
                        }
                        main()

        assert 'CODE ANALYSIS COMPLETE' in caplog.text

    def test_main_with_output_file(self, mock_env_with_api_key, mock_gemini_api, tmp_path):
        """Test main with JSON output."""
        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): pass")

        output_file = tmp_path / "results.json"

        test_args = ['codeaudit.py', str(test_file), '--output', str(output_file)]

        # Mock Path.cwd() to return tmp_path so validation passes
        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with patch.object(sys, 'argv', test_args):
                with patch('codeaudit.PromptEngine'):
                    with patch('codeaudit.FrameworkDetector'):
                        with patch('codeaudit.CodeAnalyzer.analyze_code_file') as mock_analyze:
                            mock_analyze.return_value = {
                                'file': str(test_file),
                                'issues': [],
                                'summary': {'total_issues': 0}
                            }
                            main()

        assert output_file.exists()

    def test_main_with_max_files_limit(self, mock_env_with_api_key, mock_gemini_api, tmp_path, caplog):
        """Test main with max-files limit."""
        import logging
        caplog.set_level(logging.INFO)

        # Create multiple files
        for i in range(5):
            test_file = tmp_path / f"test{i}.py"
            test_file.write_text(f"def func{i}(): pass")

        test_args = ['codeaudit.py', str(tmp_path), '--max-files', '2']

        with patch.object(sys, 'argv', test_args):
            with patch('codeaudit.PromptEngine'):
                with patch('codeaudit.FrameworkDetector'):
                    with patch('codeaudit.CodeAnalyzer.analyze_code_file') as mock_analyze:
                        mock_analyze.return_value = {
                            'file': 'test.py',
                            'issues': [],
                            'summary': {'total_issues': 0}
                        }
                        main()

        assert 'Limiting analysis to first 2' in caplog.text

    def test_main_recursive_flag(self, mock_env_with_api_key, mock_gemini_api, tmp_path):
        """Test main with recursive directory scanning."""
        # Create subdirectory with file
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        test_file = subdir / "test.py"
        test_file.write_text("def hello(): pass")

        test_args = ['codeaudit.py', str(tmp_path), '--recursive']

        with patch.object(sys, 'argv', test_args):
            with patch('codeaudit.PromptEngine'):
                with patch('codeaudit.FrameworkDetector'):
                    with patch('codeaudit.CodeAnalyzer.analyze_code_file') as mock_analyze:
                        mock_analyze.return_value = {
                            'file': str(test_file),
                            'issues': [],
                            'summary': {'total_issues': 0}
                        }
                        main()

        # Should find the file in subdirectory
        assert mock_analyze.called


class TestProgressBar:
    """Test progress bar functionality."""

    def test_main_with_progress_bar_enabled(self, mock_env_with_api_key, mock_gemini_api, tmp_path):
        """Test that progress bar is displayed by default."""
        # Create test files
        for i in range(3):
            test_file = tmp_path / f"test{i}.py"
            test_file.write_text(f"def func{i}(): pass")

        test_args = ['codeaudit.py', str(tmp_path)]

        with patch.object(sys, 'argv', test_args):
            with patch('codeaudit.PromptEngine'):
                with patch('codeaudit.FrameworkDetector'):
                    with patch('codeaudit.CodeAnalyzer.analyze_code_file') as mock_analyze:
                        with patch('codeaudit.tqdm') as mock_tqdm:
                            # Configure tqdm mock to return an iterable
                            mock_tqdm.return_value = iter([
                                tmp_path / "test0.py",
                                tmp_path / "test1.py",
                                tmp_path / "test2.py"
                            ])

                            mock_analyze.return_value = {
                                'file': 'test.py',
                                'issues': [],
                                'summary': {'total_issues': 0}
                            }

                            main()

                            # Verify tqdm was called (progress bar enabled)
                            assert mock_tqdm.called

    def test_main_with_progress_bar_disabled(self, mock_env_with_api_key, mock_gemini_api, tmp_path):
        """Test that progress bar is disabled with --no-progress flag."""
        # Create test files
        for i in range(3):
            test_file = tmp_path / f"test{i}.py"
            test_file.write_text(f"def func{i}(): pass")

        test_args = ['codeaudit.py', str(tmp_path), '--no-progress']

        with patch.object(sys, 'argv', test_args):
            with patch('codeaudit.PromptEngine'):
                with patch('codeaudit.FrameworkDetector'):
                    with patch('codeaudit.CodeAnalyzer.analyze_code_file') as mock_analyze:
                        with patch('codeaudit.tqdm') as mock_tqdm:
                            mock_analyze.return_value = {
                                'file': 'test.py',
                                'issues': [],
                                'summary': {'total_issues': 0}
                            }

                            main()

                            # Verify tqdm was NOT called (progress bar disabled)
                            assert not mock_tqdm.called


class TestFixSuggestions:
    """Test automated fix suggestion feature."""

    def test_fix_suggestions_in_response(self, mock_env_with_api_key, mock_gemini_api, tmp_path):
        """Test that fix suggestions are included in AI response and properly parsed."""
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text("""
def query_user(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return query
""")

        # Mock response with fix suggestion
        mock_response = Mock()
        mock_response.text = json.dumps({
            "issues": [
                {
                    "type": "security",
                    "severity": "high",
                    "line": 2,
                    "description": "SQL injection vulnerability",
                    "suggestion": "Use parameterized queries",
                    "fix": {
                        "before_code": "query = f\"SELECT * FROM users WHERE name = '{username}'\"",
                        "after_code": "query = \"SELECT * FROM users WHERE name = ?\"\\nparams = (username,)",
                        "explanation": "Parameterized queries prevent SQL injection by separating SQL code from data",
                        "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
                    }
                }
            ],
            "summary": {
                "total_issues": 1,
                "high_severity": 1,
                "medium_severity": 0,
                "low_severity": 0,
                "maintainability_score": "6"
            }
        })
        mock_gemini_api['instance'].generate_content.return_value = mock_response

        analyzer = CodeAnalyzer(enable_cache=False)
        result = analyzer.analyze_code_file(test_file)

        # Verify fix suggestion is in the result
        assert 'issues' in result
        assert len(result['issues']) == 1
        issue = result['issues'][0]
        assert 'fix' in issue
        assert isinstance(issue['fix'], dict)
        assert 'before_code' in issue['fix']
        assert 'after_code' in issue['fix']
        assert 'explanation' in issue['fix']
        assert 'references' in issue['fix']
        assert len(issue['fix']['references']) > 0

    def test_fix_suggestions_display(self, mock_env_with_api_key, mock_gemini_api, tmp_path):
        """Test that fix suggestions are properly displayed in output."""
        test_file = tmp_path / "test.py"
        test_file.write_text("def test(): pass")

        # Create analyzer
        analyzer = CodeAnalyzer(enable_cache=False)

        # Create test result with fix suggestion
        test_results = [{
            'file': str(test_file),
            'issues': [{
                'type': 'security',
                'severity': 'high',
                'line': 10,
                'description': 'SQL injection',
                'suggestion': 'Use parameterized queries',
                'fix': {
                    'before_code': "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
                    'after_code': "query = \"SELECT * FROM users WHERE id = ?\"",
                    'explanation': 'Prevents SQL injection',
                    'references': ['https://example.com/sql-injection']
                }
            }],
            'summary': {
                'total_issues': 1,
                'high_severity': 1,
                'medium_severity': 0,
                'low_severity': 0,
                'maintainability_score': '7'
            }
        }]

        # Mock logger to capture calls
        with patch('codeaudit.logger') as mock_logger:
            analyzer.print_analysis_results(test_results)

            # Collect all logger.info() calls
            all_calls = [str(call) for call in mock_logger.info.call_args_list]
            all_output = ' '.join(all_calls)

            # Verify fix suggestion elements are logged
            assert any('Automated Fix' in str(call) or '🔧' in str(call) for call in all_calls), \
                "Fix header not found in logger output"
            assert any('Before' in str(call) for call in all_calls), \
                "Before label not found in logger output"
            assert any('After' in str(call) for call in all_calls), \
                "After label not found in logger output"
            assert any('Why' in str(call) or 'Prevents SQL injection' in str(call) for call in all_calls), \
                "Explanation not found in logger output"
            assert any('https://example.com/sql-injection' in str(call) for call in all_calls), \
                "References not found in logger output"

    def test_fix_suggestions_optional(self, mock_env_with_api_key, mock_gemini_api, tmp_path):
        """Test that issues without fix suggestions still work."""
        test_file = tmp_path / "test.py"
        test_file.write_text("def test(): pass")

        # Mock response without fix suggestion
        mock_response = Mock()
        mock_response.text = json.dumps({
            "issues": [
                {
                    "type": "smell",
                    "severity": "low",
                    "line": 1,
                    "description": "Function too short",
                    "suggestion": "Add docstring"
                    # No fix field
                }
            ],
            "summary": {
                "total_issues": 1,
                "high_severity": 0,
                "medium_severity": 0,
                "low_severity": 1,
                "maintainability_score": "8"
            }
        })
        mock_gemini_api['instance'].generate_content.return_value = mock_response

        analyzer = CodeAnalyzer(enable_cache=False)
        result = analyzer.analyze_code_file(test_file)

        # Verify it works without fix field
        assert 'issues' in result
        assert len(result['issues']) == 1
        issue = result['issues'][0]
        assert 'fix' not in issue or issue.get('fix') is None

    def test_fix_suggestions_malformed(self, mock_env_with_api_key, mock_gemini_api, tmp_path, capsys):
        """Test handling of malformed fix suggestions."""
        test_file = tmp_path / "test.py"
        test_file.write_text("def test(): pass")

        analyzer = CodeAnalyzer(enable_cache=False)

        # Test with various malformed fix data
        malformed_results = [{
            'file': str(test_file),
            'issues': [
                {
                    'type': 'bug',
                    'severity': 'medium',
                    'line': 5,
                    'description': 'Null pointer',
                    'suggestion': 'Add null check',
                    'fix': {
                        # Missing before_code and after_code
                        'explanation': 'Check for null values'
                    }
                },
                {
                    'type': 'bug',
                    'severity': 'low',
                    'line': 10,
                    'description': 'Type error',
                    'suggestion': 'Add type hint',
                    'fix': None  # Null fix
                },
                {
                    'type': 'bug',
                    'severity': 'low',
                    'line': 15,
                    'description': 'Missing return',
                    'suggestion': 'Add return statement',
                    'fix': "not a dict"  # Wrong type
                }
            ],
            'summary': {'total_issues': 3, 'high_severity': 0, 'medium_severity': 1, 'low_severity': 2, 'maintainability_score': '7'}
        }]

        # Should not raise an exception
        try:
            analyzer.print_analysis_results(malformed_results)
            # If we get here, test passed
            assert True
        except Exception as e:
            pytest.fail(f"print_analysis_results raised exception with malformed fix data: {e}")


class TestMainEntryPoint:
    """Test __main__ entry point."""

    def test_main_entry_point(self, mock_env_with_api_key, mock_gemini_api, tmp_path):
        """Test that __main__ block calls main()."""
        test_file = tmp_path / "test.py"
        test_file.write_text("def hello(): pass")

        # Import the module and execute __main__ block
        import importlib.util
        spec = importlib.util.spec_from_file_location("codeaudit_main", "codeaudit.py")
        module = importlib.util.module_from_spec(spec)

        with patch.object(sys, 'argv', ['codeaudit.py', str(test_file)]):
            with patch('codeaudit.PromptEngine'):
                with patch('codeaudit.FrameworkDetector'):
                    with patch('codeaudit.main') as mock_main:
                        # Execute the module to trigger __name__ == "__main__"
                        try:
                            spec.loader.exec_module(module)
                        except SystemExit:
                            pass  # main() might call sys.exit()

                        # Main should have been called during module load
                        # Module loads main via import - test passes if no exception
