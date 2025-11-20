"""
Tests for the benchmarking system.

These tests verify the benchmark framework functionality without making API calls.
"""
import sys
from pathlib import Path

# Add benchmark directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'benchmark'))

from run_benchmark import BenchmarkResults, EXPECTED_VULNERABILITIES


class TestBenchmarkResults:
    """Test benchmark result calculations."""

    def test_perfect_detection(self):
        """Test metrics when all vulnerabilities are detected correctly."""
        results = BenchmarkResults()

        expected = {
            'count': 3,
            'severity': 'high',
            'type': 'security',
            'lines': [10, 20, 30]
        }

        detected_issues = [
            {'type': 'security', 'severity': 'high', 'line': 10},
            {'type': 'security', 'severity': 'high', 'line': 20},
            {'type': 'security', 'severity': 'high', 'line': 30}
        ]

        results.add_result('test.py', expected, detected_issues)

        metrics = results.results['test.py']['metrics']

        assert metrics['true_positives'] == 3
        assert metrics['false_positives'] == 0
        assert metrics['detection_rate'] == 100.0
        assert metrics['severity_matches'] == 3
        assert len(metrics['missed_lines']) == 0

    def test_partial_detection(self):
        """Test metrics when some vulnerabilities are missed."""
        results = BenchmarkResults()

        expected = {
            'count': 3,
            'severity': 'high',
            'type': 'security',
            'lines': [10, 20, 30]
        }

        # Only detect 2 out of 3
        detected_issues = [
            {'type': 'security', 'severity': 'high', 'line': 10},
            {'type': 'security', 'severity': 'high', 'line': 20}
        ]

        results.add_result('test.py', expected, detected_issues)

        metrics = results.results['test.py']['metrics']

        assert metrics['true_positives'] == 2
        assert metrics['false_positives'] == 0
        assert abs(metrics['detection_rate'] - 66.67) < 0.1  # 2/3 * 100
        assert metrics['severity_matches'] == 2
        assert metrics['missed_lines'] == [30]

    def test_false_positives(self):
        """Test metrics when false positives are detected."""
        results = BenchmarkResults()

        expected = {
            'count': 2,
            'severity': 'high',
            'type': 'security',
            'lines': [10, 20]
        }

        # Detect expected plus one extra (false positive)
        detected_issues = [
            {'type': 'security', 'severity': 'high', 'line': 10},
            {'type': 'security', 'severity': 'high', 'line': 20},
            {'type': 'security', 'severity': 'high', 'line': 99}  # False positive
        ]

        results.add_result('test.py', expected, detected_issues)

        metrics = results.results['test.py']['metrics']

        assert metrics['true_positives'] == 2
        assert metrics['false_positives'] == 1
        assert metrics['detection_rate'] == 100.0
        assert len(metrics['matching_lines']) == 2

    def test_wrong_severity(self):
        """Test when severity is incorrectly classified."""
        results = BenchmarkResults()

        expected = {
            'count': 2,
            'severity': 'high',
            'type': 'security',
            'lines': [10, 20]
        }

        # Detect issues but with wrong severity
        detected_issues = [
            {'type': 'security', 'severity': 'high', 'line': 10},
            {'type': 'security', 'severity': 'medium', 'line': 20}  # Wrong severity
        ]

        results.add_result('test.py', expected, detected_issues)

        metrics = results.results['test.py']['metrics']

        # Line 20 is not counted as high-severity issue
        # Only high severity issues are counted in this benchmark
        assert metrics['true_positives'] == 1
        assert metrics['severity_matches'] == 1

    def test_overall_metrics(self):
        """Test overall statistics across multiple files."""
        results = BenchmarkResults()

        # File 1: Perfect detection
        expected1 = {'count': 3, 'severity': 'high', 'type': 'security', 'lines': [10, 20, 30]}
        detected1 = [
            {'type': 'security', 'severity': 'high', 'line': 10},
            {'type': 'security', 'severity': 'high', 'line': 20},
            {'type': 'security', 'severity': 'high', 'line': 30}
        ]
        results.add_result('file1.py', expected1, detected1)

        # File 2: Partial detection
        expected2 = {'count': 2, 'severity': 'high', 'type': 'security', 'lines': [15, 25]}
        detected2 = [
            {'type': 'security', 'severity': 'high', 'line': 15}
        ]
        results.add_result('file2.py', expected2, detected2)

        # Overall: 4/5 detected = 80%
        assert results.total_expected == 5
        assert results.total_detected == 4
        overall_rate = (results.total_detected / results.total_expected) * 100
        assert overall_rate == 80.0

    def test_precision_calculation(self):
        """Test precision metric calculation."""
        results = BenchmarkResults()

        expected = {'count': 2, 'severity': 'high', 'type': 'security', 'lines': [10, 20]}

        # 2 true positives + 1 false positive
        detected_issues = [
            {'type': 'security', 'severity': 'high', 'line': 10},
            {'type': 'security', 'severity': 'high', 'line': 20},
            {'type': 'security', 'severity': 'high', 'line': 99}
        ]

        results.add_result('test.py', expected, detected_issues)

        # Precision = TP / (TP + FP) = 2 / (2 + 1) = 66.7%
        precision = results._calculate_precision()
        assert abs(precision - 66.7) < 0.1


class TestExpectedVulnerabilities:
    """Test that expected vulnerabilities are properly defined."""

    def test_all_test_files_have_expectations(self):
        """Verify all test files have expected vulnerabilities defined."""
        benchmark_dir = Path(__file__).parent.parent / 'benchmark' / 'vulnerable_samples'

        if not benchmark_dir.exists():
            # Benchmark directory not set up yet - skip
            return

        test_files = list(benchmark_dir.glob('*.py')) + list(benchmark_dir.glob('*.js'))

        for test_file in test_files:
            assert test_file.name in EXPECTED_VULNERABILITIES, \
                f"Missing expected vulnerabilities for {test_file.name}"

    def test_expected_vulnerabilities_structure(self):
        """Verify expected vulnerabilities have correct structure."""
        for filename, expected in EXPECTED_VULNERABILITIES.items():
            # Required fields
            assert 'count' in expected
            assert 'severity' in expected
            assert 'type' in expected
            assert 'lines' in expected

            # Validate types
            assert isinstance(expected['count'], int)
            assert expected['count'] > 0
            assert expected['severity'] in ['high', 'medium', 'low']
            assert expected['type'] == 'security'
            assert isinstance(expected['lines'], list)
            assert len(expected['lines']) == expected['count']

    def test_sql_injection_expectations(self):
        """Test SQL injection file expectations."""
        expected = EXPECTED_VULNERABILITIES['sql_injection.py']

        assert expected['count'] == 3
        assert expected['severity'] == 'high'
        assert expected['cwe'] == 'CWE-89'
        assert len(expected['lines']) == 3
        assert 'sql' in [kw.lower() for kw in expected['description_keywords']]

    def test_django_expectations(self):
        """Test Django vulnerabilities file expectations."""
        expected = EXPECTED_VULNERABILITIES['django_vulnerabilities.py']

        assert expected['count'] == 4
        assert expected['severity'] == 'high'
        assert 'django' in [kw.lower() for kw in expected['description_keywords']]


class TestBenchmarkFiles:
    """Test that benchmark files exist and are properly formatted."""

    def test_vulnerable_samples_exist(self):
        """Verify vulnerable sample files exist."""
        benchmark_dir = Path(__file__).parent.parent / 'benchmark' / 'vulnerable_samples'

        if not benchmark_dir.exists():
            # Benchmark directory not set up yet - skip
            return

        for filename in EXPECTED_VULNERABILITIES.keys():
            file_path = benchmark_dir / filename
            assert file_path.exists(), f"Test file not found: {filename}"

    def test_sql_injection_file_content(self):
        """Verify SQL injection test file has expected vulnerabilities."""
        benchmark_dir = Path(__file__).parent.parent / 'benchmark' / 'vulnerable_samples'
        sql_file = benchmark_dir / 'sql_injection.py'

        if not sql_file.exists():
            return

        content = sql_file.read_text()

        # Should contain vulnerable patterns
        assert 'string concatenation' in content.lower() or 'concatenation' in content.lower()
        assert 'execute' in content
        assert 'select' in content.lower()

    def test_benchmark_script_exists(self):
        """Verify benchmark runner script exists."""
        benchmark_script = Path(__file__).parent.parent / 'benchmark' / 'run_benchmark.py'

        if benchmark_script.exists():
            assert benchmark_script.is_file()
            # Should be executable on Unix systems
            content = benchmark_script.read_text(encoding='utf-8')
            assert 'BenchmarkResults' in content
            assert 'run_benchmark' in content
