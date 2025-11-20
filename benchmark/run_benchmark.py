#!/usr/bin/env python3
"""
CodeAudit Prompt Effectiveness Benchmarking Tool

Tests prompt templates against known vulnerabilities to measure:
- Detection rate (true positives)
- False positive rate
- Severity accuracy
- Framework-specific detection

Usage:
    python benchmark/run_benchmark.py
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

# Add parent directory to path to import codeaudit
sys.path.insert(0, str(Path(__file__).parent.parent))

from codeaudit import CodeAnalyzer


# Expected vulnerabilities for each test file
EXPECTED_VULNERABILITIES = {
    'sql_injection.py': {
        'count': 3,
        'severity': 'high',
        'cwe': 'CWE-89',
        'type': 'security',
        'lines': [14, 24, 34],
        'description_keywords': ['sql', 'injection', 'concatenation', 'formatting']
    },
    'command_injection.py': {
        'count': 3,
        'severity': 'high',
        'cwe': 'CWE-78',
        'type': 'security',
        'lines': [13, 19, 25],
        'description_keywords': ['command', 'injection', 'os.system', 'shell']
    },
    'xss_vulnerability.js': {
        'count': 4,
        'severity': 'high',
        'cwe': 'CWE-79',
        'type': 'security',
        'lines': [8, 13, 18, 23],
        'description_keywords': ['xss', 'cross-site', 'innerHTML', 'eval', 'injection']
    },
    'crypto_secrets.py': {
        'count': 5,
        'severity': 'high',
        'cwe': ['CWE-798', 'CWE-327'],
        'type': 'security',
        'lines': [12, 15, 21, 27, 33],
        'description_keywords': ['hardcoded', 'secret', 'md5', 'weak', 'random', 'api key']
    },
    'django_vulnerabilities.py': {
        'count': 4,
        'severity': 'high',
        'type': 'security',
        'lines': [17, 24, 34, 41],
        'description_keywords': ['django', 'mark_safe', 'csrf', 'sql', 'mass assignment']
    }
}


class BenchmarkResults:
    """Stores and calculates benchmark metrics."""

    def __init__(self):
        self.results = defaultdict(dict)
        self.total_expected = 0
        self.total_detected = 0
        self.total_false_positives = 0
        self.severity_matches = 0
        self.line_matches = 0

    def add_result(self, filename: str, expected: Dict, detected_issues: List[Dict]):
        """Add benchmark result for a file."""
        self.results[filename] = {
            'expected': expected,
            'detected': detected_issues,
            'metrics': self._calculate_metrics(expected, detected_issues)
        }

        # Update totals
        self.total_expected += expected['count']
        metrics = self.results[filename]['metrics']
        self.total_detected += metrics['true_positives']
        self.total_false_positives += metrics['false_positives']
        self.severity_matches += metrics['severity_matches']
        self.line_matches += metrics['line_matches']

    def _calculate_metrics(self, expected: Dict, detected_issues: List[Dict]) -> Dict:
        """Calculate detection metrics for a single file."""
        true_positives = 0
        false_positives = 0
        severity_matches = 0
        line_matches = 0

        # Filter high severity security issues
        high_security_issues = [
            issue for issue in detected_issues
            if issue.get('severity') == 'high' and issue.get('type') == 'security'
        ]

        # Check if detected issues match expected vulnerabilities
        expected_lines = set(expected['lines'])
        detected_lines = {issue.get('line') for issue in high_security_issues if issue.get('line')}

        # Count true positives (detected lines that match expected)
        matching_lines = expected_lines & detected_lines
        true_positives = len(matching_lines)
        line_matches = len(matching_lines)

        # Check severity accuracy
        for issue in high_security_issues:
            if issue.get('line') in expected_lines and issue.get('severity') == expected['severity']:
                severity_matches += 1

        # Calculate false positives (detected issues not in expected lines)
        # For this benchmark, we consider non-matching high-severity issues as potential FPs
        false_positives = len(high_security_issues) - true_positives

        # Detection rate
        detection_rate = (true_positives / expected['count']) * 100 if expected['count'] > 0 else 0

        return {
            'true_positives': true_positives,
            'false_positives': false_positives,
            'expected_count': expected['count'],
            'detected_count': len(high_security_issues),
            'detection_rate': detection_rate,
            'severity_matches': severity_matches,
            'line_matches': line_matches,
            'matching_lines': sorted(matching_lines),
            'missed_lines': sorted(expected_lines - detected_lines)
        }

    def print_report(self):
        """Print detailed benchmark report."""
        print("=" * 80)
        print("CODEAUDIT PROMPT EFFECTIVENESS BENCHMARK REPORT")
        print("=" * 80)
        print()

        # Per-file results
        for filename, data in self.results.items():
            metrics = data['metrics']
            print(f"📁 {filename}")
            print(f"   Expected: {metrics['expected_count']} vulnerabilities")
            print(f"   Detected: {metrics['true_positives']} / {metrics['expected_count']} "
                  f"({metrics['detection_rate']:.1f}%)")
            print(f"   Severity accuracy: {metrics['severity_matches']} / {metrics['true_positives']}")
            print(f"   False positives: {metrics['false_positives']}")

            if metrics['matching_lines']:
                print(f"   ✓ Detected lines: {metrics['matching_lines']}")
            if metrics['missed_lines']:
                print(f"   ✗ Missed lines: {metrics['missed_lines']}")
            print()

        # Overall statistics
        print("=" * 80)
        print("OVERALL STATISTICS")
        print("=" * 80)

        overall_detection_rate = (self.total_detected / self.total_expected) * 100 if self.total_expected > 0 else 0

        print(f"Total expected vulnerabilities: {self.total_expected}")
        print(f"Total detected (true positives): {self.total_detected}")
        print(f"Overall detection rate: {overall_detection_rate:.1f}%")
        print(f"Severity accuracy: {self.severity_matches} / {self.total_detected}")
        print(f"Total false positives: {self.total_false_positives}")
        print()

        # Quality assessment
        print("=" * 80)
        print("QUALITY ASSESSMENT")
        print("=" * 80)

        if overall_detection_rate >= 90:
            grade = "A - Excellent"
        elif overall_detection_rate >= 75:
            grade = "B - Good"
        elif overall_detection_rate >= 60:
            grade = "C - Acceptable"
        else:
            grade = "D - Needs Improvement"

        print(f"Detection Grade: {grade}")
        print(f"Precision: {self._calculate_precision():.1f}%")
        print(f"Recall: {overall_detection_rate:.1f}%")
        print()

    def _calculate_precision(self) -> float:
        """Calculate precision (TP / (TP + FP))."""
        if self.total_detected + self.total_false_positives == 0:
            return 0.0
        return (self.total_detected / (self.total_detected + self.total_false_positives)) * 100

    def save_json(self, output_path: Path):
        """Save results to JSON file."""
        report = {
            'per_file_results': dict(self.results),
            'overall_metrics': {
                'total_expected': self.total_expected,
                'total_detected': self.total_detected,
                'overall_detection_rate': (self.total_detected / self.total_expected) * 100
                if self.total_expected > 0 else 0,
                'total_false_positives': self.total_false_positives,
                'precision': self._calculate_precision(),
                'severity_accuracy': (self.severity_matches / self.total_detected) * 100
                if self.total_detected > 0 else 0
            }
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"📊 Detailed results saved to: {output_path}")


def run_benchmark():
    """Run benchmark against all vulnerable samples."""
    print("🔍 CodeAudit Prompt Effectiveness Benchmark")
    print("=" * 80)
    print()

    # Initialize analyzer
    try:
        analyzer = CodeAnalyzer()
    except Exception as e:
        print(f"❌ Error initializing CodeAnalyzer: {e}")
        print("Make sure GEMINI_API_KEY is set in your environment.")
        return 1

    # Get benchmark files
    benchmark_dir = Path(__file__).parent / 'vulnerable_samples'
    if not benchmark_dir.exists():
        print(f"❌ Benchmark directory not found: {benchmark_dir}")
        return 1

    test_files = list(benchmark_dir.glob('*.py')) + list(benchmark_dir.glob('*.js'))

    if not test_files:
        print(f"❌ No test files found in: {benchmark_dir}")
        return 1

    print(f"Found {len(test_files)} test files")
    print()

    # Run analysis on each file
    results = BenchmarkResults()

    for test_file in test_files:
        filename = test_file.name

        if filename not in EXPECTED_VULNERABILITIES:
            print(f"⚠️  Skipping {filename} - no expected vulnerabilities defined")
            continue

        print(f"🔍 Analyzing {filename}...")

        try:
            # Analyze file
            analysis_result = analyzer.analyze_code_file(test_file)

            if 'error' in analysis_result:
                print(f"   ❌ Analysis error: {analysis_result['error']}")
                continue

            # Get detected issues
            detected_issues = analysis_result.get('issues', [])

            # Add to results
            expected = EXPECTED_VULNERABILITIES[filename]
            results.add_result(filename, expected, detected_issues)

            # Quick summary
            metrics = results.results[filename]['metrics']
            print(f"   ✓ Detected {metrics['true_positives']}/{metrics['expected_count']} "
                  f"({metrics['detection_rate']:.0f}%)")

        except Exception as e:
            print(f"   ❌ Error analyzing {filename}: {e}")
            continue

    print()
    print("=" * 80)
    print()

    # Print full report
    results.print_report()

    # Save JSON report
    output_file = Path(__file__).parent / 'benchmark_results.json'
    results.save_json(output_file)

    return 0


if __name__ == '__main__':
    sys.exit(run_benchmark())
