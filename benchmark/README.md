# CodeAudit Prompt Effectiveness Benchmark

This benchmark suite tests the effectiveness of CodeAudit's prompt templates against known security vulnerabilities.

## Overview

The benchmark measures:
- **Detection Rate**: Percentage of known vulnerabilities detected
- **Precision**: Accuracy of detections (TP / (TP + FP))
- **Severity Accuracy**: Correct severity classification
- **Framework-Specific Detection**: Effectiveness of framework-specific prompts

## Test Files

### Python Vulnerabilities

**sql_injection.py**
- 3 SQL injection vulnerabilities (CWE-89)
- Tests: string concatenation, f-strings, % formatting
- Expected: 3 high-severity detections

**command_injection.py**
- 3 command injection vulnerabilities (CWE-78)
- Tests: os.system, subprocess with shell=True, os.popen
- Expected: 3 high-severity detections

**crypto_secrets.py**
- 5 cryptography and secret management issues
- Tests: hardcoded API keys, weak hashing (MD5), weak random, hardcoded passwords
- Expected: 5 high-severity detections (CWE-798, CWE-327)

**django_vulnerabilities.py**
- 4 Django framework-specific vulnerabilities
- Tests: mark_safe injection, @csrf_exempt, ORM injection, mass assignment
- Expected: 4 high-severity detections
- Tests framework-specific prompt effectiveness

### JavaScript Vulnerabilities

**xss_vulnerability.js**
- 4 cross-site scripting vulnerabilities (CWE-79)
- Tests: innerHTML, document.write, eval, jQuery .html()
- Expected: 4 high-severity detections

## Running the Benchmark

### Prerequisites

```bash
# Ensure GEMINI_API_KEY is set
export GEMINI_API_KEY="your_api_key_here"

# Install dependencies
pip install -r requirements.txt
```

### Execute Benchmark

```bash
# Run from project root
python benchmark/run_benchmark.py
```

### Output

The benchmark generates:

1. **Console Report**: Real-time progress and summary statistics
2. **JSON Report**: Detailed results in `benchmark/benchmark_results.json`

## Understanding Results

### Detection Metrics

**Per-File Metrics:**
- Expected vulnerabilities count
- Detected vulnerabilities (true positives)
- Detection rate percentage
- Severity accuracy
- False positives
- Matched/missed line numbers

**Overall Metrics:**
- Total detection rate
- Precision (TP / (TP + FP))
- Recall (same as detection rate)
- Quality grade (A/B/C/D)

### Quality Grades

| Grade | Detection Rate | Assessment |
|-------|----------------|------------|
| A | ≥ 90% | Excellent |
| B | 75-89% | Good |
| C | 60-74% | Acceptable |
| D | < 60% | Needs Improvement |

### Example Output

```
================================================================================
CODEAUDIT PROMPT EFFECTIVENESS BENCHMARK REPORT
================================================================================

📁 sql_injection.py
   Expected: 3 vulnerabilities
   Detected: 3 / 3 (100.0%)
   Severity accuracy: 3 / 3
   False positives: 0
   ✓ Detected lines: [14, 24, 34]

📁 command_injection.py
   Expected: 3 vulnerabilities
   Detected: 3 / 3 (100.0%)
   Severity accuracy: 3 / 3
   False positives: 0
   ✓ Detected lines: [13, 19, 25]

================================================================================
OVERALL STATISTICS
================================================================================
Total expected vulnerabilities: 19
Total detected (true positives): 18
Overall detection rate: 94.7%
Severity accuracy: 18 / 18
Total false positives: 2

================================================================================
QUALITY ASSESSMENT
================================================================================
Detection Grade: A - Excellent
Precision: 90.0%
Recall: 94.7%
```

## Adding New Test Cases

To add a new vulnerable code sample:

1. **Create test file** in `benchmark/vulnerable_samples/`

```python
"""
Test Case Description
Expected Issues: X high-severity vulnerabilities
CWE-XXX: Vulnerability Name
"""

# Line N: HIGH - Vulnerability description
def vulnerable_function():
    pass
```

2. **Add to EXPECTED_VULNERABILITIES** in `run_benchmark.py`

```python
EXPECTED_VULNERABILITIES = {
    'your_test.py': {
        'count': 2,
        'severity': 'high',
        'cwe': 'CWE-XXX',
        'type': 'security',
        'lines': [10, 20],
        'description_keywords': ['keyword1', 'keyword2']
    }
}
```

3. **Run benchmark** to verify detection

## Interpreting Results

### High Detection Rate (>90%)
- Prompts are effectively identifying vulnerabilities
- Template quality is excellent
- Minimal tuning needed

### Medium Detection Rate (60-90%)
- Prompts catching most issues
- May need refinement for specific patterns
- Review missed vulnerabilities

### Low Detection Rate (<60%)
- Prompt templates need improvement
- Add more specific guidance
- Include more examples
- Review template priority

### High False Positive Rate
- Prompts may be too aggressive
- Tighten detection criteria
- Add more context to examples

## Continuous Improvement

Use benchmark results to:

1. **Identify weak areas** - Which vulnerability types are missed?
2. **Refine prompts** - Add specific patterns to templates
3. **Add examples** - Include missed patterns in few-shot examples
4. **Test improvements** - Re-run benchmark after changes
5. **Track progress** - Compare results over time

## Baseline Results

Initial benchmark results establish a baseline for prompt effectiveness:

- Target detection rate: ≥ 90%
- Target precision: ≥ 85%
- Target severity accuracy: ≥ 95%

## Limitations

- **AI Variability**: Results may vary between runs due to AI model behavior
- **Test Coverage**: Limited to common vulnerability patterns
- **False Positive Definition**: Conservative (any non-matching detection)
- **Line Number Precision**: Requires exact line matches

## Future Enhancements

Planned improvements:

- [ ] Add more language-specific test cases (Java, Go, Rust)
- [ ] Test threat model prompts specifically
- [ ] Measure detection latency
- [ ] Compare against baseline (non-specialized) prompts
- [ ] Add more framework-specific tests (Flask, React, Spring)
- [ ] Statistical significance testing across multiple runs
- [ ] Vulnerability severity distribution analysis

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE List](https://cwe.mitre.org/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
