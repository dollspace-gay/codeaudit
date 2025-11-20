# CodeAudit - AI-Powered Code Security Analyzer

A powerful command-line tool that leverages Google's Gemini AI to perform comprehensive security audits on your source code. CodeAudit identifies vulnerabilities, performance issues, and code smells with intelligent, language-specific and framework-aware analysis.

## Key Features

- **AI-Powered Analysis**: Uses Google Gemini 2.5 Flash for intelligent vulnerability detection
- **Result Caching**: SHA-256-based caching avoids re-analyzing unchanged files, improving performance
- **Language-Specific Prompts**: Specialized analysis for Python, JavaScript, TypeScript, Java, C/C++, Go, Rust, PHP, Ruby, Swift, Kotlin, Scala, and Dart
- **Framework-Aware**: Detects and applies framework-specific security checks (Django, Flask, FastAPI, React, Express, Spring, etc.)
- **Few-Shot Learning**: Provides vulnerability examples to improve AI accuracy
- **Structured Logging**: Configurable logging levels for debugging and integration
- **Type-Safe**: Full type annotations checked with mypy
- **High Code Quality**: Pylint score 10.0/10

## How It Works

CodeAudit operates in a five-step process:

1. **File Discovery**: Scans directories for supported code files, respecting ignore patterns
2. **Cache Check**: Computes file hash (SHA-256) and retrieves cached results if file unchanged
3. **Framework Detection**: Identifies frameworks and selects appropriate security checks
4. **AI Analysis**: Sends code to Gemini AI with specialized prompts for deep analysis
5. **Caching & Reporting**: Caches results and generates detailed reports with severity levels, descriptions, and fix suggestions

**Note**: Cache is stored in `~/.cache/codeaudit/` and automatically invalidates when files are modified.

## Requirements

- Python 3.9+
- Google AI API Key ([Get one from Google AI Studio](https://aistudio.google.com/app/apikey))

## Setup and Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/codeaudit.git
cd codeaudit
```

### 2. Create a Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Your API Key

Create a `.env` file in the project root:

```bash
# Copy the example file
cp .env.example .env
```

Edit `.env` and add your Google AI API key:

```
GEMINI_API_KEY=your_api_key_here
```

Alternatively, set the environment variable directly:

```bash
# On macOS/Linux:
export GEMINI_API_KEY="your_api_key_here"

# On Windows (Command Prompt):
set GEMINI_API_KEY=your_api_key_here

# On Windows (PowerShell):
$env:GEMINI_API_KEY="your_api_key_here"
```

## Usage

### Basic Usage

Analyze the current directory:

```bash
python codeaudit.py .
```

Analyze a specific directory:

```bash
python codeaudit.py /path/to/project
```

Analyze a single file:

```bash
python codeaudit.py app.py
```

### Command-Line Options

```bash
python codeaudit.py [PATH] [OPTIONS]
```

**Arguments:**
- `PATH` - Path to analyze (file or directory, default: current directory)

**Options:**
- `--config FILE`, `-c FILE` - Path to configuration file (.codeaudit.yml)
- `--recursive`, `-r` - Recursively analyze subdirectories
- `--output FILE`, `-o FILE` - Save results to JSON file
- `--max-files N` - Maximum number of files to analyze
- `--no-cache` - Disable result caching
- `--no-progress` - Disable progress bar display

### Examples

Analyze a project and save results:

```bash
python codeaudit.py ./my-project --output report.json
```

Analyze up to 50 files:

```bash
python codeaudit.py ./large-project --max-files 50
```

Analyze with custom configuration:

```bash
python codeaudit.py . --config my-config.yml
```

Disable caching for fresh analysis:

```bash
python codeaudit.py . --no-cache
```

## Configuration

CodeAudit supports configuration files for customizing analysis behavior. Configuration can be specified at multiple levels with automatic merging.

### Configuration Priority

Configuration is loaded and merged in the following order (highest to lowest priority):

1. **Command-line arguments** - Direct CLI flags (e.g., `--max-files 50`)
2. **Explicit config file** - Specified with `--config` flag
3. **Project config** - `.codeaudit.yml` in project root or parent directories
4. **User config** - `~/.config/codeaudit/config.yml`
5. **Default values** - Built-in defaults

### Configuration File Locations

**Project-level configuration** (`.codeaudit.yml`):
Place in your project root directory. CodeAudit searches up to 5 parent directories.

```bash
# Create sample config in project root
python -c "from config import ConfigLoader; from pathlib import Path; ConfigLoader.create_sample_config(Path('.codeaudit.yml'))"
```

**User-level configuration** (`~/.config/codeaudit/config.yml`):
Global settings for all your projects.

```bash
# Create user-level config
mkdir -p ~/.config/codeaudit
python -c "from config import ConfigLoader; from pathlib import Path; ConfigLoader.create_sample_config(Path.home() / '.config' / 'codeaudit' / 'config.yml')"
```

### Configuration Options

```yaml
# Maximum number of files to analyze per run
max_files: 20

# Recursively scan subdirectories
recursive: true

# Output file path for JSON results (optional)
output_file: "codeaudit-results.json"

# Enable result caching (recommended for performance)
enable_cache: true

# Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL
log_level: INFO

# Programming languages to analyze
languages:
  - python
  - javascript
  - typescript
  - java
  - go
  - rust
  - php
  - ruby

# Minimum severity to report: low, medium, high
severity_threshold: low

# File and directory patterns to ignore
ignore_patterns:
  - node_modules
  - .git
  - __pycache__
  - venv
  - .venv
  - dist
  - build
  - .pytest_cache
  - htmlcov
  - "*.min.js"
  - "*.bundle.js"

# Maximum file size to analyze (in MB)
max_file_size_mb: 1.0

# Analysis timeout per file (in seconds)
analysis_timeout: 60
```

### Example Configurations

**Minimal Configuration:**
```yaml
max_files: 50
log_level: DEBUG
```

**Security-Focused Configuration:**
```yaml
severity_threshold: high
languages:
  - python
  - javascript
ignore_patterns:
  - tests
  - node_modules
  - "*.test.js"
```

**Large Project Configuration:**
```yaml
max_files: 100
max_file_size_mb: 5.0
enable_cache: true
recursive: true
ignore_patterns:
  - node_modules
  - vendor
  - build
  - dist
  - "*.min.*"
```

### Using Configuration Files

**With project config:**
```bash
# Create .codeaudit.yml in project root
cat > .codeaudit.yml <<EOF
max_files: 50
log_level: DEBUG
languages:
  - python
  - javascript
EOF

# Run analysis (automatically uses .codeaudit.yml)
python codeaudit.py .
```

**With explicit config:**
```bash
# Use specific configuration file
python codeaudit.py . --config custom-config.yml
```

**Override config with CLI:**
```bash
# Config file sets max_files: 20, but CLI overrides to 100
python codeaudit.py . --max-files 100
```

## Logging Configuration

CodeAudit includes structured logging for debugging and integration with CI/CD pipelines.

### Setting Log Level

Control logging verbosity with the `LOG_LEVEL` environment variable:

```bash
# On macOS/Linux:
export LOG_LEVEL=DEBUG
python codeaudit.py .

# On Windows (Command Prompt):
set LOG_LEVEL=DEBUG
python codeaudit.py .

# On Windows (PowerShell):
$env:LOG_LEVEL="DEBUG"
python codeaudit.py .
```

### Available Log Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `DEBUG` | Detailed diagnostic information | Troubleshooting, development |
| `INFO` | General informational messages | Default, production use |
| `WARNING` | Warning messages for unexpected situations | Monitoring issues |
| `ERROR` | Error messages for serious problems | Critical failures |
| `CRITICAL` | Critical error messages | System failures |

### Examples

**Debug mode** (verbose output for troubleshooting):
```bash
LOG_LEVEL=DEBUG python codeaudit.py .
```

**Info mode** (standard output, default):
```bash
LOG_LEVEL=INFO python codeaudit.py .
```

**Error mode** (only show errors):
```bash
LOG_LEVEL=ERROR python codeaudit.py .
```

### Logging in .env File

Add to your `.env` file for persistent configuration:

```
# Logging Configuration
LOG_LEVEL=INFO
```

## Supported Languages and Frameworks

### Programming Languages

- Python (.py)
- JavaScript (.js)
- TypeScript (.ts, .tsx)
- Java (.java)
- C/C++ (.c, .cpp)
- C# (.cs)
- Go (.go)
- Rust (.rs)
- PHP (.php)
- Ruby (.rb)
- Swift (.swift)
- Kotlin (.kt)
- Scala (.scala)
- Dart (.dart)

### Detected Frameworks

CodeAudit automatically detects and applies framework-specific security checks:

**Python:** Django, Flask, FastAPI, Tornado, Pyramid, SQLAlchemy, Celery

**JavaScript/TypeScript:** Express, React, Vue, Angular, Next.js, Nest.js

**Java:** Spring, Hibernate, Struts, JSF

**Go:** Gin, Echo, Fiber

**Ruby:** Rails, Sinatra

**PHP:** Laravel, Symfony, CodeIgniter

## Output Format

### Console Output

```
🔍 AI-Powered Code Analyzer
Analyzing path: ./my-project
Files to analyze: 15

🔍 Analyzing 15/15: database.py

============================================================
CODE ANALYSIS COMPLETE
============================================================

📊 Summary:
   Files analyzed: 15
   Total issues found: 8
   🔴 High severity: 3
   🟡 Medium severity: 4
   🟢 Low severity: 1

📁 ./src/auth.py
   📈 Maintainability: 7/10 - Good structure but could improve error handling
    - Line 42: [HIGH] SQL Injection vulnerability via string concatenation
      💡 Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### JSON Output

Use `--output report.json` to save structured results:

```json
{
  "file": "./src/auth.py",
  "issues": [
    {
      "type": "security",
      "severity": "high",
      "line": 42,
      "description": "SQL Injection vulnerability via string concatenation",
      "suggestion": "Use parameterized queries",
      "fix": {
        "before_code": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
        "after_code": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "explanation": "Parameterized queries prevent SQL injection by separating SQL code from data, ensuring user input is always treated as data rather than executable code.",
        "references": [
          "https://owasp.org/www-community/attacks/SQL_Injection",
          "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"
        ]
      }
    }
  ],
  "summary": {
    "total_issues": 8,
    "high_severity": 3,
    "medium_severity": 4,
    "low_severity": 1,
    "maintainability_score": "7/10 - Good structure but could improve error handling"
  }
}
```

### Automated Fix Suggestions

CodeAudit now provides **automated fix suggestions** with before/after code examples for identified issues:

**Console Output with Fix:**
```
📁 ./src/auth.py
   📈 Maintainability: 7/10
    - Line 42: [HIGH] SQL Injection vulnerability via string concatenation
      💡 Use parameterized queries
      🔧 Automated Fix:
         Before:
           cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
         After:
           cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
         Why: Parameterized queries prevent SQL injection by separating SQL code from data
         References:
           - https://owasp.org/www-community/attacks/SQL_Injection
```

**Fix Suggestion Structure:**

Each fix includes:
- **before_code**: The vulnerable/problematic code snippet
- **after_code**: The corrected code with the fix applied
- **explanation**: Detailed explanation of why the fix resolves the issue
- **references**: Array of URLs to documentation, security advisories, or best practices

Fix suggestions are language-aware and follow each language's best practices and idioms.

## Development

### Testing

CodeAudit has a comprehensive test suite with **126 tests** achieving **98% code coverage**.

#### Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt
```

This installs:
- `pytest` - Testing framework
- `pytest-cov` - Coverage plugin
- `pytest-mock` - Mocking utilities
- `pylint` - Code linter
- `mypy` - Static type checker

#### Running Tests

**Run all tests:**
```bash
python -m pytest tests/
```

**Run with verbose output:**
```bash
python -m pytest tests/ -v
```

**Run specific test file:**
```bash
python -m pytest tests/test_logging.py
```

**Run specific test:**
```bash
python -m pytest tests/test_cache.py::TestResultCache::test_cache_set_and_get
```

**Run tests by marker:**
```bash
# Run only unit tests
python -m pytest -m unit

# Run only integration tests
python -m pytest -m integration

# Skip slow tests
python -m pytest -m "not slow"
```

#### Coverage Reports

**Generate HTML coverage report:**
```bash
python -m pytest tests/ --cov=. --cov-report=html
```

This creates an interactive HTML report in `htmlcov/index.html` showing:
- Line-by-line coverage
- Branch coverage
- Missing lines highlighted in red

**Terminal coverage report:**
```bash
python -m pytest tests/ --cov=. --cov-report=term-missing
```

Shows coverage summary with line numbers of missing coverage.

**Current Coverage Stats:**
- **Total Coverage**: 98%
- **Total Tests**: 126
- **Branch Coverage**: Enabled
- **Coverage Target**: >95%

#### Test Structure

Tests are organized by module:

```
tests/
├── conftest.py              # Shared fixtures
├── test_cache.py            # Cache system tests (15 tests)
├── test_codeaudit_core.py   # Core analyzer tests (24 tests)
├── test_file_discovery.py   # File scanning tests (19 tests)
├── test_framework_detection.py  # Framework detection (24 tests)
├── test_logging.py          # Logging tests (15 tests)
├── test_prompt_engine.py    # Prompt system tests (21 tests)
└── test_security.py         # Security tests (8 tests)
```

#### Writing Tests

**Test Naming Convention:**
- Test files: `test_<module_name>.py`
- Test classes: `Test<ClassName>`
- Test functions: `test_<description>`

**Example Test:**
```python
def test_analyze_code_file_success(self, mock_env_with_api_key, mock_gemini_api, temp_test_file):
    """Test successful code analysis."""
    analyzer = CodeAnalyzer()
    result = analyzer.analyze_code_file(temp_test_file)

    assert 'issues' in result
    assert 'summary' in result
    assert isinstance(result['issues'], list)
```

**Available Fixtures (from conftest.py):**

| Fixture | Description | Usage |
|---------|-------------|-------|
| `temp_test_file` | Creates temporary Python file with vulnerabilities | Testing file analysis |
| `mock_gemini_api` | Mocks Gemini AI API responses | Avoiding real API calls |
| `mock_env_with_api_key` | Sets GEMINI_API_KEY in environment | Testing initialization |
| `sample_python_code` | Python code with known vulnerabilities | Testing detection |
| `sample_javascript_code` | JavaScript code with vulnerabilities | Testing multi-language |
| `mock_prompt_engine` | Mocks PromptEngine | Testing without templates |
| `mock_framework_detector` | Mocks FrameworkDetector | Testing without detection |
| `tmp_path` | Pytest built-in temporary directory | File system tests |

**Using Fixtures:**
```python
def test_cache_set_and_get(self, tmp_path):
    """Test storing and retrieving cache."""
    cache = ResultCache(cache_dir=tmp_path / "cache")

    test_file = tmp_path / "test.py"
    test_file.write_text("def hello(): pass")

    # Store result
    analysis_result = {'file': str(test_file), 'issues': []}
    cache.set(test_file, analysis_result)

    # Retrieve result
    cached_result = cache.get(test_file)
    assert cached_result == analysis_result
```

**Mocking External Dependencies:**
```python
from unittest.mock import Mock, patch

def test_api_call_failure(self, mock_env_with_api_key):
    """Test handling of API failures."""
    with patch('google.generativeai.GenerativeModel') as mock_model:
        mock_model.side_effect = Exception("API Error")

        with pytest.raises(SystemExit):
            CodeAnalyzer()
```

#### Test Configuration

The `pytest.ini` file configures test behavior:

```ini
[pytest]
# Test discovery
python_files = test_*.py
python_classes = Test*
python_functions = test_*

# Default options
addopts =
    -v                    # Verbose output
    --strict-markers      # Error on unknown markers
    --tb=short           # Short traceback format
    --cov=.              # Coverage for all modules
    --cov-report=html    # HTML coverage report
    --cov-report=term-missing  # Show missing lines
    --cov-branch         # Branch coverage

# Test markers
markers =
    unit: Unit tests
    integration: Integration tests
    slow: Slow running tests
    logging: Tests for logging functionality
```

### Code Quality Checks

CodeAudit maintains high code quality standards:

```bash
# Run pylint (target score: 10.0/10)
pylint codeaudit.py

# Run mypy type checking
mypy codeaudit.py

# Run all quality checks together
pylint codeaudit.py && mypy codeaudit.py && python -m pytest tests/
```

**Quality Standards:**
- **Pylint Score**: 10.0/10 (perfect score)
- **Mypy**: No type errors
- **Test Coverage**: >95%
- **All Tests**: Must pass

### Configuration Files

- `.pylintrc` - Pylint configuration (strict rules)
- `mypy.ini` - MyPy type checking configuration
- `pytest.ini` - Pytest and coverage configuration
- `requirements-dev.txt` - Development dependencies

## Important Considerations

### Security

- **Never commit API keys** to version control
- Use `.env` files (add `.env` to `.gitignore`)
- Set file size limits to prevent DoS (default: 1MB per file)
- Validate all file paths to prevent directory traversal

### Cost Awareness

Google AI API calls are **not free**. Be mindful of:
- Number of files scanned (use `--max-files` to limit)
- File sizes (large files = higher costs)
- API rate limits and quotas

### Limitations

- **Not a replacement** for professional security audits
- **False positives/negatives** may occur with AI analysis
- **Use results as a starting point** for manual investigation
- **Combine with other tools** (SAST, DAST, human review)

## Architecture

### Prompt Template System

CodeAudit uses a sophisticated template-based prompt system that intelligently selects the most appropriate security analysis prompts based on the code being analyzed.

#### Template Directory Structure

```
prompts/
├── base_prompt.j2              # Default fallback template
├── languages/                  # Language-specific templates
│   ├── python.j2
│   ├── javascript.j2
│   ├── typescript.j2
│   ├── java.j2
│   ├── cpp.j2
│   ├── csharp.j2
│   ├── go.j2
│   ├── rust.j2
│   ├── php.j2
│   ├── ruby.j2
│   ├── swift.j2
│   ├── kotlin.j2
│   ├── scala.j2
│   └── dart.j2
├── frameworks/                 # Framework-specific templates
│   ├── django.j2              # Django-specific security checks
│   ├── flask.j2               # Flask security patterns
│   ├── fastapi.j2             # FastAPI vulnerabilities
│   ├── react.j2               # React security issues
│   ├── express.j2             # Express.js security
│   └── spring.j2              # Spring Boot security
└── threat_models/             # Threat model-specific templates
    ├── web_security.j2        # OWASP Top 10 web vulnerabilities
    ├── api_security.j2        # API-specific threats (BOLA, etc.)
    ├── mobile_security.j2     # Mobile app security
    ├── cryptography.j2        # Crypto vulnerabilities
    ├── auth.j2                # Authentication/authorization
    ├── database.j2            # SQL/NoSQL injection
    ├── cloud.j2               # Cloud security (AWS/Azure/GCP)
    └── supply_chain.j2        # Dependency vulnerabilities
```

#### Template Selection Priority

CodeAudit selects the most specific template available using this priority order:

1. **Framework-specific template** (highest priority)
   - Used when a framework is detected (e.g., Django, React)
   - Provides framework-specific security checks
   - Example: `frameworks/django.j2` for Django code

2. **Language-specific template**
   - Used based on file extension
   - Provides language-specific vulnerability patterns
   - Example: `languages/python.j2` for `.py` files

3. **Threat model template**
   - Used when specific threat models are requested
   - Provides focused security analysis
   - Example: `threat_models/api_security.j2` for API code

4. **Base template** (fallback)
   - Used when no specific template matches
   - Provides general security analysis
   - Example: `base_prompt.j2`

**Selection Examples:**

```python
# Django application (auth.py)
# Selects: frameworks/django.j2
# Includes: Django ORM injection, template injection, CSRF checks

# Plain Python file (utils.py)
# Selects: languages/python.j2
# Includes: Python-specific vulnerabilities, stdlib issues

# API endpoint (api.js) with Express detected
# Selects: frameworks/express.j2
# Includes: Express middleware, route security, input validation

# Generic TypeScript file (helpers.ts)
# Selects: languages/typescript.j2
# Includes: TypeScript type safety, async security
```

### Framework Detection

CodeAudit automatically detects frameworks using pattern matching:

**Detection Methods:**
- Import/require statements
- Package declarations
- Framework-specific decorators
- Configuration files
- Code patterns

**Detected Frameworks:**

| Language | Frameworks |
|----------|-----------|
| **Python** | Django, Flask, FastAPI, Tornado, Pyramid, SQLAlchemy, Celery |
| **JavaScript/TypeScript** | Express, React, Vue, Angular, Next.js, Nest.js |
| **Java** | Spring, Hibernate, Struts, JSF |
| **Go** | Gin, Echo, Fiber |
| **Ruby** | Rails, Sinatra |
| **PHP** | Laravel, Symfony, CodeIgniter |

**Framework-to-Threat-Model Mapping:**

When a framework is detected, relevant threat models are automatically applied:

```python
# Django detected → Applies threat models:
# - web_security (OWASP Top 10)
# - api_security (if API endpoints found)
# - database (ORM security)

# React detected → Applies threat models:
# - web_security (XSS, CSRF)
# - api_security (if fetch/axios found)
```

### Few-Shot Examples

CodeAudit provides curated vulnerability examples to guide AI analysis:

**Example Categories:**
- SQL Injection patterns
- XSS vulnerabilities
- Authentication bypasses
- Command injection risks
- Insecure deserialization
- Path traversal attacks

**Language-Specific Examples:**

Each language has tailored examples:
- Python: `eval()` abuse, pickle injection, SQL injection
- JavaScript: Prototype pollution, XSS, command injection
- Java: Deserialization, XXE, SQL injection

### Creating Custom Templates

You can create custom prompt templates for your specific needs.

#### Template Syntax

CodeAudit templates use **Jinja2** syntax with the following variables available:

| Variable | Type | Description | Example |
|----------|------|-------------|---------|
| `file_name` | str | Name of the file being analyzed | `auth.py` |
| `language` | str | Programming language | `python` |
| `code_content` | str | Full source code of the file | `def login(user):...` |
| `frameworks` | list | Detected frameworks | `['django', 'celery']` |
| `threat_models` | list | Active threat models | `['web_security', 'auth']` |
| `few_shot_examples` | list | Vulnerability examples | `[{title, code, fix}]` |
| `has_frameworks` | bool | Whether frameworks detected | `True` |
| `has_examples` | bool | Whether examples provided | `True` |

#### Creating a Language-Specific Template

Create `prompts/languages/your_language.j2`:

```jinja2
You are an expert {{ language }} security auditor. Analyze the following code for security vulnerabilities.

## {{ language|title }} Security Best Practices

### Common {{ language }} Vulnerabilities
- Describe language-specific security issues
- Include code examples
- Reference language documentation

{% if has_frameworks %}
## Detected Frameworks
Frameworks detected: {{ frameworks | join(', ') }}
{% endif %}

{% if has_examples %}
## Security Examples

{% for example in few_shot_examples %}
### Example {{ loop.index }}: {{ example.title }}
**Vulnerable Code:**
```{{ language }}
{{ example.vulnerable_code }}
```

**Issue:** {{ example.issue }}
**Fix:** {{ example.fix }}

{% endfor %}
{% endif %}

File: {{ file_name }}
Language: {{ language }}
Code:
{{ code_content }}

Output must be valid JSON following this schema:
{
    "issues": [
        {
            "type": "security|bug|performance|smell",
            "severity": "high|medium|low",
            "line": <line_number>,
            "description": "Clear description",
            "suggestion": "Brief fix suggestion",
            "cwe_id": "CWE identifier if applicable",
            "fix": {
                "before_code": "Vulnerable code snippet",
                "after_code": "Fixed code snippet",
                "explanation": "Why this fix works",
                "references": ["URL to docs"]
            }
        }
    ],
    "summary": {
        "total_issues": <number>,
        "high_severity": <number>,
        "medium_severity": <number>,
        "low_severity": <number>,
        "maintainability_score": "Score 1-10 with explanation"
    }
}
```

**Template Features:**
- ✅ Conditional sections with `{% if has_frameworks %}`
- ✅ Loop through examples with `{% for example in few_shot_examples %}`
- ✅ Variable substitution with `{{ variable }}`
- ✅ Filters like `{{ language|title }}` for formatting
- ✅ Must end with JSON schema for structured output

#### Creating a Framework-Specific Template

Create `prompts/frameworks/your_framework.j2`:

```jinja2
You are an expert {{ framework }} security auditor.

## {{ framework|title }} Security Vulnerabilities

### Framework-Specific Issues
- List common security issues in this framework
- Include configuration mistakes
- Cover framework-specific attack vectors

### {{ framework }} Security Best Practices
```{{ language }}
# Secure configuration example
# Show proper setup
```

### Common Mistakes
```{{ language }}
# Vulnerable code
# Example of what NOT to do
```

{% if has_examples %}
## Framework Security Examples
{% for example in few_shot_examples %}
### {{ example.title }}
{{ example.vulnerable_code }}
**Fix:** {{ example.fix }}
{% endfor %}
{% endif %}

File: {{ file_name }}
Framework: {{ framework }}
Code:
{{ code_content }}

[Include JSON schema here]
```

#### Creating a Threat Model Template

Create `prompts/threat_models/your_threat.j2`:

```jinja2
You are a security auditor specializing in {{ threat_model }} threats.

## {{ threat_model|title }} Threat Model

### Attack Vectors
- Describe specific attack vectors
- Include exploitation techniques
- Reference security standards (OWASP, CWE)

### Detection Patterns
- Code patterns indicating vulnerabilities
- Configuration mistakes
- Missing security controls

### Mitigation Strategies
- How to fix identified issues
- Security best practices
- Defense in depth approaches

File: {{ file_name }}
Language: {{ language }}
Threat Model: {{ threat_model }}
Code:
{{ code_content }}

[Include JSON schema here]
```

#### Template Best Practices

1. **Always include JSON schema** - Required for structured output
2. **Use conditional sections** - Check `has_frameworks`, `has_examples`
3. **Provide specific examples** - Show vulnerable and secure code
4. **Reference standards** - Link to OWASP, CWE, language docs
5. **Keep focused** - Template should focus on specific domain
6. **Use proper escaping** - Use `{% raw %}` for code that looks like Jinja2

**Escaping Template Syntax:**

If your template includes code examples that look like Jinja2 syntax (e.g., Django templates), wrap them in `{% raw %}`:

```jinja2
### Django Template Security
```django
{% raw %}
{# Correct Django template #}
<form method="post">
  {% csrf_token %}
  {{ form }}
</form>
{% endraw %}
```
```

This prevents Jinja2 from trying to process Django template tags.

#### Testing Custom Templates

After creating a custom template, test it:

```python
from prompts.template_engine import PromptEngine

# Test language template
engine = PromptEngine()
prompt = engine.get_prompt(
    language='your_language',
    code_content='def test(): pass',
    file_name='test.ext',
    frameworks=[],
    threat_models=[],
    few_shot_examples=[]
)
print(prompt)  # Should see your template rendered

# Test framework template
prompt = engine.get_prompt(
    language='python',
    code_content='from your_framework import app',
    file_name='app.py',
    frameworks=['your_framework'],
    threat_models=[],
    few_shot_examples=[]
)
print(prompt)  # Should prioritize framework template
```

#### Example: Creating a Golang Template

```jinja2
You are an expert Go security auditor. Analyze the following Go code for security vulnerabilities.

## Go-Specific Security Vulnerabilities

### Memory Safety Issues
- **Unsafe package usage**: Using `unsafe.Pointer` without proper validation
- **Race conditions**: Concurrent map access without synchronization
- **Buffer overflows**: Slice bounds not checked

### Input Validation
- **SQL Injection**: String concatenation in database queries
- **Command Injection**: Using `os/exec` with unsanitized input
- **Path Traversal**: File operations without path sanitization

### Cryptography
- **Weak random**: Using `math/rand` instead of `crypto/rand`
- **Weak hashing**: MD5, SHA1 for security purposes
- **Hardcoded secrets**: API keys in source code

## Secure Go Code Examples

### SQL Injection Prevention
```go
// VULNERABLE
db.Query("SELECT * FROM users WHERE id = " + userID)

// SECURE
db.Query("SELECT * FROM users WHERE id = $1", userID)
```

### Command Injection Prevention
```go
// VULNERABLE
exec.Command("sh", "-c", "ls " + userInput)

// SECURE
exec.Command("ls", userInput)  // Separate arguments
```

{% if has_frameworks %}
## Detected Frameworks
Go frameworks detected: {{ frameworks | join(', ') }}
{% endif %}

{% if has_examples %}
## Go Security Examples

{% for example in few_shot_examples %}
### Example {{ loop.index }}: {{ example.title }}
**Vulnerable Code:**
```go
{{ example.vulnerable_code }}
```

**Issue:** {{ example.issue }}
**Fix:** {{ example.fix }}

{% endfor %}
{% endif %}

File: {{ file_name }}
Language: Go
Code:
{{ code_content }}

JSON Schema:
{
    "issues": [
        {
            "type": "security|bug|performance|smell",
            "severity": "high|medium|low",
            "line": <line_number>,
            "description": "Clear description with Go-specific context",
            "suggestion": "Brief one-line suggestion.",
            "cwe_id": "CWE identifier if applicable",
            "fix": {
                "before_code": "Go code showing the vulnerability",
                "after_code": "Secure Go code following best practices",
                "explanation": "Detailed explanation referencing Go documentation",
                "references": ["Optional array of URLs to Go docs, security guides"]
            }
        }
    ],
    "summary": {
        "total_issues": <number>,
        "high_severity": <number>,
        "medium_severity": <number>,
        "low_severity": <number>,
        "maintainability_score": "Score 1-10 with explanation"
    }
}
```

Save this as `prompts/languages/go.j2` and CodeAudit will automatically use it for `.go` files.

#### Template Variables Reference

**Complete list of available variables:**

```python
{
    'file_name': 'auth.py',           # File being analyzed
    'language': 'python',              # Programming language
    'code_content': '...',             # Full source code
    'frameworks': ['django'],          # Detected frameworks list
    'threat_models': ['web_security'], # Active threat models list
    'few_shot_examples': [             # Vulnerability examples
        {
            'title': 'SQL Injection in Django',
            'vulnerable_code': 'User.objects.raw(f"...")',
            'issue': 'String interpolation in SQL',
            'fix': 'Use parameterized queries'
        }
    ],
    'has_frameworks': True,            # Helper boolean
    'has_examples': True               # Helper boolean
}
```

#### Extending the Framework Detector

To add custom framework detection patterns, edit `framework_detector.py`:

```python
FRAMEWORK_PATTERNS = {
    'python': {
        'your_framework': [
            r'from your_framework import',
            r'import your_framework',
        ],
    },
}

FRAMEWORK_TO_THREAT_MODEL = {
    'your_framework': ['web_security', 'custom_threat'],
}
```

This makes CodeAudit automatically:
1. Detect your framework when patterns match
2. Select your framework template (`frameworks/your_framework.j2`)
3. Apply relevant threat models

## Troubleshooting

### API Key Issues

```
Error: GEMINI_API_KEY environment variable not found
```

**Solution:** Set the `GEMINI_API_KEY` environment variable or create a `.env` file.

### Module Import Errors

```
ModuleNotFoundError: No module named 'google.generativeai'
```

**Solution:** Install dependencies: `pip install -r requirements.txt`

### Logging Not Working

**Problem:** No log output visible

**Solution:** Set `LOG_LEVEL=DEBUG` to see all logging output

### File Size Limit

```
File skipped: Exceeds size limit of 1MB
```

**Solution:** This is a safety feature. Large files are skipped to prevent API timeouts and excessive costs.

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `pytest tests/`
2. Code quality checks pass: `pylint codeaudit.py` (score 10.0/10)
3. Type checking passes: `mypy codeaudit.py`
4. Add tests for new features
5. Update documentation

## License

MIT License - See LICENSE file for details

## Support

- GitHub Issues: [Report bugs or request features](https://github.com/yourusername/codeaudit/issues)
- Documentation: [Full documentation](https://github.com/yourusername/codeaudit/wiki)

## Acknowledgments

- Powered by Google Gemini 2.5 Flash
- Built with Python, Jinja2, and colorama
- Inspired by modern SAST tools and AI-assisted development
