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
- `--recursive`, `-r` - Recursively analyze subdirectories (default: True)
- `--output FILE`, `-o FILE` - Save results to JSON file
- `--max-files N` - Maximum number of files to analyze (default: 20)

### Examples

Analyze a project and save results:

```bash
python codeaudit.py ./my-project --output report.json
```

Analyze up to 50 files:

```bash
python codeaudit.py ./large-project --max-files 50
```

Analyze a single directory (non-recursive):

```bash
python codeaudit.py ./src --recursive=false
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
      "suggestion": "Use parameterized queries: cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
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

## Development

### Running Tests

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests with coverage
pytest tests/

# Run specific test file
pytest tests/test_logging.py
```

### Code Quality Checks

CodeAudit maintains high code quality standards:

```bash
# Run pylint (target score: 10.0/10)
pylint codeaudit.py

# Run mypy type checking
mypy codeaudit.py

# Run all tests with coverage
pytest tests/ --cov=. --cov-report=html
```

### Configuration Files

- `.pylintrc` - Pylint configuration
- `mypy.ini` - MyPy type checking configuration
- `pytest.ini` - Pytest and coverage configuration

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

### Prompt System

CodeAudit uses an intelligent prompt selection system:

1. **Framework-specific** prompts (e.g., `django.j2`)
2. **Language-specific** prompts (e.g., `python.j2`)
3. **Threat model** prompts (web, API, mobile, crypto)
4. **Base prompt** fallback

### Framework Detection

Automatic framework detection using pattern matching:
- Import statements
- Package declarations
- Framework-specific code patterns

### Few-Shot Examples

Provides curated vulnerability examples to guide AI analysis:
- SQL Injection patterns
- XSS vulnerabilities
- Authentication bypasses
- Command injection risks

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
