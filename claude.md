# Claude Code Instructions

> Project-specific guidelines for Claude Code when working in this repository

## Table of Contents
- [Issue Tracking with Beads](#issue-tracking-with-beads)
- [Python Strict Mode Protocol](#python-strict-mode-protocol)
- [Professional Coding Standards](#professional-coding-standards)
- [BD Issue Creation Requirements](#bd-issue-creation-requirements)
- [Pre-Close Checklist](#pre-close-checklist)

---

## Issue Tracking with Beads

**IMPORTANT:** For all work in this repository, you **MUST** use the beads issue tracker (`bd`).

- Use the `bd` command-line tool to create, manage, and close issues
- **DO NOT** use markdown files for to-do lists or work tracking
- All issues and bugs are tracked via `bd`

### What is bd?

**bd** (beads) is a dependency-aware issue tracker where issues chain together like beads.

### Quick Start

```bash
# Initialize bd in your project
bd init

# Initialize with custom prefix
bd init --prefix api
```

### Common Commands

#### Creating Issues

```bash
# Simple issue
bd create "Fix login bug"

# With priority and type
bd create "Add auth" -p 0 -t feature

# With description and assignee
bd create "Write tests" -d "Unit tests for auth" --assignee alice
```

#### Viewing Issues

```bash
# List all issues
bd list

# Filter by status
bd list --status open

# Filter by priority (0-4, where 0 is highest)
bd list --priority 0

# Show issue details
bd show bd-1
```

#### Managing Dependencies

```bash
# Add dependency (bd-2 blocks bd-1)
bd dep add bd-1 bd-2

# Visualize dependency tree
bd dep tree bd-1

# Detect circular dependencies
bd dep cycles
```

#### Finding Ready Work

```bash
# Show issues ready to work on
bd ready
```

> **Ready** = status is 'open' AND no blocking dependencies
> Perfect for agents to claim next work!

#### Updating Issues

```bash
# Update status
bd update bd-1 --status in_progress

# Update priority
bd update bd-1 --priority 0

# Assign to someone
bd update bd-1 --assignee bob
```

#### Closing Issues

```bash
# Close single issue
bd close bd-1

# Close multiple with reason
bd close bd-2 bd-3 --reason "Fixed in PR #42"
```

### Dependency Types

| Type | Description |
|------|-------------|
| `blocks` | Task B must complete before task A |
| `related` | Soft connection, doesn't block progress |
| `parent-child` | Epic/subtask hierarchical relationship |
| `discovered-from` | Auto-created when AI discovers related work |

### Database Location

bd automatically discovers your database in this order:

1. `--db /path/to/db.db` flag
2. `$BEADS_DB` environment variable
3. `.beads/*.db` in current directory or ancestors
4. `~/.beads/default.db` as fallback

### Agent Integration

bd is designed for AI-supervised workflows:

- ✅ Agents create issues when discovering new work
- ✅ `bd ready` shows unblocked work ready to claim
- ✅ Use `--json` flags for programmatic parsing
- ✅ Dependencies prevent agents from duplicating effort

### Git Workflow (Auto-Sync)

bd automatically keeps git in sync:

- ✅ Export to JSONL after CRUD operations (5s debounce)
- ✅ Import from JSONL when newer than DB (after git pull)
- ✅ Works seamlessly across machines and team members
- ✅ No manual export/import needed!

**Disable with:** `--no-auto-flush` or `--no-auto-import`

---

## Python Strict Mode Protocol

> **CRITICAL INSTRUCTION:** You often hallucinate Python library methods because you default to outdated training data. You must follow this strict protocol for ALL Python tasks.

### 1. Mandatory Context Gathering

Before writing any code, you **MUST** perform these checks:

1. **Check Python Version**
   ```bash
   python --version
   ```

2. **Check Library Versions**
   ```bash
   pip show <library_name>
   ```
   For any major dependency (e.g., pandas, pydantic, sqlalchemy)

3. **Scan Environment**
   Read `pyproject.toml` or `requirements.txt` if available

### 2. Anti-Hallucination Rules

- ❌ **No "Guesstimating" APIs:** Do not assume a method exists just because it "sounds right"
- ✅ **Verify Deprecations:** Check if your proposed syntax matches the *installed* version for libraries with frequent breaking changes (Pydantic V1 vs V2, Pandas 2.0, LangChain)
- ✅ **Docs First:** If unsure of a method signature, search for the *official documentation* for that specific version

### 3. Coding Standards (Strict)

Treat Python with the same rigor as Rust:

- **Type Hints Required:** All function signatures must have strict type hints
  ```python
  def fn(x: int) -> str:
  ```
  Use `typing.Optional` and `typing.Union` explicitly

- **Return Pydantic:** Prefer returning structured Pydantic models over loose dictionaries

- **No Silent Failures:** Do not use bare `try/except` blocks (`except: pass`). Catch specific exceptions only

---

## Professional Coding Standards

### Security

| Area | Requirement |
|------|-------------|
| **Input Validation** | Validate and sanitize ALL user inputs and external data |
| **Secrets Management** | NEVER hardcode API keys, passwords, or tokens |
| **Environment Variables** | Use `.env` files with `python-dotenv` |
| **SQL Injection** | Use parameterized queries, never string concatenation |
| **Path Traversal** | Validate file paths to prevent directory traversal attacks |
| **Dependencies** | Be aware of known vulnerabilities in dependencies |
| **OWASP Top 10** | Consider common web vulnerabilities (XSS, CSRF, etc.) |
| **Error Messages** | Don't expose sensitive info in error messages/logs |

**Environment Setup:**
```python
# .env file
API_KEY=your_secret_key

# .gitignore
.env
```

### Code Quality & Linting

#### PEP 8 Compliance
Follow Python style guide strictly

#### Type Hints
Add type hints to ALL function signatures and class attributes
```python
from typing import List, Dict, Optional
```

Run mypy to verify type correctness:
```bash
mypy src/ main.py
```

#### Linting
Code MUST pass pylint and mypy before closing issues:
```bash
pylint src/ main.py
mypy src/ main.py
```

#### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Functions & Variables | `snake_case` | `calculate_total()` |
| Classes | `PascalCase` | `UserAccount` |
| Constants | `UPPER_CASE` | `MAX_RETRY_COUNT` |

- Use meaningful, descriptive names
- Avoid single letters except in comprehensions

#### Code Organization

- **Group imports:** standard library, third-party, local
- **Use isort** for import sorting
- **Keep functions focused:** under 50 lines when possible
- **DRY Principle:** Don't Repeat Yourself - extract common code
- **Complexity:** Avoid deeply nested code (max 4 levels of indentation)

### Testing

#### Unit Tests Requirements

- Write tests for ALL new functions and classes
- Use `pytest` framework
- Place tests in `tests/` directory
- Name test files: `test_<module_name>.py`

#### Test Coverage

- Aim for **80%+** code coverage
- Test edge cases and error conditions
- Test both success and failure paths

#### Best Practices

- **Mocking:** Mock external dependencies (API calls, file I/O, database)
- **Fixtures:** Use pytest fixtures for common test data
- **Assertions:** Use descriptive assertion messages

#### Running Tests

All tests MUST pass before closing issues:
```bash
pytest tests/
```

### Documentation & Maintainability

#### Docstrings (REQUIRED)

Required for ALL modules, classes, and functions using Google or NumPy format:

```python
def process_user(user_id: int, validate: bool = True) -> dict:
    """Process user data and return profile.

    Args:
        user_id: The unique identifier for the user
        validate: Whether to validate user data before processing

    Returns:
        A dictionary containing user profile information

    Raises:
        ValueError: If user_id is invalid
        UserNotFoundError: If user doesn't exist
    """
```

#### Logging

Use `logging` module, NOT print statements:

```python
import logging

logger = logging.getLogger(__name__)
logger.info("Processing user %s", user_id)
```

**Logging Levels:**
- `DEBUG` - Detailed diagnostic information
- `INFO` - General informational messages
- `WARNING` - Warning messages
- `ERROR` - Error messages
- `CRITICAL` - Critical error messages

#### Error Handling

- Use specific exceptions, not bare `except:`
- Provide clear error messages
- Log exceptions with traceback

#### README Updates

Update `README.md` when adding features or changing setup

---

## BD Issue Creation Requirements

When creating bd issues for new features or bug fixes, **ALWAYS** include these subtasks:

### 1. Implementation Subtask
- Main coding work with security considerations
- Type hints added
- Input validation where needed

### 2. Testing Subtask
- Unit tests written
- Edge cases covered
- Tests passing (`pytest tests/`)

### 3. Code Quality Subtask
- pylint passing (score >= 10.0)
- mypy passing (no type errors)
- Docstrings added/updated

### 4. Documentation Subtask
- Function/class docstrings complete
- README updated if needed
- Comments added for complex logic

### 5. Security Review Subtask (if applicable)
- Input validation verified
- No hardcoded secrets
- Error handling doesn't expose sensitive data

### Example Issue Creation Workflow

```bash
# Create parent issue
bd create "Add user authentication feature" -p 0

# Create subtask issues
bd create "Implement auth logic with input validation" -p 1 \
  -d "Add authentication with type hints and security checks"

bd create "Write tests for authentication" -p 1 \
  -d "Unit tests with edge cases and mocking"

bd create "Lint and type-check auth code" -p 1 \
  -d "Run pylint and mypy, fix all issues"

bd create "Document authentication feature" -p 1 \
  -d "Add docstrings and update README"

# Add dependencies
bd dep add <parent-issue> <implementation-issue>
bd dep add <parent-issue> <testing-issue>
bd dep add <parent-issue> <linting-issue>
bd dep add <parent-issue> <docs-issue>
```

---

## Pre-Close Checklist

Before closing ANY issue, run this checklist:

```bash
# Code Quality
☐ Code passes pylint (pylint src/ main.py)
☐ Code passes mypy (mypy src/ main.py)
☐ All tests pass (pytest tests/)

# Documentation
☐ Type hints added to all functions
☐ Docstrings added/updated
☐ README updated if needed

# Security
☐ No hardcoded secrets or credentials
☐ Input validation for external data
☐ Error handling with specific exceptions
☐ Logging used instead of print
☐ Error messages don't expose sensitive data
```

---

**Remember:** Quality over speed. Follow these guidelines strictly to maintain code quality and security standards.
