"""
Configuration management for CodeAudit.

Supports loading configuration from multiple sources:
1. Project-level: .codeaudit.yml in current directory
2. User-level: ~/.config/codeaudit/config.yml
3. Command-line arguments (override config files)

Configuration is validated and merged with defaults.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class CodeAuditConfig:
    """Configuration settings for CodeAudit.

    Attributes:
        max_files: Maximum number of files to analyze
        recursive: Whether to recursively scan directories
        output_file: Path to JSON output file
        enable_cache: Whether to enable result caching
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        languages: List of programming languages to analyze
        severity_threshold: Minimum severity to report (low, medium, high)
        ignore_patterns: List of file/directory patterns to ignore
        max_file_size_mb: Maximum file size to analyze in MB
        analysis_timeout: Analysis timeout per file in seconds
    """

    max_files: int = 20
    recursive: bool = True
    output_file: Optional[str] = None
    enable_cache: bool = True
    log_level: str = "INFO"
    languages: List[str] = field(default_factory=lambda: [
        "python", "javascript", "typescript", "java", "go", "rust"
    ])
    severity_threshold: str = "low"
    ignore_patterns: List[str] = field(default_factory=lambda: [
        "node_modules", ".git", "__pycache__", "venv", ".venv",
        "dist", "build", ".pytest_cache", "htmlcov"
    ])
    max_file_size_mb: float = 1.0
    analysis_timeout: int = 60

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        self.validate()

    def validate(self) -> None:
        """Validate configuration values.

        Raises:
            ValueError: If configuration values are invalid
        """
        # Validate max_files
        if self.max_files <= 0:
            raise ValueError(f"max_files must be positive, got {self.max_files}")

        # Validate log_level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level.upper() not in valid_log_levels:
            raise ValueError(
                f"log_level must be one of {valid_log_levels}, got '{self.log_level}'"
            )
        self.log_level = self.log_level.upper()

        # Validate severity_threshold
        valid_severities = ["low", "medium", "high"]
        if self.severity_threshold.lower() not in valid_severities:
            raise ValueError(
                f"severity_threshold must be one of {valid_severities}, "
                f"got '{self.severity_threshold}'"
            )
        self.severity_threshold = self.severity_threshold.lower()

        # Validate max_file_size_mb
        if self.max_file_size_mb <= 0:
            raise ValueError(
                f"max_file_size_mb must be positive, got {self.max_file_size_mb}"
            )

        # Validate analysis_timeout
        if self.analysis_timeout <= 0:
            raise ValueError(
                f"analysis_timeout must be positive, got {self.analysis_timeout}"
            )

        logger.debug("Configuration validated successfully")

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary.

        Returns:
            Dictionary representation of configuration
        """
        return {
            'max_files': self.max_files,
            'recursive': self.recursive,
            'output_file': self.output_file,
            'enable_cache': self.enable_cache,
            'log_level': self.log_level,
            'languages': self.languages,
            'severity_threshold': self.severity_threshold,
            'ignore_patterns': self.ignore_patterns,
            'max_file_size_mb': self.max_file_size_mb,
            'analysis_timeout': self.analysis_timeout
        }


class ConfigLoader:
    """Load and merge configuration from multiple sources."""

    PROJECT_CONFIG_FILE = ".codeaudit.yml"
    USER_CONFIG_FILE = Path.home() / ".config" / "codeaudit" / "config.yml"

    @staticmethod
    def load_yaml_file(file_path: Path) -> Dict[str, Any]:
        """Load configuration from YAML file.

        Args:
            file_path: Path to YAML configuration file

        Returns:
            Dictionary of configuration values

        Raises:
            yaml.YAMLError: If YAML parsing fails
            IOError: If file cannot be read
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)

            if config_data is None:
                logger.warning("Configuration file is empty: %s", file_path)
                return {}

            if not isinstance(config_data, dict):
                raise ValueError(
                    f"Configuration file must contain a YAML mapping, got {type(config_data)}"
                )

            logger.info("Loaded configuration from: %s", file_path)
            return config_data

        except yaml.YAMLError as e:
            logger.error("Invalid YAML in config file %s: %s", file_path, e)
            raise
        except IOError as e:
            logger.error("Could not read config file %s: %s", file_path, e)
            raise

    @staticmethod
    def find_project_config() -> Optional[Path]:
        """Find project-level configuration file.

        Searches for .codeaudit.yml in current directory and parent directories.

        Returns:
            Path to project config file, or None if not found
        """
        current_dir = Path.cwd()

        # Search up to 5 parent directories
        for _ in range(5):
            config_path = current_dir / ConfigLoader.PROJECT_CONFIG_FILE
            if config_path.exists():
                logger.debug("Found project config: %s", config_path)
                return config_path

            # Move to parent directory
            parent = current_dir.parent
            if parent == current_dir:  # Reached root
                break
            current_dir = parent

        return None

    @classmethod
    def load(cls, config_file: Optional[Path] = None) -> CodeAuditConfig:
        """Load configuration from all sources and merge.

        Configuration priority (highest to lowest):
        1. Explicitly provided config_file parameter
        2. Project-level .codeaudit.yml
        3. User-level ~/.config/codeaudit/config.yml
        4. Default values

        Args:
            config_file: Optional explicit configuration file path

        Returns:
            CodeAuditConfig with merged configuration

        Raises:
            ValueError: If configuration is invalid
        """
        # Start with empty config dict
        merged_config: Dict[str, Any] = {}

        # 1. Load user-level config if exists
        if cls.USER_CONFIG_FILE.exists():
            try:
                user_config = cls.load_yaml_file(cls.USER_CONFIG_FILE)
                merged_config.update(user_config)
                logger.debug("Loaded user config: %d settings", len(user_config))
            except Exception as e:
                logger.warning("Failed to load user config: %s", e)

        # 2. Load project-level config if exists (overrides user config)
        project_config_path = cls.find_project_config()
        if project_config_path:
            try:
                project_config = cls.load_yaml_file(project_config_path)
                merged_config.update(project_config)
                logger.debug("Loaded project config: %d settings", len(project_config))
            except Exception as e:
                logger.warning("Failed to load project config: %s", e)

        # 3. Load explicit config file if provided (highest priority)
        if config_file:
            if not config_file.exists():
                raise ValueError(f"Configuration file not found: {config_file}")

            try:
                explicit_config = cls.load_yaml_file(config_file)
                merged_config.update(explicit_config)
                logger.debug("Loaded explicit config: %d settings", len(explicit_config))
            except Exception as e:
                logger.error("Failed to load config from %s: %s", config_file, e)
                raise

        # Create CodeAuditConfig with merged values (defaults filled in automatically)
        try:
            config = CodeAuditConfig(**merged_config)
            logger.info("Configuration loaded successfully")
            return config
        except TypeError as e:
            logger.error("Invalid configuration parameters: %s", e)
            raise ValueError(f"Invalid configuration: {e}") from e

    @classmethod
    def save(cls, config: CodeAuditConfig, file_path: Path) -> None:
        """Save configuration to YAML file.

        Args:
            config: Configuration to save
            file_path: Path to save configuration file
        """
        # Create parent directory if needed
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Convert config to dict
        config_dict = config.to_dict()

        # Write to YAML file
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.safe_dump(config_dict, f, default_flow_style=False, sort_keys=False)

        logger.info("Saved configuration to: %s", file_path)

    @classmethod
    def create_sample_config(cls, file_path: Path) -> None:
        """Create a sample configuration file with comments.

        Args:
            file_path: Path to create sample configuration file
        """
        sample_config = """# CodeAudit Configuration File
# Place this file as .codeaudit.yml in your project root
# or ~/.config/codeaudit/config.yml for user-level settings

# Maximum number of files to analyze per run
max_files: 20

# Recursively scan subdirectories
recursive: true

# Output file path for JSON results (optional)
# output_file: "codeaudit-results.json"

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
"""

        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(sample_config, encoding='utf-8')
        logger.info("Created sample configuration file: %s", file_path)
