"""
Tests for config.py module.
"""
# pylint: disable=unused-argument  # Fixtures needed for test setup

import pytest
import yaml
from pathlib import Path
from unittest.mock import patch

from config import CodeAuditConfig, ConfigLoader


class TestCodeAuditConfig:
    """Test CodeAuditConfig dataclass."""

    def test_initialization_with_defaults(self):
        """Test that CodeAuditConfig initializes with default values."""
        config = CodeAuditConfig()

        assert config.max_files == 20
        assert config.recursive is True
        assert config.output_file is None
        assert config.enable_cache is True
        assert config.log_level == "INFO"
        assert "python" in config.languages
        assert config.severity_threshold == "low"
        assert "node_modules" in config.ignore_patterns
        assert config.max_file_size_mb == 1.0
        assert config.analysis_timeout == 60

    def test_initialization_with_custom_values(self):
        """Test initialization with custom values."""
        config = CodeAuditConfig(
            max_files=50,
            recursive=False,
            output_file="report.json",
            enable_cache=False,
            log_level="DEBUG",
            languages=["python", "java"],
            severity_threshold="high",
            ignore_patterns=["test"],
            max_file_size_mb=2.0,
            analysis_timeout=120
        )

        assert config.max_files == 50
        assert config.recursive is False
        assert config.output_file == "report.json"
        assert config.enable_cache is False
        assert config.log_level == "DEBUG"
        assert config.languages == ["python", "java"]
        assert config.severity_threshold == "high"
        assert config.ignore_patterns == ["test"]
        assert config.max_file_size_mb == 2.0
        assert config.analysis_timeout == 120

    def test_validate_log_level_case_insensitive(self):
        """Test that log level validation is case-insensitive."""
        config = CodeAuditConfig(log_level="debug")
        assert config.log_level == "DEBUG"

        config = CodeAuditConfig(log_level="Info")
        assert config.log_level == "INFO"

    def test_validate_severity_threshold_case_insensitive(self):
        """Test that severity threshold validation is case-insensitive."""
        config = CodeAuditConfig(severity_threshold="HIGH")
        assert config.severity_threshold == "high"

        config = CodeAuditConfig(severity_threshold="Medium")
        assert config.severity_threshold == "medium"

    def test_validate_invalid_max_files(self):
        """Test validation fails for invalid max_files."""
        with pytest.raises(ValueError, match="max_files must be positive"):
            CodeAuditConfig(max_files=0)

        with pytest.raises(ValueError, match="max_files must be positive"):
            CodeAuditConfig(max_files=-1)

    def test_validate_invalid_log_level(self):
        """Test validation fails for invalid log level."""
        with pytest.raises(ValueError, match="log_level must be one of"):
            CodeAuditConfig(log_level="INVALID")

    def test_validate_invalid_severity_threshold(self):
        """Test validation fails for invalid severity threshold."""
        with pytest.raises(ValueError, match="severity_threshold must be one of"):
            CodeAuditConfig(severity_threshold="critical")

    def test_validate_invalid_max_file_size(self):
        """Test validation fails for invalid max file size."""
        with pytest.raises(ValueError, match="max_file_size_mb must be positive"):
            CodeAuditConfig(max_file_size_mb=0)

        with pytest.raises(ValueError, match="max_file_size_mb must be positive"):
            CodeAuditConfig(max_file_size_mb=-1.5)

    def test_validate_invalid_analysis_timeout(self):
        """Test validation fails for invalid analysis timeout."""
        with pytest.raises(ValueError, match="analysis_timeout must be positive"):
            CodeAuditConfig(analysis_timeout=0)

        with pytest.raises(ValueError, match="analysis_timeout must be positive"):
            CodeAuditConfig(analysis_timeout=-30)

    def test_to_dict(self):
        """Test conversion to dictionary."""
        config = CodeAuditConfig(
            max_files=30,
            log_level="WARNING"
        )

        config_dict = config.to_dict()

        assert config_dict['max_files'] == 30
        assert config_dict['log_level'] == "WARNING"
        assert isinstance(config_dict, dict)
        assert 'languages' in config_dict
        assert 'ignore_patterns' in config_dict


class TestConfigLoaderLoadYamlFile:
    """Test ConfigLoader.load_yaml_file method."""

    def test_load_valid_yaml_file(self, tmp_path):
        """Test loading a valid YAML configuration file."""
        config_file = tmp_path / "config.yml"
        config_data = {
            'max_files': 30,
            'recursive': False,
            'log_level': 'DEBUG'
        }
        config_file.write_text(yaml.safe_dump(config_data))

        loaded_config = ConfigLoader.load_yaml_file(config_file)

        assert loaded_config == config_data
        assert loaded_config['max_files'] == 30
        assert loaded_config['recursive'] is False

    def test_load_empty_yaml_file(self, tmp_path):
        """Test loading an empty YAML file."""
        config_file = tmp_path / "empty.yml"
        config_file.write_text("")

        loaded_config = ConfigLoader.load_yaml_file(config_file)

        assert loaded_config == {}

    def test_load_nonexistent_file_raises_error(self):
        """Test that loading nonexistent file raises IOError."""
        fake_file = Path("nonexistent.yml")

        with pytest.raises(IOError):
            ConfigLoader.load_yaml_file(fake_file)

    def test_load_invalid_yaml_raises_error(self, tmp_path):
        """Test that invalid YAML raises YAMLError."""
        config_file = tmp_path / "invalid.yml"
        config_file.write_text("invalid: yaml: content: [")

        with pytest.raises(yaml.YAMLError):
            ConfigLoader.load_yaml_file(config_file)

    def test_load_non_dict_yaml_raises_error(self, tmp_path):
        """Test that non-dictionary YAML raises ValueError."""
        config_file = tmp_path / "list.yml"
        config_file.write_text("- item1\n- item2")

        with pytest.raises(ValueError, match="must contain a YAML mapping"):
            ConfigLoader.load_yaml_file(config_file)


class TestConfigLoaderFindProjectConfig:
    """Test ConfigLoader.find_project_config method."""

    def test_find_config_in_current_directory(self, tmp_path):
        """Test finding config in current directory."""
        config_file = tmp_path / ".codeaudit.yml"
        config_file.write_text("max_files: 30")

        with patch('pathlib.Path.cwd', return_value=tmp_path):
            found_config = ConfigLoader.find_project_config()

        assert found_config == config_file

    def test_find_config_in_parent_directory(self, tmp_path):
        """Test finding config in parent directory."""
        config_file = tmp_path / ".codeaudit.yml"
        config_file.write_text("max_files: 30")

        subdir = tmp_path / "subdir"
        subdir.mkdir()

        with patch('pathlib.Path.cwd', return_value=subdir):
            found_config = ConfigLoader.find_project_config()

        assert found_config == config_file

    def test_find_config_in_ancestor_directory(self, tmp_path):
        """Test finding config in ancestor directory."""
        config_file = tmp_path / ".codeaudit.yml"
        config_file.write_text("max_files: 30")

        # Create nested directories
        deep_dir = tmp_path / "level1" / "level2" / "level3"
        deep_dir.mkdir(parents=True)

        with patch('pathlib.Path.cwd', return_value=deep_dir):
            found_config = ConfigLoader.find_project_config()

        assert found_config == config_file

    def test_find_config_returns_none_if_not_found(self, tmp_path):
        """Test that None is returned if no config file exists."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        with patch('pathlib.Path.cwd', return_value=subdir):
            found_config = ConfigLoader.find_project_config()

        assert found_config is None


class TestConfigLoaderLoad:
    """Test ConfigLoader.load method (config merging)."""

    def test_load_with_defaults_only(self, tmp_path):
        """Test loading with no config files (defaults only)."""
        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with patch.object(ConfigLoader, 'USER_CONFIG_FILE', tmp_path / "nonexistent.yml"):
                config = ConfigLoader.load()

        assert config.max_files == 20  # Default value
        assert config.recursive is True
        assert config.enable_cache is True

    def test_load_with_user_config(self, tmp_path):
        """Test loading user-level configuration."""
        user_config_file = tmp_path / "user_config.yml"
        user_config_data = {'max_files': 50, 'log_level': 'DEBUG'}
        user_config_file.write_text(yaml.safe_dump(user_config_data))

        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with patch.object(ConfigLoader, 'USER_CONFIG_FILE', user_config_file):
                config = ConfigLoader.load()

        assert config.max_files == 50
        assert config.log_level == "DEBUG"

    def test_load_with_project_config(self, tmp_path):
        """Test loading project-level configuration."""
        project_config_file = tmp_path / ".codeaudit.yml"
        project_config_data = {'max_files': 100, 'recursive': False}
        project_config_file.write_text(yaml.safe_dump(project_config_data))

        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with patch.object(ConfigLoader, 'USER_CONFIG_FILE', tmp_path / "nonexistent.yml"):
                config = ConfigLoader.load()

        assert config.max_files == 100
        assert config.recursive is False

    def test_load_project_overrides_user_config(self, tmp_path):
        """Test that project config overrides user config."""
        user_config_file = tmp_path / "user_config.yml"
        user_config_data = {'max_files': 50, 'log_level': 'DEBUG'}
        user_config_file.write_text(yaml.safe_dump(user_config_data))

        project_config_file = tmp_path / ".codeaudit.yml"
        project_config_data = {'max_files': 100}  # Override max_files
        project_config_file.write_text(yaml.safe_dump(project_config_data))

        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with patch.object(ConfigLoader, 'USER_CONFIG_FILE', user_config_file):
                config = ConfigLoader.load()

        assert config.max_files == 100  # From project config
        assert config.log_level == "DEBUG"  # From user config

    def test_load_explicit_config_overrides_all(self, tmp_path):
        """Test that explicit config file overrides everything."""
        user_config_file = tmp_path / "user_config.yml"
        user_config_file.write_text(yaml.safe_dump({'max_files': 50}))

        project_config_file = tmp_path / ".codeaudit.yml"
        project_config_file.write_text(yaml.safe_dump({'max_files': 100}))

        explicit_config_file = tmp_path / "custom.yml"
        explicit_config_file.write_text(yaml.safe_dump({'max_files': 200}))

        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with patch.object(ConfigLoader, 'USER_CONFIG_FILE', user_config_file):
                config = ConfigLoader.load(config_file=explicit_config_file)

        assert config.max_files == 200  # From explicit config

    def test_load_explicit_nonexistent_file_raises_error(self):
        """Test that specifying nonexistent explicit config raises error."""
        fake_file = Path("nonexistent.yml")

        with pytest.raises(ValueError, match="Configuration file not found"):
            ConfigLoader.load(config_file=fake_file)

    def test_load_invalid_config_values_raises_error(self, tmp_path):
        """Test that invalid config values raise ValueError."""
        config_file = tmp_path / "invalid.yml"
        config_file.write_text(yaml.safe_dump({'max_files': -1}))

        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with patch.object(ConfigLoader, 'USER_CONFIG_FILE', tmp_path / "nonexistent.yml"):
                with pytest.raises(ValueError, match="max_files must be positive"):
                    ConfigLoader.load(config_file=config_file)

    def test_load_handles_corrupted_user_config_gracefully(self, tmp_path):
        """Test that corrupted user config is skipped gracefully."""
        user_config_file = tmp_path / "user_config.yml"
        user_config_file.write_text("invalid: yaml: [")

        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with patch.object(ConfigLoader, 'USER_CONFIG_FILE', user_config_file):
                config = ConfigLoader.load()  # Should not crash

        # Should fall back to defaults
        assert config.max_files == 20


class TestConfigLoaderSave:
    """Test ConfigLoader.save method."""

    def test_save_config_to_file(self, tmp_path):
        """Test saving configuration to file."""
        config = CodeAuditConfig(max_files=50, log_level="DEBUG")
        save_path = tmp_path / "saved_config.yml"

        ConfigLoader.save(config, save_path)

        assert save_path.exists()

        # Load and verify
        with open(save_path, 'r', encoding='utf-8') as f:
            saved_data = yaml.safe_load(f)

        assert saved_data['max_files'] == 50
        assert saved_data['log_level'] == "DEBUG"

    def test_save_creates_parent_directory(self, tmp_path):
        """Test that save creates parent directory if needed."""
        config = CodeAuditConfig()
        save_path = tmp_path / "nested" / "dir" / "config.yml"

        ConfigLoader.save(config, save_path)

        assert save_path.exists()
        assert save_path.parent.exists()


class TestConfigLoaderCreateSampleConfig:
    """Test ConfigLoader.create_sample_config method."""

    def test_create_sample_config(self, tmp_path):
        """Test creating a sample configuration file."""
        sample_path = tmp_path / "sample.yml"

        ConfigLoader.create_sample_config(sample_path)

        assert sample_path.exists()

        # Verify it contains comments and valid YAML
        content = sample_path.read_text()
        assert "# CodeAudit Configuration File" in content
        assert "max_files:" in content
        assert "languages:" in content

        # Should be valid YAML
        data = yaml.safe_load(content)
        assert isinstance(data, dict)
        assert 'max_files' in data

    def test_create_sample_config_creates_directory(self, tmp_path):
        """Test that create_sample_config creates parent directory."""
        sample_path = tmp_path / "nested" / "sample.yml"

        ConfigLoader.create_sample_config(sample_path)

        assert sample_path.exists()
        assert sample_path.parent.exists()


class TestConfigIntegration:
    """Integration tests for configuration system."""

    def test_complete_workflow(self, tmp_path):
        """Test complete workflow: load, modify, save, reload."""
        # Create initial config file
        config_file = tmp_path / ".codeaudit.yml"
        initial_data = {'max_files': 30, 'log_level': 'INFO'}
        config_file.write_text(yaml.safe_dump(initial_data))

        # Load configuration
        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with patch.object(ConfigLoader, 'USER_CONFIG_FILE', tmp_path / "nonexistent.yml"):
                config = ConfigLoader.load()

        assert config.max_files == 30

        # Modify configuration
        config.max_files = 50
        config.log_level = "DEBUG"

        # Save modified configuration
        save_path = tmp_path / "modified.yml"
        ConfigLoader.save(config, save_path)

        # Reload and verify
        reloaded_config = ConfigLoader.load(config_file=save_path)
        assert reloaded_config.max_files == 50
        assert reloaded_config.log_level == "DEBUG"

    def test_merge_multiple_sources(self, tmp_path):
        """Test merging configuration from multiple sources."""
        # User config: sets max_files
        user_config = tmp_path / "user.yml"
        user_config.write_text(yaml.safe_dump({'max_files': 50, 'log_level': 'DEBUG'}))

        # Project config: overrides max_files, sets recursive
        project_config = tmp_path / ".codeaudit.yml"
        project_config.write_text(yaml.safe_dump({'max_files': 100, 'recursive': False}))

        with patch('pathlib.Path.cwd', return_value=tmp_path):
            with patch.object(ConfigLoader, 'USER_CONFIG_FILE', user_config):
                config = ConfigLoader.load()

        # Project config should override user config for max_files
        assert config.max_files == 100
        # User config log_level should be preserved
        assert config.log_level == "DEBUG"
        # Project config recursive should be used
        assert config.recursive is False
        # Defaults should be used for unspecified values
        assert config.enable_cache is True
