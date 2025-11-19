"""
Tests for prompts/template_engine.py module.
"""

from pathlib import Path

import pytest

from prompts.template_engine import PromptEngine


class TestPromptEngine:
    """Test PromptEngine class."""

    def test_initialization_default_directory(self):
        """Test that PromptEngine initializes with default template directory."""
        engine = PromptEngine()
        assert engine is not None
        assert engine.template_dir is not None
        assert isinstance(engine.template_dir, Path)

    def test_initialization_custom_directory(self, tmp_path):
        """Test that PromptEngine initializes with custom template directory."""
        custom_dir = tmp_path / "templates"
        custom_dir.mkdir()

        engine = PromptEngine(template_dir=custom_dir)
        assert engine.template_dir == custom_dir

    def test_get_prompt_with_base_template(self, tmp_path):
        """Test getting a prompt with base template."""
        # Create a minimal template directory structure
        template_dir = tmp_path / "templates"
        template_dir.mkdir()

        # Create base_prompt.j2
        base_template = template_dir / "base_prompt.j2"
        base_template.write_text("""
You are analyzing {{ language }} code.
File: {{ file_name }}

Code:
{{ code_content }}
""")

        engine = PromptEngine(template_dir=template_dir)
        prompt = engine.get_prompt(
            language="python",
            code_content="def hello(): pass",
            file_name="test.py",
            frameworks=[],
            threat_models=[],
            few_shot_examples=[]
        )

        assert "python" in prompt
        assert "test.py" in prompt
        assert "def hello(): pass" in prompt

    def test_get_prompt_with_language_specific_template(self, tmp_path):
        """Test that language-specific template is preferred over base."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        languages_dir = template_dir / "languages"
        languages_dir.mkdir()

        # Create base template
        base_template = template_dir / "base_prompt.j2"
        base_template.write_text("Base template")

        # Create language-specific template
        python_template = languages_dir / "python.j2"
        python_template.write_text("Python-specific template for {{ file_name }}")

        engine = PromptEngine(template_dir=template_dir)
        prompt = engine.get_prompt(
            language="python",
            code_content="code",
            file_name="test.py",
            frameworks=[],
            threat_models=[],
            few_shot_examples=[]
        )

        assert "Python-specific" in prompt
        assert "test.py" in prompt
        assert "Base template" not in prompt

    def test_get_prompt_with_framework_specific_template(self, tmp_path):
        """Test that framework-specific template is preferred over language."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        frameworks_dir = template_dir / "frameworks"
        frameworks_dir.mkdir()
        languages_dir = template_dir / "languages"
        languages_dir.mkdir()

        # Create templates
        (template_dir / "base_prompt.j2").write_text("Base")
        (languages_dir / "python.j2").write_text("Python")
        (frameworks_dir / "django.j2").write_text("Django-specific for {{ file_name }}")

        engine = PromptEngine(template_dir=template_dir)
        prompt = engine.get_prompt(
            language="python",
            code_content="code",
            file_name="views.py",
            frameworks=["django"],
            threat_models=[],
            few_shot_examples=[]
        )

        assert "Django-specific" in prompt
        assert "views.py" in prompt

    def test_get_prompt_fallback_to_base_when_no_specific_template(self, tmp_path):
        """Test fallback to base template when no specific template exists."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()

        base_template = template_dir / "base_prompt.j2"
        base_template.write_text("Base template for {{ language }}")

        engine = PromptEngine(template_dir=template_dir)
        prompt = engine.get_prompt(
            language="unknown_lang",
            code_content="code",
            file_name="test.file",
            frameworks=[],
            threat_models=[],
            few_shot_examples=[]
        )

        assert "Base template" in prompt
        assert "unknown_lang" in prompt

    def test_get_prompt_raises_error_when_no_base_template(self, tmp_path):
        """Test that error is raised when no base template exists."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()

        engine = PromptEngine(template_dir=template_dir)

        with pytest.raises(ValueError) as exc_info:
            engine.get_prompt(
                language="python",
                code_content="code",
                file_name="test.py",
                frameworks=[],
                threat_models=[],
                few_shot_examples=[]
            )

        assert "No templates found" in str(exc_info.value)
        assert "base_prompt.j2" in str(exc_info.value)

    def test_get_prompt_with_frameworks_context(self, tmp_path):
        """Test that frameworks are passed to template context."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()

        base_template = template_dir / "base_prompt.j2"
        base_template.write_text("""
{% if has_frameworks %}
Detected frameworks: {{ frameworks|join(', ') }}
{% endif %}
""")

        engine = PromptEngine(template_dir=template_dir)
        prompt = engine.get_prompt(
            language="python",
            code_content="code",
            file_name="test.py",
            frameworks=["django", "flask"],
            threat_models=[],
            few_shot_examples=[]
        )

        assert "django" in prompt
        assert "flask" in prompt

    def test_get_prompt_with_threat_models_context(self, tmp_path):
        """Test that threat models are passed to template context."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()

        base_template = template_dir / "base_prompt.j2"
        base_template.write_text("""
{% if has_threat_models %}
Threat models: {{ threat_models|join(', ') }}
{% endif %}
""")

        engine = PromptEngine(template_dir=template_dir)
        prompt = engine.get_prompt(
            language="python",
            code_content="code",
            file_name="test.py",
            frameworks=[],
            threat_models=["web", "api"],
            few_shot_examples=[]
        )

        assert "web" in prompt
        assert "api" in prompt

    def test_get_prompt_with_few_shot_examples_context(self, tmp_path):
        """Test that few-shot examples are passed to template context."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()

        base_template = template_dir / "base_prompt.j2"
        base_template.write_text("""
{% if has_examples %}
Examples count: {{ few_shot_examples|length }}
{% endif %}
""")

        engine = PromptEngine(template_dir=template_dir)
        examples = [
            {"title": "Example 1", "vulnerable_code": "code1"},
            {"title": "Example 2", "vulnerable_code": "code2"}
        ]
        prompt = engine.get_prompt(
            language="python",
            code_content="code",
            file_name="test.py",
            frameworks=[],
            threat_models=[],
            few_shot_examples=examples
        )

        assert "Examples count: 2" in prompt

    def test_list_available_templates(self, tmp_path):
        """Test listing available templates."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()

        # Create template structure
        languages_dir = template_dir / "languages"
        languages_dir.mkdir()
        (languages_dir / "python.j2").write_text("Python")
        (languages_dir / "javascript.j2").write_text("JavaScript")

        frameworks_dir = template_dir / "frameworks"
        frameworks_dir.mkdir()
        (frameworks_dir / "django.j2").write_text("Django")

        threat_models_dir = template_dir / "threat_models"
        threat_models_dir.mkdir()
        (threat_models_dir / "web_security.j2").write_text("Web")

        engine = PromptEngine(template_dir=template_dir)
        templates = engine.list_available_templates()

        assert isinstance(templates, dict)
        assert 'languages' in templates
        assert 'frameworks' in templates
        assert 'threat_models' in templates

        assert 'python' in templates['languages']
        assert 'javascript' in templates['languages']
        assert 'django' in templates['frameworks']
        assert 'web_security' in templates['threat_models']

    def test_list_available_templates_empty_directories(self, tmp_path):
        """Test listing templates with empty directories."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()

        # Create empty directories
        (template_dir / "languages").mkdir()
        (template_dir / "frameworks").mkdir()
        (template_dir / "threat_models").mkdir()

        engine = PromptEngine(template_dir=template_dir)
        templates = engine.list_available_templates()

        assert not templates['languages']
        assert not templates['frameworks']
        assert not templates['threat_models']

    def test_list_available_templates_missing_directories(self, tmp_path):
        """Test listing templates when directories don't exist."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()

        engine = PromptEngine(template_dir=template_dir)
        templates = engine.list_available_templates()

        assert not templates['languages']
        assert not templates['frameworks']
        assert not templates['threat_models']

    def test_template_priority_order(self, tmp_path):
        """Test that template selection follows correct priority order."""
        template_dir = tmp_path / "templates"
        template_dir.mkdir()

        # Create all template types
        (template_dir / "base_prompt.j2").write_text("BASE")

        languages_dir = template_dir / "languages"
        languages_dir.mkdir()
        (languages_dir / "python.j2").write_text("LANGUAGE")

        frameworks_dir = template_dir / "frameworks"
        frameworks_dir.mkdir()
        (frameworks_dir / "django.j2").write_text("FRAMEWORK {{ file_name }}")

        threat_models_dir = template_dir / "threat_models"
        threat_models_dir.mkdir()
        (threat_models_dir / "web_security.j2").write_text("THREAT_MODEL")

        engine = PromptEngine(template_dir=template_dir)

        # Test framework priority (highest)
        prompt_framework = engine.get_prompt(
            language="python",
            code_content="code",
            file_name="test.py",
            frameworks=["django"],
            threat_models=["web_security"],
            few_shot_examples=[]
        )
        assert "FRAMEWORK" in prompt_framework
        assert "LANGUAGE" not in prompt_framework
        assert "THREAT_MODEL" not in prompt_framework

        # Test language priority (when no framework)
        prompt_language = engine.get_prompt(
            language="python",
            code_content="code",
            file_name="test.py",
            frameworks=[],
            threat_models=["web_security"],
            few_shot_examples=[]
        )
        assert "LANGUAGE" in prompt_language
        assert "FRAMEWORK" not in prompt_language
        assert "THREAT_MODEL" not in prompt_language

        # Test threat model priority (when no framework or language)
        prompt_threat = engine.get_prompt(
            language="unknown",
            code_content="code",
            file_name="test.py",
            frameworks=[],
            threat_models=["web_security"],
            few_shot_examples=[]
        )
        assert "THREAT_MODEL" in prompt_threat
        assert "LANGUAGE" not in prompt_threat
        assert "FRAMEWORK" not in prompt_threat

        # Test base priority (lowest, when nothing else matches)
        prompt_base = engine.get_prompt(
            language="unknown",
            code_content="code",
            file_name="test.py",
            frameworks=[],
            threat_models=[],
            few_shot_examples=[]
        )
        assert "BASE" in prompt_base
