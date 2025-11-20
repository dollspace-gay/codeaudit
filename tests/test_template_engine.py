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


class TestProductionTemplates:
    """Test that all production templates load and render correctly."""

    def test_all_language_templates_load(self):
        """Test that all 14 language-specific templates can be loaded and rendered."""
        engine = PromptEngine()
        languages = ['python', 'javascript', 'typescript', 'java', 'cpp', 'csharp',
                    'go', 'rust', 'php', 'ruby', 'swift', 'kotlin', 'scala', 'dart']

        for language in languages:
            prompt = engine.get_prompt(
                language=language,
                code_content="def test(): pass",
                file_name=f"test.{language}",
                frameworks=[],
                threat_models=[],
                few_shot_examples=[]
            )
            assert prompt is not None
            assert len(prompt) > 100  # Should be a substantial prompt
            assert 'JSON Schema' in prompt or 'json' in prompt.lower()

    def test_all_threat_model_templates_load(self):
        """Test that all 8 threat model templates can be loaded and rendered."""
        engine = PromptEngine()
        threat_models_list = [
            'web_security', 'api_security', 'mobile_security', 'cryptography',
            'auth', 'database', 'cloud', 'supply_chain'
        ]

        for threat_model in threat_models_list:
            prompt = engine.get_prompt(
                language='unknown',  # Use unknown language to force threat model selection
                code_content="def test(): pass",
                file_name="test.py",
                frameworks=[],
                threat_models=[threat_model],
                few_shot_examples=[]
            )
            assert prompt is not None
            assert len(prompt) > 200  # Threat models should be comprehensive

    def test_threat_model_web_security_content(self):
        """Test that web_security template contains expected security guidance."""
        engine = PromptEngine()
        prompt = engine.get_prompt(
            language='unknown',
            code_content="code",
            file_name="test.py",
            frameworks=[],
            threat_models=['web_security'],
            few_shot_examples=[]
        )

        # Verify OWASP Top 10 content
        assert 'OWASP' in prompt or 'owasp' in prompt.lower()
        assert 'XSS' in prompt or 'Cross-Site Scripting' in prompt
        assert 'CSRF' in prompt or 'Cross-Site Request Forgery' in prompt
        assert 'SQL' in prompt or 'injection' in prompt.lower()

    def test_threat_model_api_security_content(self):
        """Test that api_security template contains expected API security guidance."""
        engine = PromptEngine()
        prompt = engine.get_prompt(
            language='unknown',
            code_content="code",
            file_name="test.py",
            frameworks=[],
            threat_models=['api_security'],
            few_shot_examples=[]
        )

        # Verify API security content
        assert 'API' in prompt or 'api' in prompt.lower()
        assert 'BOLA' in prompt or 'authorization' in prompt.lower()
        assert 'rate limit' in prompt.lower() or 'Rate Limiting' in prompt

    def test_threat_model_cryptography_content(self):
        """Test that cryptography template contains expected crypto guidance."""
        engine = PromptEngine()
        prompt = engine.get_prompt(
            language='unknown',
            code_content="code",
            file_name="test.py",
            frameworks=[],
            threat_models=['cryptography'],
            few_shot_examples=[]
        )

        # Verify cryptography content
        assert 'AES' in prompt or 'encryption' in prompt.lower()
        assert 'MD5' in prompt or 'SHA' in prompt
        assert 'key' in prompt.lower()

    def test_framework_django_template_loads(self):
        """Test that Django framework template can be loaded."""
        engine = PromptEngine()
        prompt = engine.get_prompt(
            language='python',
            code_content="from django.db import models",
            file_name="models.py",
            frameworks=['django'],
            threat_models=[],
            few_shot_examples=[]
        )

        assert prompt is not None
        assert 'Django' in prompt or 'django' in prompt.lower()
        assert 'CSRF' in prompt or 'csrf' in prompt.lower()

    def test_fix_suggestions_in_templates(self):
        """Test that templates include fix suggestion schema."""
        engine = PromptEngine()

        # Test base template
        prompt = engine.get_prompt(
            language='unknown',
            code_content="code",
            file_name="test.txt",
            frameworks=[],
            threat_models=[],
            few_shot_examples=[]
        )
        assert 'fix' in prompt.lower()
        assert 'before_code' in prompt or 'after_code' in prompt

        # Test language-specific template
        prompt_python = engine.get_prompt(
            language='python',
            code_content="def test(): pass",
            file_name="test.py",
            frameworks=[],
            threat_models=[],
            few_shot_examples=[]
        )
        assert 'fix' in prompt_python.lower()
        assert 'before_code' in prompt_python or 'after_code' in prompt_python

    def test_few_shot_examples_injection(self):
        """Test that few-shot examples are properly injected into templates."""
        engine = PromptEngine()

        examples = [
            {
                'title': 'SQL Injection Example',
                'vulnerable_code': 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                'issue': 'SQL injection vulnerability',
                'fix': 'Use parameterized queries'
            }
        ]

        prompt = engine.get_prompt(
            language='python',
            code_content="code",
            file_name="test.py",
            frameworks=[],
            threat_models=[],
            few_shot_examples=examples
        )

        assert 'SQL Injection Example' in prompt
        assert 'parameterized queries' in prompt

    def test_template_priority_with_production_templates(self):
        """Test template selection priority with actual production templates."""
        engine = PromptEngine()

        # Framework should take priority over language
        prompt_django = engine.get_prompt(
            language='python',
            code_content="code",
            file_name="test.py",
            frameworks=['django'],
            threat_models=[],
            few_shot_examples=[]
        )
        # Should use Django template, not Python template
        assert 'django' in prompt_django.lower()

        # Language should take priority over threat model
        prompt_python = engine.get_prompt(
            language='python',
            code_content="code",
            file_name="test.py",
            frameworks=[],
            threat_models=['web_security'],
            few_shot_examples=[]
        )
        # Should use Python template
        assert 'Python' in prompt_python

        # Threat model should be used when no language/framework match
        prompt_threat = engine.get_prompt(
            language='unknown_lang',
            code_content="code",
            file_name="test.xyz",
            frameworks=[],
            threat_models=['api_security'],
            few_shot_examples=[]
        )
        # Should use API security template
        assert 'api' in prompt_threat.lower() or 'API' in prompt_threat

    def test_template_rendering_with_all_parameters(self):
        """Test template rendering with all possible parameters filled."""
        engine = PromptEngine()

        examples = [{'title': 'Test', 'vulnerable_code': 'code', 'issue': 'issue', 'fix': 'fix'}]

        prompt = engine.get_prompt(
            language='python',
            code_content='def vulnerable(): pass',
            file_name='vuln.py',
            frameworks=['django', 'flask'],
            threat_models=['web_security', 'api_security'],
            few_shot_examples=examples
        )

        # Verify all parameters are used in rendering
        assert 'vuln.py' in prompt
        assert 'vulnerable' in prompt or 'def vulnerable()' in prompt
        assert 'Test' in prompt  # From few-shot example

    def test_json_schema_in_all_templates(self):
        """Test that all templates include JSON schema for structured output."""
        engine = PromptEngine()

        # Test various template types
        test_cases = [
            {'language': 'python', 'frameworks': [], 'threat_models': []},
            {'language': 'javascript', 'frameworks': [], 'threat_models': []},
            {'language': 'unknown', 'frameworks': [], 'threat_models': ['web_security']},
            {'language': 'python', 'frameworks': ['django'], 'threat_models': []},
        ]

        for case in test_cases:
            prompt = engine.get_prompt(
                language=case['language'],
                code_content='code',
                file_name='test.py',
                frameworks=case['frameworks'],
                threat_models=case['threat_models'],
                few_shot_examples=[]
            )

            # All templates should have JSON schema
            assert 'issues' in prompt.lower()
            assert 'severity' in prompt.lower()
            assert 'summary' in prompt.lower()

