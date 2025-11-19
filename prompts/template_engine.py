"""
Prompt template engine using Jinja2.

Provides intelligent prompt selection based on:
- Language (Python, JavaScript, Java, etc.)
- Framework (Django, React, Spring, etc.)
- Threat model (Web, API, Mobile, Crypto, etc.)
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape, TemplateNotFound, Template


class PromptEngine:
    """
    Manages prompt template selection and rendering.

    Attributes:
        template_dir: Directory containing Jinja2 templates
        env: Jinja2 environment for template rendering
    """

    def __init__(self, template_dir: Optional[Path] = None):
        """
        Initialize the prompt template engine.

        Args:
            template_dir: Path to templates directory. Defaults to ./prompts/

        Raises:
            ValueError: If template directory doesn't exist
        """
        if template_dir is None:
            template_dir = Path(__file__).parent

        self.template_dir = Path(template_dir)

        if not self.template_dir.exists():
            raise ValueError(f"Template directory not found: {self.template_dir}")

        # Configure Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(),
            trim_blocks=True,
            lstrip_blocks=True
        )

    def get_prompt(
        self,
        language: str,
        code_content: str,
        file_name: str,
        frameworks: Optional[List[str]] = None,
        threat_models: Optional[List[str]] = None,
        few_shot_examples: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """
        Generate analysis prompt based on context.

        Selects the most specific template available:
        1. Framework-specific (e.g., django.j2)
        2. Language-specific (e.g., python.j2)
        3. Threat model-specific (e.g., web_security.j2)
        4. Base prompt (base_prompt.j2)

        Args:
            language: Programming language (e.g., 'python', 'javascript')
            code_content: Source code to analyze
            file_name: Name of the file being analyzed
            frameworks: List of detected frameworks (e.g., ['django', 'flask'])
            threat_models: List of applicable threat models (e.g., ['web', 'api'])
            few_shot_examples: List of example vulnerabilities for few-shot learning

        Returns:
            Rendered prompt string ready for AI analysis
        """
        frameworks = frameworks or []
        threat_models = threat_models or []
        few_shot_examples = few_shot_examples or []

        # Try to find the most specific template
        template = self._select_template(language, frameworks, threat_models)

        # Prepare context variables for template rendering
        context = {
            'language': language,
            'file_name': file_name,
            'code_content': code_content,
            'frameworks': frameworks,
            'threat_models': threat_models,
            'few_shot_examples': few_shot_examples,
            'has_frameworks': len(frameworks) > 0,
            'has_threat_models': len(threat_models) > 0,
            'has_examples': len(few_shot_examples) > 0
        }

        return template.render(**context)

    def _select_template(
        self,
        language: str,
        frameworks: List[str],
        threat_models: List[str]
    ) -> Template:
        """
        Select the most appropriate template based on priority.

        Priority order:
        1. Framework-specific (frameworks/<framework>.j2)
        2. Language-specific (languages/<language>.j2)
        3. Threat model-specific (threat_models/<model>.j2)
        4. Base prompt (base_prompt.j2)

        Args:
            language: Programming language
            frameworks: List of detected frameworks
            threat_models: List of applicable threat models

        Returns:
            Jinja2 Template object
        """
        # Try framework-specific templates first (highest priority)
        for framework in frameworks:
            try:
                return self.env.get_template(f"frameworks/{framework}.j2")
            except TemplateNotFound:
                continue

        # Try language-specific template
        try:
            return self.env.get_template(f"languages/{language}.j2")
        except TemplateNotFound:
            pass

        # Try threat model-specific template
        for model in threat_models:
            try:
                return self.env.get_template(f"threat_models/{model}.j2")
            except TemplateNotFound:
                continue

        # Fallback to base prompt
        try:
            return self.env.get_template("base_prompt.j2")
        except TemplateNotFound as e:
            raise ValueError(
                f"No templates found! Expected at least base_prompt.j2 in {self.template_dir}"
            ) from e

    def list_available_templates(self) -> Dict[str, List[str]]:
        """
        List all available prompt templates.

        Returns:
            Dictionary with template categories and available templates:
            {
                'languages': ['python', 'javascript', ...],
                'frameworks': ['django', 'react', ...],
                'threat_models': ['web_security', 'api_security', ...]
            }
        """
        categories: Dict[str, List[str]] = {
            'languages': [],
            'frameworks': [],
            'threat_models': []
        }

        for category in categories.keys():
            category_dir = self.template_dir / category
            if category_dir.exists():
                for template_file in category_dir.glob("*.j2"):
                    categories[category].append(template_file.stem)

        return categories
