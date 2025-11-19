"""
Framework detection system for identifying libraries and frameworks in code.

Analyzes source code and dependencies to detect:
- Web frameworks (Django, Flask, FastAPI, Express, React, etc.)
- ORM libraries (SQLAlchemy, Sequelize, Hibernate, etc.)
- Testing frameworks (pytest, Jest, JUnit, etc.)
- Other common libraries
"""

import re
from pathlib import Path
from typing import List, Dict, Set
from enum import Enum


class Language(Enum):
    """Supported programming languages."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"
    SWIFT = "swift"
    KOTLIN = "kotlin"
    SCALA = "scala"
    DART = "dart"


class FrameworkDetector:
    """
    Detects frameworks and libraries used in source code.

    Uses pattern matching on imports, package declarations, and
    common framework-specific code patterns.
    """

    # Framework detection patterns by language
    PATTERNS: Dict[Language, Dict[str, List[str]]] = {
        Language.PYTHON: {
            'django': [
                r'from django',
                r'import django',
                r'django\.conf',
                r'django\.db\.models',
                r'django\.http',
            ],
            'flask': [
                r'from flask import',
                r'import flask',
                r'Flask\(__name__\)',
                r'@app\.route',
            ],
            'fastapi': [
                r'from fastapi import',
                r'import fastapi',
                r'FastAPI\(',
                r'@app\.(get|post|put|delete)',
            ],
            'sqlalchemy': [
                r'from sqlalchemy import',
                r'import sqlalchemy',
                r'declarative_base',
            ],
            'requests': [
                r'import requests',
                r'requests\.(get|post)',
            ],
            'pandas': [
                r'import pandas',
                r'pd\.DataFrame',
            ],
            'numpy': [
                r'import numpy',
                r'np\.array',
            ],
        },
        Language.JAVASCRIPT: {
            'express': [
                r'require\([\'"]express[\'"]\)',
                r'from [\'"]express[\'"]',
                r'app\.(get|post|put|delete)',
            ],
            'react': [
                r'from [\'"]react[\'"]',
                r'React\.Component',
                r'useState|useEffect',
                r'<[A-Z][a-zA-Z]*',  # JSX components
            ],
            'vue': [
                r'from [\'"]vue[\'"]',
                r'new Vue\(',
                r'Vue\.component',
            ],
            'angular': [
                r'from [\'"]@angular',
                r'@Component',
                r'@NgModule',
            ],
            'sequelize': [
                r'require\([\'"]sequelize[\'"]\)',
                r'from [\'"]sequelize[\'"]',
            ],
            'mongoose': [
                r'require\([\'"]mongoose[\'"]\)',
                r'mongoose\.Schema',
            ],
        },
        Language.TYPESCRIPT: {
            'express': [
                r'from [\'"]express[\'"]',
                r'app\.(get|post|put|delete)',
            ],
            'react': [
                r'from [\'"]react[\'"]',
                r'React\.FC',
                r'useState|useEffect',
            ],
            'angular': [
                r'from [\'"]@angular',
                r'@Component',
                r'@Injectable',
            ],
            'nestjs': [
                r'from [\'"]@nestjs',
                r'@Controller',
                r'@Injectable',
            ],
        },
        Language.JAVA: {
            'spring': [
                r'org\.springframework',
                r'@SpringBootApplication',
                r'@RestController',
                r'@Autowired',
            ],
            'hibernate': [
                r'org\.hibernate',
                r'@Entity',
                r'@Table',
            ],
            'jakarta': [
                r'jakarta\.servlet',
                r'jakarta\.persistence',
            ],
        },
        Language.CSHARP: {
            'aspnet': [
                r'using Microsoft\.AspNetCore',
                r'\[ApiController\]',
                r'\[HttpGet\]',
            ],
            'entityframework': [
                r'using Microsoft\.EntityFrameworkCore',
                r'DbContext',
                r'DbSet',
            ],
        },
        Language.GO: {
            'gin': [
                r'github\.com/gin-gonic/gin',
                r'gin\.Default\(',
                r'router\.GET',
            ],
            'echo': [
                r'github\.com/labstack/echo',
                r'echo\.New\(',
            ],
            'gorm': [
                r'github\.com/jinzhu/gorm',
                r'gorm\.Model',
            ],
        },
        Language.RUBY: {
            'rails': [
                r'require [\'"]rails[\'"]',
                r'Rails\.application',
                r'ActiveRecord::Base',
                r'< ApplicationController',
            ],
            'sinatra': [
                r'require [\'"]sinatra[\'"]',
                r'get [\'"]/',
                r'Sinatra::Base',
            ],
        },
        Language.PHP: {
            'laravel': [
                r'use Illuminate\\',
                r'extends Controller',
                r'Route::',
            ],
            'symfony': [
                r'use Symfony\\',
                r'#\[Route',
            ],
            'wordpress': [
                r'add_action\(',
                r'get_posts\(',
                r'wp_',
            ],
        },
        Language.SWIFT: {
            'swiftui': [
                r'import SwiftUI',
                r'struct.*: View',
                r'@State|@Binding',
            ],
            'uikit': [
                r'import UIKit',
                r'UIViewController',
                r'UIView',
            ],
        },
        Language.KOTLIN: {
            'spring': [
                r'org\.springframework',
                r'@SpringBootApplication',
                r'@RestController',
            ],
            'android': [
                r'import android\.',
                r'AppCompatActivity',
                r'findViewById',
            ],
        },
    }

    def __init__(self) -> None:
        """Initialize the framework detector."""
        pass

    def detect_frameworks(self, code_content: str, language: str) -> List[str]:
        """
        Detect frameworks used in the given code.

        Args:
            code_content: Source code content
            language: Programming language (e.g., 'python', 'javascript')

        Returns:
            List of detected framework names (e.g., ['django', 'sqlalchemy'])
        """
        # Normalize language name
        try:
            lang_enum = Language(language.lower())
        except ValueError:
            # Unsupported language
            return []

        if lang_enum not in self.PATTERNS:
            return []

        detected: Set[str] = set()
        patterns = self.PATTERNS[lang_enum]

        for framework, regexes in patterns.items():
            for pattern in regexes:
                if re.search(pattern, code_content, re.MULTILINE):
                    detected.add(framework)
                    break  # Framework found, no need to check other patterns

        return sorted(list(detected))

    def detect_from_file(self, file_path: Path) -> List[str]:
        """
        Detect frameworks from a file.

        Args:
            file_path: Path to source code file

        Returns:
            List of detected framework names
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()

            # Determine language from file extension
            extension_map = {
                '.py': 'python',
                '.js': 'javascript',
                '.ts': 'typescript',
                '.jsx': 'javascript',
                '.tsx': 'typescript',
                '.java': 'java',
                '.cs': 'csharp',
                '.go': 'go',
                '.rs': 'rust',
                '.php': 'php',
                '.rb': 'ruby',
                '.swift': 'swift',
                '.kt': 'kotlin',
                '.scala': 'scala',
                '.dart': 'dart',
            }

            language = extension_map.get(file_path.suffix, '')
            if not language:
                return []

            return self.detect_frameworks(code_content, language)

        except Exception:
            return []

    @staticmethod
    def get_threat_models_for_frameworks(frameworks: List[str]) -> List[str]:
        """
        Determine applicable threat models based on detected frameworks.

        Args:
            frameworks: List of detected frameworks

        Returns:
            List of threat model names (e.g., ['web', 'api', 'database'])
        """
        threat_models: Set[str] = set()

        web_frameworks = {'django', 'flask', 'fastapi', 'express', 'spring',
                         'aspnet', 'rails', 'laravel', 'symfony', 'gin', 'echo'}

        mobile_frameworks = {'swiftui', 'uikit', 'android'}

        database_frameworks = {'sqlalchemy', 'sequelize', 'hibernate',
                              'entityframework', 'gorm', 'mongoose'}

        frontend_frameworks = {'react', 'vue', 'angular'}

        for framework in frameworks:
            if framework in web_frameworks:
                threat_models.add('web')
                threat_models.add('api')

            if framework in mobile_frameworks:
                threat_models.add('mobile')

            if framework in database_frameworks:
                threat_models.add('database')

            if framework in frontend_frameworks:
                threat_models.add('web')

        return sorted(list(threat_models))
