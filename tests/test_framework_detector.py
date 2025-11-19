"""
Tests for framework_detector.py module.
"""

from pathlib import Path
from unittest.mock import patch

from framework_detector import FrameworkDetector


class TestFrameworkDetector:
    """Test FrameworkDetector class."""

    def test_initialization(self):
        """Test that FrameworkDetector initializes successfully."""
        detector = FrameworkDetector()
        assert detector is not None

    def test_detect_frameworks_python_django(self):
        """Test detection of Django framework in Python code."""
        detector = FrameworkDetector()
        code = """
from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
"""
        frameworks = detector.detect_frameworks(code, 'python')
        assert 'django' in frameworks

    def test_detect_frameworks_python_flask(self):
        """Test detection of Flask framework in Python code."""
        detector = FrameworkDetector()
        code = """
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/users')
def get_users():
    return jsonify({'users': []})
"""
        frameworks = detector.detect_frameworks(code, 'python')
        assert 'flask' in frameworks

    def test_detect_frameworks_python_fastapi(self):
        """Test detection of FastAPI framework in Python code."""
        detector = FrameworkDetector()
        code = """
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

@app.get("/items/{item_id}")
async def read_item(item_id: int):
    return {"item_id": item_id}
"""
        frameworks = detector.detect_frameworks(code, 'python')
        assert 'fastapi' in frameworks

    def test_detect_frameworks_javascript_express(self):
        """Test detection of Express framework in JavaScript code."""
        detector = FrameworkDetector()
        code = """
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
    res.json({ users: [] });
});
"""
        frameworks = detector.detect_frameworks(code, 'javascript')
        assert 'express' in frameworks

    def test_detect_frameworks_javascript_react(self):
        """Test detection of React framework in JavaScript code."""
        detector = FrameworkDetector()
        code = """
import React, { useState } from 'react';
import ReactDOM from 'react-dom';

function App() {
    const [count, setCount] = useState(0);
    return <div onClick={() => setCount(count + 1)}>{count}</div>;
}
"""
        frameworks = detector.detect_frameworks(code, 'javascript')
        assert 'react' in frameworks

    def test_detect_frameworks_java_spring(self):
        """Test detection of Spring framework in Java code."""
        detector = FrameworkDetector()
        code = """
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
"""
        frameworks = detector.detect_frameworks(code, 'java')
        assert 'spring' in frameworks

    def test_detect_frameworks_no_frameworks(self):
        """Test that no frameworks are detected in plain code."""
        detector = FrameworkDetector()
        code = """
def add(a, b):
    return a + b

def multiply(x, y):
    return x * y
"""
        frameworks = detector.detect_frameworks(code, 'python')
        assert not frameworks

    def test_detect_frameworks_multiple(self):
        """Test detection of multiple frameworks in the same code."""
        detector = FrameworkDetector()
        code = """
from flask import Flask
from sqlalchemy import create_engine

app = Flask(__name__)
engine = create_engine('postgresql://localhost/db')
"""
        frameworks = detector.detect_frameworks(code, 'python')
        assert 'flask' in frameworks
        assert 'sqlalchemy' in frameworks
        assert len(frameworks) >= 2

    def test_detect_frameworks_case_insensitive_language(self):
        """Test that language parameter is case-insensitive."""
        detector = FrameworkDetector()
        code = "from django.db import models"

        frameworks_lower = detector.detect_frameworks(code, 'python')
        frameworks_upper = detector.detect_frameworks(code, 'PYTHON')
        frameworks_mixed = detector.detect_frameworks(code, 'Python')

        assert frameworks_lower == frameworks_upper == frameworks_mixed

    def test_detect_frameworks_unsupported_language(self):
        """Test that unsupported languages return empty list."""
        detector = FrameworkDetector()
        code = "some code here"
        frameworks = detector.detect_frameworks(code, 'unsupported_lang')
        assert not frameworks


class TestGetThreatModelsForFrameworks:
    """Test get_threat_models_for_frameworks static method."""

    def test_web_frameworks_return_web_and_api(self):
        """Test that web frameworks return web and api threat models."""
        threat_models = FrameworkDetector.get_threat_models_for_frameworks(['django', 'flask'])
        assert 'web' in threat_models
        assert 'api' in threat_models

    def test_database_frameworks_return_database(self):
        """Test that database frameworks return database threat model."""
        threat_models = FrameworkDetector.get_threat_models_for_frameworks(['sqlalchemy', 'hibernate'])
        assert 'database' in threat_models

    def test_mobile_frameworks_return_mobile(self):
        """Test that mobile frameworks return mobile threat model."""
        threat_models = FrameworkDetector.get_threat_models_for_frameworks(['swiftui', 'android'])
        assert 'mobile' in threat_models

    def test_frontend_frameworks_return_web(self):
        """Test that frontend frameworks return web threat model."""
        threat_models = FrameworkDetector.get_threat_models_for_frameworks(['react', 'vue', 'angular'])
        assert 'web' in threat_models

    def test_empty_frameworks_return_empty_list(self):
        """Test that empty framework list returns empty threat models."""
        threat_models = FrameworkDetector.get_threat_models_for_frameworks([])
        assert not threat_models

    def test_unknown_frameworks_return_empty_list(self):
        """Test that unknown frameworks return empty threat models."""
        threat_models = FrameworkDetector.get_threat_models_for_frameworks(['unknown-framework'])
        assert not threat_models

    def test_multiple_threat_models_no_duplicates(self):
        """Test that multiple frameworks don't create duplicate threat models."""
        threat_models = FrameworkDetector.get_threat_models_for_frameworks(['django', 'flask', 'fastapi'])
        # All three are web frameworks, so should only have 'web' and 'api' once
        assert len([tm for tm in threat_models if tm == 'web']) == 1
        assert len([tm for tm in threat_models if tm == 'api']) == 1

    def test_mixed_categories_return_multiple_threat_models(self):
        """Test that frameworks from different categories return multiple threat models."""
        threat_models = FrameworkDetector.get_threat_models_for_frameworks(
            ['django', 'sqlalchemy', 'react']
        )
        assert 'web' in threat_models
        assert 'api' in threat_models
        assert 'database' in threat_models


class TestDetectFromFile:
    """Test detect_from_file method."""

    def test_detect_from_file_python(self, tmp_path):
        """Test detecting frameworks from a Python file."""
        detector = FrameworkDetector()

        # Create a Python file with Django code
        test_file = tmp_path / "views.py"
        test_file.write_text("""
from django.http import HttpResponse
from django.views import View

class MyView(View):
    def get(self, request):
        return HttpResponse("Hello")
""")

        frameworks = detector.detect_from_file(test_file)
        assert 'django' in frameworks

    def test_detect_from_file_javascript(self, tmp_path):
        """Test detecting frameworks from a JavaScript file."""
        detector = FrameworkDetector()

        test_file = tmp_path / "app.js"
        test_file.write_text("""
const express = require('express');
const app = express();

app.get('/', (req, res) => {
    res.send('Hello World');
});
""")

        frameworks = detector.detect_from_file(test_file)
        assert 'express' in frameworks

    def test_detect_from_file_unsupported_extension(self, tmp_path):
        """Test that unsupported file extensions return empty list."""
        detector = FrameworkDetector()

        test_file = tmp_path / "readme.txt"
        test_file.write_text("This is a text file")

        frameworks = detector.detect_from_file(test_file)
        assert not frameworks

    def test_detect_from_file_nonexistent_file(self):
        """Test handling of non-existent files."""
        detector = FrameworkDetector()

        fake_file = Path("nonexistent.py")
        frameworks = detector.detect_from_file(fake_file)
        assert not frameworks

    def test_detect_from_file_unreadable_file(self, tmp_path):
        """Test handling of file read errors."""
        detector = FrameworkDetector()

        test_file = tmp_path / "test.py"
        test_file.write_text("from django import forms")

        # Mock file read to raise exception
        with patch('builtins.open', side_effect=IOError("Permission denied")):
            frameworks = detector.detect_from_file(test_file)
            assert not frameworks

    def test_detect_frameworks_with_invalid_language(self):
        """Test error handling for invalid language enum."""
        detector = FrameworkDetector()

        # This should handle the case where language conversion fails
        code = "from django import forms"

        # Force an exception by passing invalid data
        with patch('framework_detector.Language', side_effect=ValueError("Invalid")):
            frameworks = detector.detect_frameworks(code, 'invalid_lang')
            assert not frameworks

    def test_detect_frameworks_with_language_enum_but_no_patterns(self):
        """Test detecting frameworks with valid language enum but no patterns defined."""
        detector = FrameworkDetector()

        # Rust is a valid Language enum but has no patterns defined in PATTERNS dict
        rust_code = """
        fn main() {
            println!("Hello, world!");
        }
        """
        frameworks = detector.detect_frameworks(rust_code, "rust")
        assert not frameworks
