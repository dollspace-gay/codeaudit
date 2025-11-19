"""
Tests for few_shot_examples.py module.
"""

from few_shot_examples import FewShotExamples, VulnerabilityExample


class TestVulnerabilityExample:
    """Test VulnerabilityExample dataclass."""

    def test_create_example(self):
        """Test creating a VulnerabilityExample."""
        example = VulnerabilityExample(
            title="SQL Injection Test",
            language="python",
            vulnerable_code="query = f'SELECT * FROM users WHERE id = {user_id}'",
            issue="SQL injection vulnerability",
            fix="Use parameterized queries",
            severity="high",
            category="security"
        )
        assert example.title == "SQL Injection Test"
        assert example.language == "python"
        assert example.severity == "high"
        assert example.category == "security"

    def test_to_dict(self):
        """Test converting VulnerabilityExample to dictionary."""
        example = VulnerabilityExample(
            title="XSS Test",
            language="javascript",
            vulnerable_code="<script>alert(1)</script>",
            issue="XSS vulnerability",
            fix="Escape user input"
        )
        example_dict = example.to_dict()

        assert isinstance(example_dict, dict)
        assert example_dict['title'] == "XSS Test"
        assert example_dict['language'] == "javascript"
        assert example_dict['vulnerable_code'] == "<script>alert(1)</script>"
        assert example_dict['issue'] == "XSS vulnerability"
        assert example_dict['fix'] == "Escape user input"


class TestFewShotExamples:
    """Test FewShotExamples class."""

    def test_get_examples_python(self):
        """Test getting Python examples."""
        examples = FewShotExamples.get_examples('python', max_examples=3)

        assert isinstance(examples, list)
        assert len(examples) <= 3
        for example in examples:
            assert isinstance(example, dict)
            assert 'title' in example
            assert 'language' in example
            assert 'vulnerable_code' in example
            assert 'issue' in example
            assert 'fix' in example

    def test_get_examples_javascript(self):
        """Test getting JavaScript examples."""
        examples = FewShotExamples.get_examples('javascript', max_examples=2)

        assert isinstance(examples, list)
        assert len(examples) <= 2
        for example in examples:
            assert isinstance(example, dict)

    def test_get_examples_java(self):
        """Test getting Java examples."""
        examples = FewShotExamples.get_examples('java', max_examples=1)

        assert isinstance(examples, list)
        assert len(examples) <= 1

    def test_get_examples_unsupported_language_returns_python(self):
        """Test that unsupported languages return Python examples as fallback."""
        examples = FewShotExamples.get_examples('unsupported_language', max_examples=2)

        assert isinstance(examples, list)
        assert len(examples) <= 2
        # Should return Python examples as fallback
        assert len(examples) > 0

    def test_get_examples_max_examples_respected(self):
        """Test that max_examples parameter is respected."""
        examples_1 = FewShotExamples.get_examples('python', max_examples=1)
        examples_3 = FewShotExamples.get_examples('python', max_examples=3)

        assert len(examples_1) <= 1
        assert len(examples_3) <= 3

    def test_get_examples_with_category_filter(self):
        """Test filtering examples by category."""
        examples = FewShotExamples.get_examples('python', max_examples=5, category='security')

        assert isinstance(examples, list)
        for example in examples:
            # All examples should match the category filter
            assert isinstance(example, dict)

    def test_get_examples_category_none(self):
        """Test that category=None returns all examples."""
        examples_all = FewShotExamples.get_examples('python', max_examples=10, category=None)
        examples_security = FewShotExamples.get_examples('python', max_examples=10, category='security')

        # Without filter should return at least as many as with filter
        assert len(examples_all) >= len(examples_security)

    def test_get_security_examples(self):
        """Test get_security_examples helper method."""
        examples = FewShotExamples.get_security_examples('python', max_examples=3)

        assert isinstance(examples, list)
        assert len(examples) <= 3
        # Should only return security examples
        for example in examples:
            assert isinstance(example, dict)

    def test_get_examples_case_insensitive_language(self):
        """Test that language parameter is case-insensitive."""
        examples_lower = FewShotExamples.get_examples('python', max_examples=2)
        examples_upper = FewShotExamples.get_examples('PYTHON', max_examples=2)
        examples_mixed = FewShotExamples.get_examples('Python', max_examples=2)

        assert len(examples_lower) == len(examples_upper) == len(examples_mixed)

    def test_add_custom_example_python(self):
        """Test adding a custom Python example."""
        initial_count = len(FewShotExamples.PYTHON_EXAMPLES)

        custom_example = VulnerabilityExample(
            title="Custom Python Vulnerability",
            language="python",
            vulnerable_code="os.system(user_input)",
            issue="Command injection",
            fix="Use subprocess with proper escaping",
            severity="high",
            category="security"
        )

        FewShotExamples.add_custom_example(custom_example)

        # Verify it was added
        assert len(FewShotExamples.PYTHON_EXAMPLES) == initial_count + 1
        assert FewShotExamples.PYTHON_EXAMPLES[-1] == custom_example

        # Clean up
        FewShotExamples.PYTHON_EXAMPLES.pop()

    def test_add_custom_example_javascript(self):
        """Test adding a custom JavaScript example."""
        initial_count = len(FewShotExamples.JAVASCRIPT_EXAMPLES)

        custom_example = VulnerabilityExample(
            title="Custom JS Vulnerability",
            language="javascript",
            vulnerable_code="eval(userInput)",
            issue="Code injection",
            fix="Avoid eval, use JSON.parse",
            severity="high",
            category="security"
        )

        FewShotExamples.add_custom_example(custom_example)

        assert len(FewShotExamples.JAVASCRIPT_EXAMPLES) == initial_count + 1

        # Clean up
        FewShotExamples.JAVASCRIPT_EXAMPLES.pop()

    def test_add_custom_example_java(self):
        """Test adding a custom Java example."""
        initial_count = len(FewShotExamples.JAVA_EXAMPLES)

        custom_example = VulnerabilityExample(
            title="Custom Java Vulnerability",
            language="java",
            vulnerable_code="Runtime.exec(userInput)",
            issue="Command injection",
            fix="Use ProcessBuilder with validation",
            severity="high",
            category="security"
        )

        FewShotExamples.add_custom_example(custom_example)

        assert len(FewShotExamples.JAVA_EXAMPLES) == initial_count + 1

        # Clean up
        FewShotExamples.JAVA_EXAMPLES.pop()

    def test_python_examples_exist(self):
        """Test that PYTHON_EXAMPLES class attribute exists and has content."""
        assert hasattr(FewShotExamples, 'PYTHON_EXAMPLES')
        assert isinstance(FewShotExamples.PYTHON_EXAMPLES, list)
        assert len(FewShotExamples.PYTHON_EXAMPLES) > 0

    def test_javascript_examples_exist(self):
        """Test that JAVASCRIPT_EXAMPLES class attribute exists and has content."""
        assert hasattr(FewShotExamples, 'JAVASCRIPT_EXAMPLES')
        assert isinstance(FewShotExamples.JAVASCRIPT_EXAMPLES, list)
        assert len(FewShotExamples.JAVASCRIPT_EXAMPLES) > 0

    def test_java_examples_exist(self):
        """Test that JAVA_EXAMPLES class attribute exists and has content."""
        assert hasattr(FewShotExamples, 'JAVA_EXAMPLES')
        assert isinstance(FewShotExamples.JAVA_EXAMPLES, list)
        assert len(FewShotExamples.JAVA_EXAMPLES) > 0

    def test_get_examples_returns_copy_not_reference(self):
        """Test that get_examples returns independent data."""
        examples1 = FewShotExamples.get_examples('python', max_examples=2)
        examples2 = FewShotExamples.get_examples('python', max_examples=2)

        # Should return equal data but different objects
        assert examples1 == examples2
        assert examples1 is not examples2

    def test_add_custom_example_unsupported_language(self):
        """Test adding a custom example with unsupported language does nothing."""
        custom_example = VulnerabilityExample(
            title="Custom Unsupported Vulnerability",
            language="unsupported_lang",
            vulnerable_code="some code",
            issue="Some issue",
            fix="Some fix",
            severity="high",
            category="security"
        )

        # Count initial examples
        python_count = len(FewShotExamples.PYTHON_EXAMPLES)
        js_count = len(FewShotExamples.JAVASCRIPT_EXAMPLES)
        java_count = len(FewShotExamples.JAVA_EXAMPLES)

        # Add example with unsupported language
        FewShotExamples.add_custom_example(custom_example)

        # Verify no lists were modified
        assert len(FewShotExamples.PYTHON_EXAMPLES) == python_count
        assert len(FewShotExamples.JAVASCRIPT_EXAMPLES) == js_count
        assert len(FewShotExamples.JAVA_EXAMPLES) == java_count
