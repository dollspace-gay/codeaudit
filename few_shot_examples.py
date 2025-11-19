"""
Few-shot example system for improving AI code analysis accuracy.

Provides curated examples of common vulnerabilities and their fixes
to guide the AI model through few-shot learning.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class VulnerabilityExample:
    """
    Represents a vulnerability example for few-shot learning.

    Attributes:
        title: Short title of the vulnerability
        language: Programming language
        vulnerable_code: Example of vulnerable code
        issue: Description of the security issue
        fix: Secure code example or fix description
        severity: Severity level (high/medium/low)
        category: Vulnerability category (security/bug/performance/smell)
    """
    title: str
    language: str
    vulnerable_code: str
    issue: str
    fix: str
    severity: str = "high"
    category: str = "security"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for template rendering."""
        return {
            'title': self.title,
            'language': self.language,
            'vulnerable_code': self.vulnerable_code,
            'issue': self.issue,
            'fix': self.fix,
            'severity': self.severity,
            'category': self.category
        }


class FewShotExamples:
    """
    Database of vulnerability examples for few-shot learning.

    Provides language-specific and vulnerability-type-specific examples
    to improve AI detection accuracy.
    """

    # Python examples
    PYTHON_EXAMPLES = [
        VulnerabilityExample(
            title="SQL Injection via String Concatenation",
            language="python",
            vulnerable_code="""
user_input = request.GET['username']
query = f"SELECT * FROM users WHERE username = '{user_input}'"
cursor.execute(query)
            """.strip(),
            issue="SQL injection vulnerability. User input is directly interpolated into SQL query.",
            fix="""
user_input = request.GET['username']
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (user_input,))
            """.strip(),
            severity="high",
            category="security"
        ),
        VulnerabilityExample(
            title="Pickle Deserialization",
            language="python",
            vulnerable_code="""
import pickle
user_data = request.body
obj = pickle.loads(user_data)
            """.strip(),
            issue="Arbitrary code execution via pickle deserialization. Attacker can execute malicious code.",
            fix="""
import json
user_data = request.body
obj = json.loads(user_data)  # Use safe serialization
            """.strip(),
            severity="high",
            category="security"
        ),
        VulnerabilityExample(
            title="Command Injection",
            language="python",
            vulnerable_code="""
filename = request.GET['file']
os.system(f"cat {filename}")
            """.strip(),
            issue="Command injection vulnerability. User can execute arbitrary shell commands.",
            fix="""
import subprocess
filename = request.GET['file']
# Validate filename
if not filename.isalnum():
    raise ValueError("Invalid filename")
subprocess.run(["cat", filename], check=True)
            """.strip(),
            severity="high",
            category="security"
        ),
        VulnerabilityExample(
            title="Path Traversal",
            language="python",
            vulnerable_code="""
filename = request.GET['file']
with open(f"/uploads/{filename}", 'r') as f:
    content = f.read()
            """.strip(),
            issue="Path traversal vulnerability. User can access files outside intended directory using '../'.",
            fix="""
from pathlib import Path
filename = request.GET['file']
base_dir = Path("/uploads").resolve()
file_path = (base_dir / filename).resolve()
if base_dir not in file_path.parents:
    raise ValueError("Invalid file path")
with open(file_path, 'r') as f:
    content = f.read()
            """.strip(),
            severity="high",
            category="security"
        ),
        VulnerabilityExample(
            title="Mutable Default Argument",
            language="python",
            vulnerable_code="""
def add_item(item, items=[]):
    items.append(item)
    return items
            """.strip(),
            issue="Mutable default argument. The list is shared across function calls.",
            fix="""
def add_item(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items
            """.strip(),
            severity="medium",
            category="bug"
        ),
    ]

    # JavaScript examples
    JAVASCRIPT_EXAMPLES = [
        VulnerabilityExample(
            title="XSS via innerHTML",
            language="javascript",
            vulnerable_code="""
const username = req.query.name;
document.getElementById('greeting').innerHTML = `Hello ${username}!`;
            """.strip(),
            issue="Cross-Site Scripting (XSS) vulnerability. User input rendered as HTML.",
            fix="""
const username = req.query.name;
document.getElementById('greeting').textContent = `Hello ${username}!`;
            """.strip(),
            severity="high",
            category="security"
        ),
        VulnerabilityExample(
            title="Prototype Pollution",
            language="javascript",
            vulnerable_code="""
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}
            """.strip(),
            issue="Prototype pollution vulnerability. Attacker can pollute Object.prototype.",
            fix="""
function merge(target, source) {
    for (let key in source) {
        if (source.hasOwnProperty(key) && key !== '__proto__') {
            target[key] = source[key];
        }
    }
    return target;
}
            """.strip(),
            severity="high",
            category="security"
        ),
        VulnerabilityExample(
            title="NoSQL Injection",
            language="javascript",
            vulnerable_code="""
const username = req.body.username;
const user = await db.collection('users').findOne({ username: username });
            """.strip(),
            issue="NoSQL injection if username is an object like {'$ne': null}.",
            fix="""
const username = String(req.body.username);
const user = await db.collection('users').findOne({ username: username });
            """.strip(),
            severity="high",
            category="security"
        ),
    ]

    # Java examples
    JAVA_EXAMPLES = [
        VulnerabilityExample(
            title="SQL Injection in JDBC",
            language="java",
            vulnerable_code="""
String userId = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);
            """.strip(),
            issue="SQL injection vulnerability using Statement instead of PreparedStatement.",
            fix="""
String userId = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setString(1, userId);
ResultSet rs = pstmt.executeQuery();
            """.strip(),
            severity="high",
            category="security"
        ),
    ]

    @classmethod
    def get_examples(
        cls,
        language: str,
        max_examples: int = 3,
        category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get few-shot examples for a specific language.

        Args:
            language: Programming language (e.g., 'python', 'javascript')
            max_examples: Maximum number of examples to return
            category: Filter by category (security/bug/performance/smell)

        Returns:
            List of example dictionaries for template rendering
        """
        language = language.lower()

        # Select examples based on language
        if language == 'python':
            examples = cls.PYTHON_EXAMPLES
        elif language in ('javascript', 'js'):
            examples = cls.JAVASCRIPT_EXAMPLES
        elif language == 'java':
            examples = cls.JAVA_EXAMPLES
        else:
            # Return generic examples for unsupported languages
            examples = cls.PYTHON_EXAMPLES[:2]

        # Filter by category if specified
        if category:
            examples = [ex for ex in examples if ex.category == category]

        # Limit to max_examples
        examples = examples[:max_examples]

        return [ex.to_dict() for ex in examples]

    @classmethod
    def get_security_examples(cls, language: str, max_examples: int = 3) -> List[Dict[str, Any]]:
        """Get security-focused examples."""
        return cls.get_examples(language, max_examples, category='security')

    @classmethod
    def add_custom_example(cls, example: VulnerabilityExample) -> None:
        """
        Add a custom example to the database.

        Args:
            example: VulnerabilityExample instance

        Note:
            This is a runtime addition and will not persist across sessions.
            For persistent examples, add to the class attributes above.
        """
        language = example.language.lower()

        if language == 'python':
            cls.PYTHON_EXAMPLES.append(example)
        elif language in ('javascript', 'js'):
            cls.JAVASCRIPT_EXAMPLES.append(example)
        elif language == 'java':
            cls.JAVA_EXAMPLES.append(example)
