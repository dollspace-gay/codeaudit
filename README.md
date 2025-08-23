AI-Powered Code Vulnerability Scanner
This is a powerful and flexible command-line tool that leverages Google's Generative AI to perform security audits on your source code. It can scan individual files or entire directories, identify potential vulnerabilities, and provide detailed explanations and suggestions for fixing them.
Key Features
AI-Powered Analysis: Uses advanced generative AI models (like Gemini) to find a wide range of security vulnerabilities.
Flexible Targeting: Scan entire project folders, specific sub-directories, or individual files in a single run.
Concurrent Scanning: Utilizes multi-threading to analyze multiple files simultaneously, significantly speeding up scans on large projects.
Robust & Resilient: Includes an automatic retry mechanism to handle intermittent network or API issues.
Intelligent Parsing: Smartly extracts JSON data even when the AI's response includes markdown formatting.
Highly Configurable: Easily customize file types, excluded directories, AI models, and more.
How It Works
The scanner operates in a simple, four-step process:
File Discovery: The script identifies all target files based on the SCAN_PATHS configuration, respecting file extension filters and directory exclusions.
AI Analysis: The content of each file is sent to the Google Generative AI API with a carefully engineered prompt that instructs the AI to act as a cybersecurity expert.
Result Processing: The AI's response, a structured JSON object, is received and parsed. The script is designed to handle potential inconsistencies in the AI's output.
Reporting: A final report is generated in the console, detailing all potential vulnerabilities found, including the file path, line number, an explanation of the issue, and a suggested fix.
Requirements
Python 3.7+
An active Google AI API Key. You can get one from Google AI Studio.
⬇️ Setup and Installation
Follow these steps to get the scanner running on your local machine.
1. Get the Code
Clone this repository or simply download the codeaudit.py and requirements.txt files to a new directory.
2. Create a Virtual Environment (Recommended)
It's highly recommended to use a virtual environment to keep project dependencies isolated.
code
Bash
# Navigate to your project directory
cd /path/to/your/scanner

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
3. Install Dependencies
Install the necessary Python library using the requirements.txt file.
code
Bash
pip install -r requirements.txt
4. Configure Your API Key
The most secure way to handle your API key is to use an environment variable.
On macOS/Linux:
code
Bash
export GOOGLE_API_KEY="YOUR_API_KEY_HERE"
(To make this permanent, add the line to your ~/.bashrc, ~/.zshrc, or other shell profile file.)
On Windows (Command Prompt):
code
Bash
set GOOGLE_API_KEY="YOUR_API_KEY_HERE"
You will also need to modify one line in codeaudit.py to tell it to read this environment variable.
Change this line:
code
Python
GOOGLE_API_KEY = "api-key-here"
To this:
code
Python
import os
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
⚙️ Configuration
You can customize the scanner's behavior by editing the configuration variables at the top of the codeaudit.py script.
SCAN_PATHS: The most important setting. This is a list of paths to scan. You can mix and match directories and files.
code
Python
# Example: Scan a whole project, a specific folder, and one file
SCAN_PATHS = [
    "./my-web-app/",
    "./scripts/utils/",
    "./config/database.py"
]
AI_MODEL: The generative AI model to use. 'gemini-1.5-flash' is recommended for its balance of speed and capability.
MAX_WORKERS: The number of concurrent threads for scanning. A value between 5 and 15 is usually effective, but you can adjust it based on your machine's power.
FILES_TO_SCAN: A list of file extensions the scanner should look for. Add or remove extensions to match your project's tech stack.
DIRS_TO_EXCLUDE: A list of directory names to ignore. This is crucial for skipping dependency folders (node_modules), virtual environments (venv), and Git metadata (.git).
▶️ Usage
Once your configuration is set, simply run the script from your terminal:
code
Bash
python codeaudit.py
The scanner will print its progress as it discovers and analyzes files. When the scan is complete, it will present a final report of all issues found.
Sample Output
code
Code
--- AI-Powered Code Vulnerability Scanner ---
[+] Searching for files in directory: ./
[+] Found 5 total unique files to scan.
[+] Submitted 5 files for analysis. Waiting for results...
  [!] Found 1 potential issues in ./src/user_routes.py
  [+] No issues found in ./src/database.py
  [+] No issues found in ./src/app.py

--- Scan Complete: Found 1 Total Potential Issues ---

--- Issue 1/1 ---
File:               ./src/user_routes.py
Line:               42
Vulnerability:      SQL Injection

[+] Explanation:
The database query is constructed by directly formatting a user-provided 'username' string into the SQL statement. A malicious user could provide a crafted username like "' OR 1=1; --" to bypass authentication or manipulate the query.

[+] Suggested Fix:
Use parameterized queries (prepared statements) to safely pass user input to the database. The database driver will handle the proper escaping of characters, preventing injection attacks.

Example (using a library like psycopg2):
```python
cursor.execute("SELECT * FROM users WHERE username = %s;", (username,))
------------------------------------------------------------```
⚠️ Important Considerations
Security: Never commit your API key directly into your source code or share it publicly. Use environment variables as recommended.
Cost: API calls to Google's AI models are not free. Be mindful of the number and size of files you are scanning, as this will directly impact your costs.
Not a Replacement: This tool is a powerful aid for identifying potential security issues. It is not a substitute for professional human code reviews, thorough security audits, or established static analysis (SAST) tools.
False Positives/Negatives: Generative AI is not perfect. It may occasionally miss a vulnerability (a false negative) or flag safe code as vulnerable (a false positive). Always use the results as a starting point for your own investigation.