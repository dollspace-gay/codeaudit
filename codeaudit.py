# -*- coding-utf-8 -*-
"""
AI-Powered Code Vulnerability Scanner using Google's Generative AI

This script recursively scans a project directory, reads the content of specified
file types, and uses Google's Generative AI to identify potential security
vulnerabilities and suggest fixes.

This version includes a robust JSON parsing and retry mechanism to handle
potential inconsistencies in the AI's output.

Author: Doll
Date: 2025-08-22
"""

import os
import re
import json
import time
import google.generativeai as genai
from typing import List, Dict, Any, Generator

# --- Configuration ---

# IMPORTANT: Replace with your actual Google AI API key.
# It is strongly recommended to use environment variables for production.
GOOGLE_API_KEY = "api-key-here"

# The path to the project codebase you want to scan.
# "." refers to the current directory where the script is run.
PROJECT_PATH = "./"

# The generative AI model to use for analysis.
# 'gemini-1.5-flash' is fast and capable. 'gemini-pro' is another solid option.
AI_MODEL = "gemini-2.5-flash"

# Number of times to retry calling the AI if JSON parsing fails.
MAX_RETRIES = 3

# List of file extensions to include in the scan.
# Add or remove extensions based on your project's technology stack.
FILES_TO_SCAN = [
    ".py", ".js", ".java", ".go", ".rb", ".php", ".ts", ".html",
    ".cs", ".c", ".cpp", ".sh", ".yaml", ".yml", ".tf", ".json"
]

# List of directories to exclude from the scan.
DIRS_TO_EXCLUDE = [
    "node_modules", ".git", "venv", "__pycache__", "dist", "build",
    "target", ".vscode", ".idea", "docs", "test", "tests", "bin", "obj"
]

# --- Main Script Logic ---

def configure_google_ai() -> None:
    """
    Configures the Google Generative AI client with the API key.
    Exits the script if the API key is not provided.
    """
    if GOOGLE_API_KEY == "YOUR_GOOGLE_AI_API_KEY" or not GOOGLE_API_KEY:
        print("Error: Google AI API key is not configured.")
        print("Please replace 'YOUR_GOOGLE_AI_API_KEY' with your actual key.")
        exit(1)
    try:
        genai.configure(api_key=GOOGLE_API_KEY)
    except Exception as e:
        print(f"Error configuring Google AI client: {e}")
        exit(1)

def find_code_files(path: str) -> Generator[str, None, None]:
    """
    Finds all code files in a directory that match the specified extensions,
    excluding specified directories.

    Args:
        path: The root directory to start scanning from.

    Yields:
        The full path to each code file found.
    """
    for root, dirs, files in os.walk(path):
        # Modify the dir list in-place to prevent os.walk from traversing them
        dirs[:] = [d for d in dirs if d not in DIRS_TO_EXCLUDE]

        for file in files:
            if any(file.endswith(ext) for ext in FILES_TO_SCAN):
                yield os.path.join(root, file)

def extract_json_from_text(text: str) -> str:
    """
    Extracts a JSON object from a string, even if it's embedded in
    markdown code blocks or other text.
    """
    # Look for JSON within ```json ... ``` markdown block
    match = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        return match.group(1)

    # If no markdown block, find the first '{' and last '}'
    start_index = text.find('{')
    end_index = text.rfind('}')
    if start_index != -1 and end_index != -1 and end_index > start_index:
        return text[start_index:end_index+1]
    
    # Fallback to returning the original text if no clear JSON is found
    return text

def analyze_code_with_ai(file_path: str, file_content: str) -> Dict[str, Any]:
    """
    Sends code to Google's Generative AI for analysis with a retry mechanism.

    Args:
        file_path: The path to the file being analyzed (for context).
        file_content: The actual source code to analyze.

    Returns:
        A dictionary containing the AI's analysis results or an error message.
    """
    model = genai.GenerativeModel(AI_MODEL)
    
    prompt = f"""
    You are an expert cybersecurity analyst. Your task is to perform a security audit on the following source code and respond ONLY with a valid JSON object. Do not include any introductory text or markdown formatting around the JSON.

    File Path: {file_path}

    Instructions:
    1.  Thoroughly analyze the code for security vulnerabilities (e.g., SQL Injection, XSS, Hardcoded Secrets, Command Injection, etc.).
    2.  Respond with a JSON object containing a single key: "vulnerabilities".
    3.  The "vulnerabilities" key should map to a list of objects. Each object represents one vulnerability found.
    4.  Each vulnerability object must have these exact keys: "line_number" (integer), "vulnerability_type" (string), "explanation" (string), and "suggested_fix" (string containing a code block or detailed steps).
    5.  If no vulnerabilities are found, return a JSON object with an empty list: {{"vulnerabilities": []}}.

    Source Code to Analyze:
    ```
    {file_content}
    ```
    """
    
    for attempt in range(MAX_RETRIES):
        try:
            print(f"[*] Analyzing {file_path} with AI (Attempt {attempt + 1}/{MAX_RETRIES})...")
            response = model.generate_content(prompt)
            raw_text = response.text
            
            json_string = extract_json_from_text(raw_text)
            
            return json.loads(json_string)
            
        except json.JSONDecodeError:
            print(f"  [!] Failed to decode JSON from AI response on attempt {attempt + 1}.")
            if attempt == MAX_RETRIES - 1:
                print(f"  [!] Exhausted all retries for {file_path}.")
                print(f"  [!] Last Raw AI Response:\n---\n{raw_text}\n---")
                return {"error": "Failed to decode JSON from AI after multiple retries."}
            time.sleep(2) # Wait for 2 seconds before retrying
            
        except Exception as e:
            print(f"  [!] An unexpected error occurred during AI analysis: {e}")
            return {"error": str(e)}
            
    return {"error": "AI analysis failed after all retries."}

def main() -> None:
    """
    Main function to orchestrate the code scanning and reporting process.
    """
    print("--- AI-Powered Code Vulnerability Scanner ---")
    configure_google_ai()

    if not os.path.isdir(PROJECT_PATH):
        print(f"Error: Project path '{PROJECT_PATH}' is not a valid directory.")
        return

    all_found_issues: List[Dict[str, Any]] = []
    files_to_scan = list(find_code_files(PROJECT_PATH))

    if not files_to_scan:
        print(f"No files matching the specified extensions found in '{PROJECT_PATH}'.")
        return

    print(f"[+] Found {len(files_to_scan)} files to scan.")

    for file_path in files_to_scan:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            if not content.strip():
                print(f"[*] Skipping empty file: {file_path}")
                continue

            analysis_result = analyze_code_with_ai(file_path, content)

            if "error" in analysis_result:
                print(f"  [-] Could not process {file_path}: {analysis_result['error']}")
                continue

            vulnerabilities = analysis_result.get("vulnerabilities", [])
            if vulnerabilities:
                print(f"  [!] Found {len(vulnerabilities)} potential issues in {file_path}")
                for issue in vulnerabilities:
                    issue['file_path'] = file_path
                    all_found_issues.append(issue)
            else:
                print(f"  [+] No issues found in {file_path}")

        except Exception as e:
            print(f"  [-] Failed to read or process file {file_path}: {e}")

    # --- Final Report ---
    if not all_found_issues:
        print("\n--- Scan Complete ---")
        print("[+] Excellent! The AI found no vulnerabilities in the scanned files.")
        return

    print(f"\n--- Scan Complete: Found {len(all_found_issues)} Total Potential Issues ---")
    for i, issue in enumerate(all_found_issues, 1):
        print(f"\n--- Issue {i}/{len(all_found_issues)} ---")
        print(f"File:               {issue['file_path']}")
        print(f"Line:               {issue.get('line_number', 'N/A')}")
        print(f"Vulnerability:      {issue.get('vulnerability_type', 'N/A')}")
        print("\n[+] Explanation:")
        print(issue.get('explanation', 'Not provided.'))
        print("\n[+] Suggested Fix:")
        print(issue.get('suggested_fix', 'Not provided.'))
        print("-" * 60)

if __name__ == "__main__":
    main()
