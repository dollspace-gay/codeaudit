#!/usr/bin/env python3
"""
AI-Powered Code Analyzer using Google Gemini
Detects bugs, performance issues, and code smells in your codebase
"""

import os
import sys
import argparse
import json
from pathlib import Path
from typing import List, Dict, Any
import google.generativeai as genai
from google.generativeai.types import generation_types
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

# Define a constant for the maximum file size to analyze
MAX_FILE_SIZE_MB = 1
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

class CodeAnalyzer:
    def __init__(self):
        """Initialize the code analyzer with Gemini AI"""
        try:
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                print(f"{Fore.RED}Error: GEMINI_API_KEY environment variable not found.{Style.RESET_ALL}")
                sys.exit(1)
            
            genai.configure(api_key=api_key)

            # Use GenerationConfig to enforce JSON output for reliability
            self.generation_config = genai.GenerationConfig(
                response_mime_type="application/json"
            )
            self.model = genai.GenerativeModel(
                'gemini-2.5-flash',
                generation_config=self.generation_config
            )

        except Exception as e:
            print(f"{Fore.RED}Error configuring the Gemini API: {e}{Style.RESET_ALL}")
            sys.exit(1)
        
        self.supported_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.cs', 
            '.go', '.rs', '.php', '.rb', '.swift', '.kt', '.scala', '.dart'
        }
        
    def get_files_to_analyze(self, path: str, recursive: bool = True) -> List[Path]:
        """Get all code files in the specified path, respecting ignore patterns."""
        path_obj = Path(path)
        files = []
        
        ignored_dirs = {'.git', 'node_modules', '__pycache__', 'build', 'dist', 'target'}
        
        if path_obj.is_file():
            if path_obj.suffix in self.supported_extensions:
                files.append(path_obj)
        elif path_obj.is_dir():
            pattern = "**/*" if recursive else "*"
            for file in path_obj.glob(pattern):
                if file.is_file() and file.suffix in self.supported_extensions:
                    if not any(part in ignored_dirs or part.startswith('.') for part in file.parts):
                        files.append(file)
        
        return files
    
    def analyze_code_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze a single code file for bugs and issues."""
        try:
            # Add file size check to prevent Denial of Service
            file_size = file_path.stat().st_size
            if file_size > MAX_FILE_SIZE_BYTES:
                return {
                    'file': str(file_path),
                    'error': f"File skipped: Exceeds size limit of {MAX_FILE_SIZE_MB}MB.",
                    'issues': []
                }
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()

        except Exception as e:
            return {
                'file': str(file_path),
                'error': f"Could not read file: {e}",
                'issues': []
            }
        
        prompt = f"""
You are an expert code reviewer and static analysis tool. Analyze the following code for:
1. **Security Vulnerabilities**: SQL Injection, XSS, insecure deserialization, etc.
2. **Potential Bugs**: Null pointer exceptions, race conditions, off-by-one errors.
3. **Performance Issues**: Inefficient algorithms (O(n²)), unnecessary loops.
4. **Code Smells**: Long functions, duplicate code, high complexity, magic numbers.

The output MUST be a single, valid JSON object following the schema below. Do not include any text or markdown formatting before or after the JSON.

File: {file_path.name}
Language: {file_path.suffix[1:]}
Code:
{code_content}

JSON Schema:
{{
    "issues": [
        {{
            "type": "security|bug|performance|smell",
            "severity": "high|medium|low",
            "line": <line_number>,
            "description": "Clear description of the issue.",
            "suggestion": "Specific refactoring suggestion with a code example if applicable."
        }}
    ],
    "summary": {{
        "total_issues": <number>,
        "high_severity": <number>,
        "medium_severity": <number>,
        "low_severity": <number>,
        "maintainability_score": "A score from 1 (poor) to 10 (excellent) with a brief one-sentence explanation."
    }}
}}
"""

        try:
            response = self.model.generate_content(prompt)
            # With response_mime_type="application/json", response.text is a clean JSON string.
            analysis = json.loads(response.text)
            analysis['file'] = str(file_path)
            return analysis

        except json.JSONDecodeError:
            return {
                'file': str(file_path),
                'error': 'Failed to parse AI response as JSON despite requesting JSON format.',
                'raw_response': response.text[:1000] if 'response' in locals() else "No response received",
                'issues': []
            }
        except generation_types.BlockedPromptError:
             return {
                'file': str(file_path),
                'error': 'AI analysis blocked. The prompt may contain sensitive content.',
                'issues': []
            }
        except Exception as e:
            return {
                'file': str(file_path),
                'error': f"AI analysis failed: {e}",
                'issues': []
            }
    
    def print_analysis_results(self, results: List[Dict[str, Any]]):
        """Print formatted analysis results"""
        total_files = len(results)
        total_issues = sum(len(result.get('issues', [])) for result in results)
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"CODE ANALYSIS COMPLETE")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        print(f"\n📊 {Fore.YELLOW}Summary:{Style.RESET_ALL}")
        print(f"   Files analyzed: {total_files}")
        print(f"   Total issues found: {total_issues}")
        
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for result in results:
            for issue in result.get('issues', []):
                severity = issue.get('severity', 'medium')
                severity_counts.setdefault(severity, 0)
                severity_counts[severity] += 1
        
        print(f"   🔴 High severity: {severity_counts.get('high', 0)}")
        print(f"   🟡 Medium severity: {severity_counts.get('medium', 0)}")
        print(f"   🟢 Low severity: {severity_counts.get('low', 0)}")
        
        for result in results:
            file_str = result.get('file', 'Unknown file')
            if result.get('error'):
                print(f"\n❌ {Fore.RED}{file_str}: {result['error']}{Style.RESET_ALL}")
                if 'raw_response' in result:
                    print(f"{Fore.YELLOW}   Raw Response Snippet: {result['raw_response']}{Style.RESET_ALL}")
                continue
                
            issues = result.get('issues', [])
            if not issues:
                print(f"\n✅ {Fore.GREEN}{file_str}: No issues found{Style.RESET_ALL}")
                continue
            
            print(f"\n📁 {Fore.CYAN}{file_str}{Style.RESET_ALL}")
            
            if 'summary' in result:
                summary = result['summary']
                print(f"   📈 Maintainability: {summary.get('maintainability_score', 'N/A')}")
            
            for issue in issues:
                severity = issue.get('severity', 'medium')
                line = issue.get('line', 'N/A')
                description = issue.get('description', 'No description')
                suggestion = issue.get('suggestion', 'No suggestion')
                severity_color = Fore.RED if severity == 'high' else Fore.YELLOW if severity == 'medium' else Fore.GREEN
                
                print(f"    - Line {line}: {severity_color}[{severity.upper()}]{Style.RESET_ALL} {description}")
                print(f"      💡 {Fore.CYAN}{suggestion}{Style.RESET_ALL}")

    def save_results_json(self, results: List[Dict[str, Any]], output_file: Path):
        """Save analysis results to JSON file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"\n💾 Results saved to: {output_file}")
        except Exception as e:
            print(f"\n{Fore.RED}Error saving results to {output_file}: {e}{Style.RESET_ALL}")

def validate_output_path(output_path_str: str) -> Path:
    """Validate the output path to prevent directory traversal and overwrites."""
    if not output_path_str:
        return None

    path = Path(output_path_str).resolve()
    cwd = Path.cwd().resolve()
    
    if cwd not in path.parents and path.parent != cwd:
        print(f"{Fore.RED}Error: Output path '{output_path_str}' is outside the current directory tree.{Style.RESET_ALL}")
        sys.exit(1)
    
    if path.exists() and path.is_file():
        overwrite = input(f"{Fore.YELLOW}Warning: Output file '{path}' already exists. Overwrite? (y/N): {Style.RESET_ALL}").lower()
        if overwrite != 'y':
            print("Aborted.")
            sys.exit(0)
            
    return path

def main():
    # --- FIX: Restored the complete and correct argparse setup ---
    parser = argparse.ArgumentParser(
        description='AI-Powered Code Analyzer for Bug Detection and Refactoring',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python code_analyzer.py .                    # Analyze current directory
  python code_analyzer.py ../server            # Analyze specific directory  
  python code_analyzer.py app.py               # Analyze single file
  python code_analyzer.py . --output report.json  # Save results to JSON
        """
    )
    
    parser.add_argument('path', nargs='?', default='.', 
                       help='Path to analyze (file or directory, default: current directory)')
    parser.add_argument('--recursive', '-r', action='store_true', default=True,
                       help='Recursively analyze subdirectories (default: True)')
    parser.add_argument('--output', '-o', type=str,
                       help='Save results to JSON file')
    parser.add_argument('--max-files', type=int, default=20,
                       help='Maximum number of files to analyze (default: 20)')
    
    args = parser.parse_args()
    
    validated_output_path = validate_output_path(args.output)
    
    print(f"{Fore.CYAN}🔍 AI-Powered Code Analyzer{Style.RESET_ALL}")
    print(f"Analyzing path: {args.path}")
    
    analyzer = CodeAnalyzer()
    files = analyzer.get_files_to_analyze(args.path, args.recursive)
    
    if not files:
        print(f"{Fore.YELLOW}No supported code files found in: {args.path}{Style.RESET_ALL}")
        return
    
    if len(files) > args.max_files:
        print(f"{Fore.YELLOW}Found {len(files)} files, analyzing first {args.max_files} (use --max-files to change){Style.RESET_ALL}")
        files = files[:args.max_files]
    
    print(f"Files to analyze: {len(files)}")
    
    results = []
    for i, file_path in enumerate(files, 1):
        sys.stdout.write(f"\r🔍 Analyzing {i}/{len(files)}: {file_path.name}{' ' * 20}")
        sys.stdout.flush()
        result = analyzer.analyze_code_file(file_path)
        results.append(result)
    
    sys.stdout.write("\n")
    
    analyzer.print_analysis_results(results)
    
    if validated_output_path:
        analyzer.save_results_json(results, validated_output_path)

if __name__ == "__main__":
    main()
