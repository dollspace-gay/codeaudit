#!/usr/bin/env python3
"""
AI-Powered Code Analyzer using Google Gemini
Detects bugs, performance issues, and code smells in your codebase
"""

import os
import sys
import argparse
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import google.generativeai as genai
from google.generativeai.types import generation_types
from colorama import init, Fore, Style
from prompts import PromptEngine
from framework_detector import FrameworkDetector
from few_shot_examples import FewShotExamples

# Initialize colorama for cross-platform colored output
init()

# Configure logging
def setup_logging() -> logging.Logger:
    """
    Configure logging for the application.

    Log level can be set via LOG_LEVEL environment variable.
    Valid values: DEBUG, INFO, WARNING, ERROR, CRITICAL
    Default: INFO
    """
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()

    # Validate log level
    numeric_level = getattr(logging, log_level, None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    # Configure logging format with colors for console
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    return logging.getLogger(__name__)

# Initialize logger
logger = setup_logging()

# Define a constant for the maximum file size to analyze
MAX_FILE_SIZE_MB = 1
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

class CodeAnalyzer:
    """
    AI-powered code analyzer using Google Gemini.

    Analyzes source code files for security vulnerabilities, bugs,
    performance issues, and code smells using AI-driven analysis
    with language-specific and framework-aware prompts.

    Attributes:
        model: Google Generative AI model instance
        generation_config: Configuration for JSON output
        supported_extensions: Set of file extensions to analyze
        prompt_engine: Template engine for dynamic prompts (or None if unavailable)
        framework_detector: Detector for identifying frameworks (or None if unavailable)
    """

    def __init__(self) -> None:
        """Initialize the code analyzer with Gemini AI and prompt system"""
        try:
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                logger.error("GEMINI_API_KEY environment variable not found")
                print(f"{Fore.RED}Error: GEMINI_API_KEY environment variable not found.{Style.RESET_ALL}")
                sys.exit(1)

            genai.configure(api_key=api_key)
            logger.info("Gemini AI configured successfully")

            # Use GenerationConfig to enforce JSON output for reliability
            self.generation_config = genai.GenerationConfig(
                response_mime_type="application/json"
            )
            self.model = genai.GenerativeModel(
                'gemini-2.5-flash',
                generation_config=self.generation_config
            )
            logger.debug("Generative model initialized: gemini-2.5-flash")

        except Exception as e:
            logger.error("Error configuring Gemini API: %s", e, exc_info=True)
            print(f"{Fore.RED}Error configuring the Gemini API: {e}{Style.RESET_ALL}")
            sys.exit(1)

        self.supported_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.cs',
            '.go', '.rs', '.php', '.rb', '.swift', '.kt', '.scala', '.dart'
        }
        logger.debug("Supported file extensions: %s", self.supported_extensions)

        # Initialize new prompt template system
        self.prompt_engine: Optional[PromptEngine]
        self.framework_detector: Optional[FrameworkDetector]
        try:
            self.prompt_engine = PromptEngine()
            self.framework_detector = FrameworkDetector()
            logger.info("Prompt template system initialized successfully")
            print(f"{Fore.GREEN}✓ Prompt template system initialized{Style.RESET_ALL}")
        except Exception as e:
            logger.warning("Could not initialize prompt system: %s. Falling back to basic prompts", e)
            print(f"{Fore.YELLOW}Warning: Could not initialize prompt system: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Falling back to basic prompts{Style.RESET_ALL}")
            self.prompt_engine = None
            self.framework_detector = None

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

    def _get_basic_prompt(self, file_path: Path, code_content: str, language: str) -> str:
        """Generate basic fallback prompt when template system unavailable."""
        return f"""
You are an expert code reviewer and static analysis tool. Analyze the following code for:
1. **Security Vulnerabilities**: SQL Injection, XSS, insecure deserialization, etc.
2. **Potential Bugs**: Null pointer exceptions, race conditions, off-by-one errors.
3. **Performance Issues**: Inefficient algorithms (O(n²)), unnecessary loops.
4. **Code Smells**: Long functions, duplicate code, high complexity, magic numbers.

The output MUST be a single, valid JSON object following the schema below. Do not include any text or markdown formatting before or after the JSON.

File: {file_path.name}
Language: {language}
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

        # Determine language from file extension
        language = file_path.suffix[1:] if file_path.suffix else 'unknown'

        # Use new prompt system if available
        if self.prompt_engine and self.framework_detector:
            try:
                # Detect frameworks
                frameworks = self.framework_detector.detect_frameworks(code_content, language)
                logger.debug("Detected frameworks for %s: %s", file_path.name, frameworks)

                # Get threat models based on frameworks
                threat_models = FrameworkDetector.get_threat_models_for_frameworks(frameworks)
                logger.debug("Threat models for %s: %s", file_path.name, threat_models)

                # Get few-shot examples
                few_shot_examples = FewShotExamples.get_security_examples(language, max_examples=2)
                logger.debug("Loaded %d few-shot examples for %s", len(few_shot_examples), language)

                # Generate prompt using template engine
                prompt = self.prompt_engine.get_prompt(
                    language=language,
                    code_content=code_content,
                    file_name=file_path.name,
                    frameworks=frameworks,
                    threat_models=threat_models,
                    few_shot_examples=few_shot_examples
                )
                logger.debug("Generated specialized prompt for %s", file_path.name)

            except Exception as e:
                # Fallback to basic prompt if template system fails
                logger.warning("Template system failed for %s, using basic prompt: %s", file_path.name, e)
                print(f"{Fore.YELLOW}Warning: Template system failed, using basic prompt: {e}{Style.RESET_ALL}")
                prompt = self._get_basic_prompt(file_path, code_content, language)
        else:
            # Use basic prompt if template system not initialized
            prompt = self._get_basic_prompt(file_path, code_content, language)

        try:
            logger.debug("Sending analysis request for %s", file_path.name)
            response = self.model.generate_content(prompt)
            # With response_mime_type="application/json", response.text is a clean JSON string.
            analysis = json.loads(response.text)
            analysis['file'] = str(file_path)
            logger.info("Successfully analyzed %s: %d issues found",
                       file_path.name, len(analysis.get('issues', [])))
            return analysis

        except json.JSONDecodeError as e:
            logger.error("JSON decode error for %s: %s", file_path.name, e)
            return {
                'file': str(file_path),
                'error': 'Failed to parse AI response as JSON despite requesting JSON format.',
                'raw_response': response.text[:1000] if 'response' in locals() else "No response received",
                'issues': []
            }
        except generation_types.BlockedPromptError as e:  # type: ignore[attr-defined]
            logger.warning("AI blocked prompt for %s: %s", file_path.name, e)
            return {
                'file': str(file_path),
                'error': 'AI analysis blocked. The prompt may contain sensitive content.',
                'issues': []
            }
        except Exception as e:
            logger.error("AI analysis failed for %s: %s", file_path.name, e, exc_info=True)
            return {
                'file': str(file_path),
                'error': f"AI analysis failed: {e}",
                'issues': []
            }

    def print_analysis_results(self, results: List[Dict[str, Any]]) -> None:
        """Print formatted analysis results"""
        total_files = len(results)
        total_issues = sum(len(result.get('issues', [])) for result in results)

        print(f"\n{Fore.CYAN}{'='*60}")
        print("CODE ANALYSIS COMPLETE")
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

    def save_results_json(self, results: List[Dict[str, Any]], output_file: Path) -> None:
        """Save analysis results to JSON file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            logger.info("Results saved to %s", output_file)
            print(f"\n💾 Results saved to: {output_file}")
        except Exception as e:
            logger.error("Error saving results to %s: %s", output_file, e, exc_info=True)
            print(f"\n{Fore.RED}Error saving results to {output_file}: {e}{Style.RESET_ALL}")

def validate_output_path(output_path_str: str) -> Optional[Path]:
    """Validate the output path to prevent directory traversal and overwrites."""
    if not output_path_str:
        return None

    path = Path(output_path_str).resolve()
    cwd = Path.cwd().resolve()

    if cwd not in path.parents and path.parent != cwd:
        logger.error("Output path '%s' is outside current directory tree", output_path_str)
        print(f"{Fore.RED}Error: Output path '{output_path_str}' is outside the current directory tree.{Style.RESET_ALL}")
        sys.exit(1)

    if path.exists() and path.is_file():
        logger.warning("Output file '%s' already exists, prompting user", path)
        overwrite = input(f"{Fore.YELLOW}Warning: Output file '{path}' already exists. Overwrite? (y/N): {Style.RESET_ALL}").lower()
        if overwrite != 'y':
            logger.info("User aborted overwrite")
            print("Aborted.")
            sys.exit(0)
        logger.info("User confirmed overwrite")

    return path

def main() -> None:
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

    logger.info("Starting CodeAudit analysis")
    logger.info("Target path: %s, recursive: %s, max_files: %s",
               args.path, args.recursive, args.max_files)

    validated_output_path = validate_output_path(args.output)

    print(f"{Fore.CYAN}🔍 AI-Powered Code Analyzer{Style.RESET_ALL}")
    print(f"Analyzing path: {args.path}")

    analyzer = CodeAnalyzer()
    files = analyzer.get_files_to_analyze(args.path, args.recursive)

    if not files:
        logger.warning("No supported code files found in: %s", args.path)
        print(f"{Fore.YELLOW}No supported code files found in: {args.path}{Style.RESET_ALL}")
        return

    logger.info("Found %d files to analyze", len(files))

    if len(files) > args.max_files:
        logger.info("Limiting analysis to first %d files (found %d total)", args.max_files, len(files))
        print(f"{Fore.YELLOW}Found {len(files)} files, analyzing first {args.max_files} (use --max-files to change){Style.RESET_ALL}")
        files = files[:args.max_files]

    print(f"Files to analyze: {len(files)}")

    results = []
    for i, file_path in enumerate(files, 1):
        sys.stdout.write(f"\r🔍 Analyzing {i}/{len(files)}: {file_path.name}{' ' * 20}")
        sys.stdout.flush()
        logger.debug("Processing file %d/%d: %s", i, len(files), file_path)
        result = analyzer.analyze_code_file(file_path)
        results.append(result)

    sys.stdout.write("\n")
    logger.info("Analysis complete: %d files processed", len(results))

    analyzer.print_analysis_results(results)

    if validated_output_path:
        analyzer.save_results_json(results, validated_output_path)

if __name__ == "__main__":
    main()
