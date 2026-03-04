#!/usr/bin/env python3
"""Shadow AI Scanner v0.1

Scans a codebase for signs of "Shadow AI" usage:
1. Exposed API Keys (OpenAI, Anthropic, Google, etc.)
2. AI Library Imports (langchain, openai, anthropic, etc.)
3. Hardcoded Prompts (strings that look like LLM prompts)

Usage:
  python3 scanner.py /path/to/repo
  python3 scanner.py .  --json
  python3 scanner.py /path/to/repo --output report.json

Author: Arx Intelligence (https://arx-intelligence.lu)
License: MIT
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Any

# ============================================================================
# PATTERNS
# ============================================================================

API_KEY_PATTERNS = {
    "OpenAI": r"sk-[a-zA-Z0-9]{20,}",
    "OpenAI Project": r"sk-proj-[a-zA-Z0-9\-_]{50,}",
    "Anthropic": r"sk-ant-[a-zA-Z0-9\-_]{50,}",
    "Google AI": r"AIza[a-zA-Z0-9\-_]{35,}",
    "Cohere": r"[a-zA-Z0-9]{40}",  # Generic, needs context
    "HuggingFace": r"hf_[a-zA-Z0-9]{30,}",
    "Pinecone": r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",  # UUID-like
    "DeepSeek": r"sk-[a-zA-Z0-9]{32}",  # Common format for newer providers
    "DashScope (Qwen)": r"sk-[a-zA-Z0-9]{32}",
}

AI_LIBRARY_PATTERNS = {
    "Python": [
        r"^\s*import\s+(openai|anthropic|langchain|cohere|pinecone|weaviate|chromadb|llama_index|transformers|torch|tensorflow|mlx|ollama)",
        r"^\s*from\s+(openai|anthropic|langchain|cohere|pinecone|weaviate|chromadb|llama_index|transformers|torch|tensorflow|mlx|ollama)\s+import",
        r"^\s*import\s+google\.generativeai",
        r"^\s*from\s+google\.generativeai\s+import",
    ],
    "JavaScript/TypeScript": [
        r"require\(['\"](@?openai|@anthropic|langchain|@pinecone|cohere|@tensorflow|onnxruntime-node|ollama)['\"]\)",
        r"import\s+.*\s+from\s+['\"](@?openai|@anthropic|langchain|@pinecone|cohere|@tensorflow|onnxruntime-node|ollama)['\"]",
    ],
}

PROMPT_PATTERNS = [
    r"You are a helpful assistant",
    r"You are an AI",
    r"As an AI language model",
    r"system\s*:\s*['\"].*['\"]",
    r"role\s*:\s*['\"]system['\"]",
    r"\.chat\.completions\.create\(",
    r"\.messages\.create\(",
    r"ChatCompletion\.create\(",
]

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".json", ".yaml", ".yml", ".toml", ".env", ".sh", ".bash",
    ".md", ".txt", ".ini", ".cfg", ".conf",
}

# Files to skip (false positive sources)
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "Pipfile.lock", "composer.lock",
}

# Directories to skip
SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env", "dist", "build", ".next", ".nuxt", "coverage",
}


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class Finding:
    type: str  # "api_key", "library", "prompt"
    category: str  # e.g., "OpenAI", "langchain"
    file: str
    line: int
    snippet: str
    severity: str  # "critical", "high", "medium", "low"


@dataclass
class ScanReport:
    target: str
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        key = f"{finding.type}:{finding.category}"
        self.summary[key] = self.summary.get(key, 0) + 1

    def to_markdown(self) -> str:
        """Generate a professional Markdown report."""
        md = [
            "# 🛡️ Shadow AI Exposure Report",
            f"\n**Target:** `{self.target}`  ",
            f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Files Scanned:** {self.files_scanned}  ",
            f"**Total Indicators Found:** {len(self.findings)}  \n",
            "---",
            "\n## 📊 Executive Summary",
            "This report identifies potential 'Shadow AI' usage—unauthorized or unmanaged AI integration that could lead to data leakage, regulatory non-compliance (EU AI Act), or security vulnerabilities.\n"
        ]

        # Summary Table
        md.append("| Category | Indicator Type | Count | Severity |")
        md.append("| :--- | :--- | :--- | :--- |")
        
        # Sort by severity priority
        severity_map = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_summary = sorted(self.summary.items(), key=lambda x: x[0])
        
        for key, count in sorted_summary:
            indicator_type, category = key.split(":")
            severity = "Low"
            if indicator_type == "api_key": severity = "🔴 CRITICAL"
            elif indicator_type == "library": severity = "🟡 MEDIUM"
            elif indicator_type == "prompt": severity = "⚪ LOW"
            md.append(f"| {category} | {indicator_type.replace('_', ' ').title()} | {count} | {severity} |")

        # Detailed Findings
        if self.findings:
            md.append("\n---")
            md.append("\n## 🔍 Detailed Findings")
            
            # Group by severity
            for sev in ["critical", "high", "medium", "low"]:
                findings = [f for f in self.findings if f.severity == sev]
                if not findings: continue
                
                label = sev.upper()
                if sev == "critical": label = "🚨 CRITICAL (Immediate Action Required)"
                md.append(f"\n### {label}")
                
                for f in findings:
                    md.append(f"- **{f.category}** in `{f.file}:{f.line}`")
                    md.append(f"  > `{f.snippet}`\n")

        md.append("\n---")
        md.append("\n## ⚖️ Regulatory Context (EU AI Act)")
        md.append("- **High-Risk Classification:** Unmanaged AI usage in financial services can categorize your entity as a 'deployer' of high-risk AI (Annex III), triggering mandatory fundamental rights impact assessments.")
        md.append("- **Transparency (Art. 50):** Unauthorized chatbots or AI-generated content must be disclosed. Failure to detect 'Shadow AI' makes compliance impossible.")
        
        md.append("\n## 💡 Recommendations")
        md.append("1. **Sanitize Codebase:** Rotate and remove all exposed API keys immediately.")
        md.append("2. **Implement AI Policy:** Deploy an Acceptable Use Policy (AUP) for all employees.")
        md.append("3. **Continuous Monitoring:** Integrate this scanner into your CI/CD pipeline.")
        
        md.append(f"\n\n*Generated by Arx Intelligence — Luxembourg's AI Compliance Partner*  ")
        md.append("*[arx-intelligence.lu](https://arx-intelligence.lu)*")
        
        return "\n".join(md)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "total_findings": len(self.findings),
            "summary": self.summary,
            "findings": [asdict(f) for f in self.findings],
        }


# ============================================================================
# SCANNER
# ============================================================================

def should_scan_file(path: Path) -> bool:
    """Check if file should be scanned."""
    if path.suffix.lower() not in SCAN_EXTENSIONS:
        return False
    # Skip binary files
    if path.suffix.lower() in {".pyc", ".pyo", ".so", ".dll", ".exe"}:
        return False
    # Skip lock files (false positive sources)
    if path.name in SKIP_FILES:
        return False
    return True


def scan_file(path: Path, report: ScanReport) -> None:
    """Scan a single file for Shadow AI indicators."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return

    lines = content.splitlines()
    file_str = str(path)

    for line_num, line in enumerate(lines, start=1):
        # 1. Check for API Keys
        for key_type, pattern in API_KEY_PATTERNS.items():
            if re.search(pattern, line):
                # Avoid false positives (comments, examples)
                if "example" in line.lower() or "xxx" in line.lower():
                    continue
                snippet = line.strip()[:100]
                # Mask the actual key
                snippet = re.sub(pattern, f"[REDACTED {key_type} KEY]", snippet)
                report.add_finding(Finding(
                    type="api_key",
                    category=key_type,
                    file=file_str,
                    line=line_num,
                    snippet=snippet,
                    severity="critical",
                ))

        # 2. Check for AI Library Imports
        for lang, patterns in AI_LIBRARY_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    report.add_finding(Finding(
                        type="library",
                        category=match.group(1) if match.lastindex else "unknown",
                        file=file_str,
                        line=line_num,
                        snippet=line.strip()[:100],
                        severity="medium",
                    ))

        # 3. Check for Hardcoded Prompts
        for pattern in PROMPT_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                report.add_finding(Finding(
                    type="prompt",
                    category="hardcoded_prompt",
                    file=file_str,
                    line=line_num,
                    snippet=line.strip()[:100],
                    severity="low",
                ))
                break  # Only report once per line


def scan_directory(target: Path, report: ScanReport) -> None:
    """Recursively scan a directory."""
    for root, dirs, files in os.walk(target):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            fpath = Path(root) / fname
            if should_scan_file(fpath):
                report.files_scanned += 1
                scan_file(fpath, report)


# ============================================================================
# OUTPUT
# ============================================================================

def print_report(report: ScanReport, as_json: bool = False) -> None:
    """Print the scan report."""
    if as_json:
        print(json.dumps(report.to_dict(), indent=2))
        return

    print("\n" + "=" * 60)
    print("🔍 SHADOW AI SCANNER - REPORT")
    print("=" * 60)
    print(f"Target: {report.target}")
    print(f"Files scanned: {report.files_scanned}")
    print(f"Total findings: {len(report.findings)}")
    print("-" * 60)

    if not report.findings:
        print("✅ No Shadow AI indicators found. You're clean!")
        return

    # Group by severity
    critical = [f for f in report.findings if f.severity == "critical"]
    high = [f for f in report.findings if f.severity == "high"]
    medium = [f for f in report.findings if f.severity == "medium"]
    low = [f for f in report.findings if f.severity == "low"]

    if critical:
        print("\n🚨 CRITICAL (Exposed API Keys):")
        for f in critical:
            print(f"  [{f.category}] {f.file}:{f.line}")
            print(f"    → {f.snippet}")

    if high:
        print("\n⚠️  HIGH:")
        for f in high:
            print(f"  [{f.category}] {f.file}:{f.line}")

    if medium:
        print("\n📦 MEDIUM (AI Libraries Detected):")
        libs = set(f.category for f in medium)
        print(f"  Libraries found: {', '.join(libs)}")
        for f in medium[:5]:  # Show first 5
            print(f"    {f.file}:{f.line} → {f.snippet[:60]}")
        if len(medium) > 5:
            print(f"    ... and {len(medium) - 5} more")

    if low:
        print("\n📝 LOW (Hardcoded Prompts):")
        for f in low[:3]:  # Show first 3
            print(f"  {f.file}:{f.line} → {f.snippet[:60]}")
        if len(low) > 3:
            print(f"  ... and {len(low) - 3} more")

    print("\n" + "=" * 60)
    print("📊 SUMMARY")
    print("-" * 60)
    for key, count in sorted(report.summary.items()):
        print(f"  {key}: {count}")
    print("=" * 60)
    print("\n💡 Next steps: Contact Arx Intelligence for a full audit.")
    print("   → https://www.linkedin.com/in/eric-carneiro-arx/")
    print()


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Shadow AI Scanner - Detect AI usage in your codebase"
    )
    parser.add_argument("target", help="Directory or file to scan")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--md", action="store_true", help="Output as professional Markdown report")
    parser.add_argument("--output", "-o", help="Write report to file")
    args = parser.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Error: {target} does not exist", file=sys.stderr)
        return 1

    report = ScanReport(target=str(target))

    if target.is_file():
        report.files_scanned = 1
        scan_file(target, report)
    else:
        scan_directory(target, report)

    if args.output:
        if args.md:
            Path(args.output).write_text(report.to_markdown(), encoding="utf-8")
        else:
            Path(args.output).write_text(
                json.dumps(report.to_dict(), indent=2), encoding="utf-8"
            )
        print(f"Report written to {args.output}")
    elif args.md:
        print(report.to_markdown())
    else:
        print_report(report, as_json=args.json)

    # Exit code: 0 if clean, 1 if critical findings
    return 1 if any(f.severity == "critical" for f in report.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
