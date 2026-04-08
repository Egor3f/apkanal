#!/usr/bin/env python3
"""apkanal — Android APK Backdoor Analyzer.

Pulls APKs via ADB, decompiles with jadx, and analyzes for backdoor-like
code using Claude (via Claude Code CLI).
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from tui import run_tui, run_interactive_tui
from config import (
    EXCLUDED_FILE_PATTERNS,
    EXCLUDED_PACKAGES,
    FINDINGS_SCHEMA,
    MANIFEST_SCHEMA,
    MAX_CHUNK_CHARS,
    PARALLEL_CHUNKS,
    STRIP_IMPORTS,
    STRIP_METADATA,
    SUSPICION_PATTERNS,
    SYSTEM_PROMPT_ANALYSIS,
    SYSTEM_PROMPT_INTERACTIVE,
    SYSTEM_PROMPT_MANIFEST,
)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PatternMatch:
    category: str
    pattern_name: str
    line_number: int
    line_content: str
    weight: int


@dataclass
class SourceFile:
    path: Path
    relative_path: str
    package: str
    content: str
    size: int
    score: int = 0
    matches: list[PatternMatch] = field(default_factory=list)


@dataclass
class Chunk:
    files: list[SourceFile]
    total_chars: int
    max_score: int
    packages: list[str]


@dataclass
class Finding:
    severity: str
    title: str
    description: str
    file_path: str
    code_snippet: str
    confidence: float
    category: str


@dataclass
class UsageStats:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    cost_usd: float = 0.0
    calls: int = 0

    def update(self, wrapper: dict):
        usage = wrapper.get("usage", {})
        self.input_tokens += usage.get("input_tokens", 0)
        self.output_tokens += usage.get("output_tokens", 0)
        self.cache_read_tokens += usage.get("cache_read_input_tokens", 0)
        self.cache_creation_tokens += usage.get("cache_creation_input_tokens", 0)
        self.cost_usd += wrapper.get("total_cost_usd", 0.0)
        self.calls += 1

    def summary(self) -> str:
        total_in = self.input_tokens + self.cache_read_tokens + self.cache_creation_tokens
        return (f"tokens: {total_in:,} in + {self.output_tokens:,} out "
                f"| cost: ${self.cost_usd:.4f} | calls: {self.calls}")


# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------

class C:
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def severity_color(sev: str) -> str:
    return {
        "CRITICAL": C.RED + C.BOLD,
        "HIGH": C.RED,
        "MEDIUM": C.YELLOW,
        "LOW": C.GREEN,
        "INFO": C.DIM,
    }.get(sev, "")


def log(msg: str, prefix: str = "*"):
    print(f"{C.CYAN}[{prefix}]{C.RESET} {msg}")


def warn(msg: str):
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def error(msg: str):
    print(f"{C.RED}[ERROR]{C.RESET} {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# ADB helpers
# ---------------------------------------------------------------------------

def check_adb() -> bool:
    try:
        r = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=5)
        lines = [l for l in r.stdout.strip().splitlines()[1:] if l.strip()]
        if not lines:
            error("No Android device connected. Connect a device and enable USB debugging.")
            return False
        return True
    except FileNotFoundError:
        error("adb not found in PATH. Install Android SDK platform-tools.")
        return False


def list_packages(search: str | None = None, third_party: bool = False) -> list[str]:
    """Return sorted list of package names."""
    cmd = ["adb", "shell", "pm", "list", "packages"]
    if third_party:
        cmd.append("-3")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        error(f"Failed to list packages: {r.stderr}")
        return []
    pkgs = sorted(l.removeprefix("package:") for l in r.stdout.strip().splitlines())
    if search:
        search_l = search.lower()
        pkgs = [p for p in pkgs if search_l in p.lower()]
    return pkgs



def pull_apk(package: str, output_dir: Path) -> Path | None:
    log(f"Resolving APK path for {package}...")
    r = subprocess.run(
        ["adb", "shell", "pm", "path", package],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0 or not r.stdout.strip():
        error(f"Package not found: {package}")
        return None

    # May have multiple APKs (split APKs); take the base
    apk_paths = [l.removeprefix("package:") for l in r.stdout.strip().splitlines()]
    device_path = apk_paths[0]
    for p in apk_paths:
        if "base" in p.lower():
            device_path = p
            break

    local_path = output_dir / f"{package}.apk"
    log(f"Pulling {device_path}...")
    r = subprocess.run(
        ["adb", "pull", device_path, str(local_path)],
        capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        error(f"Failed to pull APK: {r.stderr}")
        return None

    size_mb = local_path.stat().st_size / (1024 * 1024)
    log(f"Pulled {local_path.name} ({size_mb:.1f} MB)")
    return local_path


# ---------------------------------------------------------------------------
# Decompilation
# ---------------------------------------------------------------------------

DECOMPILE_DONE_MARKER = ".decompile_done"


def decompile_apk(apk_path: Path, output_dir: Path) -> tuple[Path, str]:
    """Decompile APK. Returns (output_dir, tool_used). Skips if already done."""
    marker = output_dir / DECOMPILE_DONE_MARKER

    # Already decompiled successfully — detect which tool was used
    if marker.exists():
        tool = marker.read_text().strip() or "jadx"
        log(f"Using existing decompilation ({tool})")
        return output_dir, tool

    # Clean up any partial decompilation from a previous interrupted run
    if output_dir.exists():
        warn("Removing incomplete decompilation from previous run...")
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    jadx = shutil.which("jadx")
    if jadx:
        log("Decompiling with jadx (this may take a minute)...")
        r = subprocess.run(
            [jadx, "--no-debug-info", str(apk_path), "-d", str(output_dir)],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode == 0 or any((output_dir / d).exists() for d in ["sources", "resources"]):
            marker.write_text("jadx")
            return output_dir, "jadx"
        warn(f"jadx failed: {r.stderr[:200]}")

    apktool = shutil.which("apktool")
    if apktool:
        warn("Falling back to apktool (smali output — lower analysis quality)")
        # Clean jadx leftovers if any
        if output_dir.exists():
            shutil.rmtree(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            [apktool, "d", str(apk_path), "-o", str(output_dir), "-f"],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode == 0:
            marker.write_text("apktool")
            return output_dir, "apktool"
        error(f"apktool failed: {r.stderr[:200]}")

    error("No decompiler available. Install jadx: brew install jadx")
    sys.exit(1)


def find_manifest(decompile_dir: Path, tool: str) -> Path | None:
    candidates = [
        decompile_dir / "resources" / "AndroidManifest.xml",  # jadx
        decompile_dir / "AndroidManifest.xml",                 # apktool
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def is_excluded_path(relative: str) -> bool:
    for prefix in EXCLUDED_PACKAGES:
        if relative.startswith(prefix):
            return True
    basename = Path(relative).name
    for pattern in EXCLUDED_FILE_PATTERNS:
        if pattern in basename:
            return True
    return False


def collect_source_files(decompile_dir: Path, tool: str) -> list[SourceFile]:
    ext = ".java" if tool == "jadx" else ".smali"
    sources_dir = decompile_dir / "sources" if tool == "jadx" else decompile_dir / "smali"
    if not sources_dir.exists():
        sources_dir = decompile_dir  # fallback

    files = []
    for p in sources_dir.rglob(f"*{ext}"):
        relative = str(p.relative_to(sources_dir))
        if is_excluded_path(relative):
            continue
        try:
            raw = p.read_text(errors="replace")
            if STRIP_METADATA:
                raw = re.sub(r'@Metadata\([^)]*\)\n?', '', raw, flags=re.DOTALL)
            lines = []
            for line in raw.splitlines():
                stripped = line.lstrip()
                if STRIP_IMPORTS and stripped.startswith("import "):
                    continue
                lines.append(stripped)
            content = "\n".join(lines)
        except OSError:
            continue
        package = str(Path(relative).parent).replace(os.sep, ".")
        files.append(SourceFile(
            path=p,
            relative_path=relative,
            package=package,
            content=content,
            size=len(content),
        ))
    return files


# ---------------------------------------------------------------------------
# Suspicion scoring
# ---------------------------------------------------------------------------

def score_file(sf: SourceFile) -> SourceFile:
    total = 0
    matches = []
    for category, patterns in SUSPICION_PATTERNS.items():
        for regex, weight, desc in patterns:
            for i, line in enumerate(sf.content.splitlines(), 1):
                if re.search(regex, line):
                    matches.append(PatternMatch(category, desc, i, line.strip()[:120], weight))
                    total += weight
                    break  # one match per pattern per file is enough
    sf.score = min(100, total)
    sf.matches = matches
    return sf


def prescan_files(files: list[SourceFile]) -> list[SourceFile]:
    for f in files:
        score_file(f)
    files.sort(key=lambda f: f.score, reverse=True)
    return files


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------

def build_chunks(files: list[SourceFile], min_score: int = 0) -> list[Chunk]:
    # Filter by minimum score
    candidates = [f for f in files if f.score >= min_score]
    if not candidates:
        return []

    # Group by package
    pkg_groups: dict[str, list[SourceFile]] = {}
    for f in candidates:
        pkg_groups.setdefault(f.package, []).append(f)

    # Sort packages by max score in group
    sorted_pkgs = sorted(
        pkg_groups.items(),
        key=lambda kv: max(f.score for f in kv[1]),
        reverse=True,
    )

    chunks: list[Chunk] = []
    current_files: list[SourceFile] = []
    current_chars = 0
    current_pkgs: list[str] = []

    for pkg, group_files in sorted_pkgs:
        for sf in sorted(group_files, key=lambda f: f.score, reverse=True):
            if current_chars + sf.size > MAX_CHUNK_CHARS and current_files:
                chunks.append(Chunk(
                    files=current_files,
                    total_chars=current_chars,
                    max_score=max(f.score for f in current_files),
                    packages=current_pkgs,
                ))
                current_files = []
                current_chars = 0
                current_pkgs = []

            current_files.append(sf)
            current_chars += sf.size
            if pkg not in current_pkgs:
                current_pkgs.append(pkg)

    if current_files:
        chunks.append(Chunk(
            files=current_files,
            total_chars=current_chars,
            max_score=max(f.score for f in current_files),
            packages=current_pkgs,
        ))

    return chunks


# Package name for log filenames (set in main)
_current_package: str = ""

# ---------------------------------------------------------------------------
# LLM response cache
# ---------------------------------------------------------------------------

CACHE_DIR = Path("apkanal_output") / ".cache"


def _cache_key(prompt: str, system_prompt: str, model: str,
               json_schema: dict | None) -> str:
    h = hashlib.sha256()
    h.update(prompt.encode())
    h.update(system_prompt.encode())
    h.update(model.encode())
    if json_schema:
        h.update(json.dumps(json_schema, sort_keys=True).encode())
    return h.hexdigest()


def _cache_get(key: str) -> dict | str | None:
    path = CACHE_DIR / f"{key}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return data.get("result")
    except (json.JSONDecodeError, KeyError):
        return None


def _cache_put(key: str, result: dict | str):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / f"{key}.json"
    path.write_text(json.dumps({"result": result}, indent=2, default=str))


# ---------------------------------------------------------------------------
# Claude Code CLI integration
# ---------------------------------------------------------------------------

def claude_analyze(prompt: str, system_prompt: str, json_schema: dict | None = None,
                   model: str = "sonnet", usage: UsageStats | None = None,
                   cache: bool = True) -> dict | str:
    """Call claude -p and return parsed JSON or raw text."""
    # Check cache
    key = None
    if cache:
        key = _cache_key(prompt, system_prompt, model, json_schema)
        cached = _cache_get(key)
        if cached is not None:
            log(f"{C.DIM}(cached){C.RESET}")
            return cached
    # Log request/response for debugging
    log_dir = Path("apkanal_output") / ".logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    log_prefix = f"{_current_package}_{ts}" if _current_package else f"unknown_{ts}"

    req_path = log_dir / f"{log_prefix}_req.txt"
    req_path.write_text(f"=== MODEL: {model} ===\n\n=== SYSTEM PROMPT ===\n{system_prompt}\n\n"
                        f"=== JSON SCHEMA ===\n{json.dumps(json_schema, indent=2) if json_schema else 'none'}\n\n"
                        f"=== PROMPT ===\n{prompt}\n")

    cmd = [
        "claude", "-p",
        "--model", model,
        "--system-prompt", system_prompt,
        "--tools", "",              # disable tools — pure text analysis
        "--no-session-persistence", # don't save throwaway sessions
    ]

    # Always get JSON wrapper so we can parse usage stats
    if json_schema:
        cmd += ["--output-format", "json", "--json-schema", json.dumps(json_schema)]
    else:
        cmd += ["--output-format", "json"]

    try:
        r = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        error("Claude CLI timed out (300s)")
        return {"findings": [], "summary": "Analysis timed out"} if json_schema else "Analysis timed out"

    output = r.stdout.strip()
    resp_path = log_dir / f"{log_prefix}_resp.txt"
    resp_path.write_text(output or r.stderr.strip())

    if not output:
        stderr = r.stderr.strip()[:300]
        error(f"Claude CLI error: {stderr}")
        return {"findings": [], "summary": f"Error: {stderr}"} if json_schema else f"Error: {stderr}"

    # Parse the JSON wrapper (always present with --output-format json)
    try:
        wrapper = json.loads(output)
    except json.JSONDecodeError:
        warn("Failed to parse Claude CLI output")
        return {"findings": [], "summary": output[:500]} if json_schema else output

    # Track usage
    if usage and isinstance(wrapper, dict):
        usage.update(wrapper)

    parsed = None
    if isinstance(wrapper, dict):
        if wrapper.get("is_error"):
            err = wrapper.get("result") or wrapper.get("error") or ""
            # Log full response for debugging
            err_log = log_dir / f"{log_prefix}_error.json"
            err_log.write_text(json.dumps(wrapper, indent=2, default=str))
            detail = err if isinstance(err, str) else json.dumps(err, default=str)
            error(f"Claude returned error: {detail[:500]}")
            error(f"Full error logged to {err_log}")
            # Don't cache errors
            return {"findings": [], "summary": f"Error: {detail[:200]}"} if json_schema else f"Error: {detail}"

        if json_schema:
            if "structured_output" in wrapper and wrapper["structured_output"]:
                parsed = wrapper["structured_output"]
            else:
                result_str = wrapper.get("result", "")
                if isinstance(result_str, dict):
                    parsed = result_str
                elif isinstance(result_str, str) and result_str:
                    try:
                        parsed = json.loads(result_str)
                    except json.JSONDecodeError:
                        pass
            if parsed is None:
                parsed = {"findings": [], "summary": wrapper.get("result", "")[:500]}
        else:
            parsed = wrapper.get("result", "")
    else:
        parsed = wrapper

    # Cache successful results
    if cache:
        _cache_put(key, parsed)
    return parsed



# ---------------------------------------------------------------------------
# Manifest analysis
# ---------------------------------------------------------------------------

def analyze_manifest(manifest_path: Path, usage: UsageStats | None = None) -> dict:
    log("Analyzing AndroidManifest.xml (haiku)...")
    content = manifest_path.read_text(errors="replace")
    prompt = f"Analyze this AndroidManifest.xml:\n\n```xml\n{content}\n```"
    return claude_analyze(prompt, SYSTEM_PROMPT_MANIFEST, MANIFEST_SCHEMA, "haiku", usage)


# ---------------------------------------------------------------------------
# Source code analysis
# ---------------------------------------------------------------------------

def format_chunk_prompt(chunk: Chunk, manifest_summary: str) -> str:
    parts = []
    parts.append(f"Context from manifest analysis:\n{manifest_summary}\n")
    parts.append(f"Analyzing {len(chunk.files)} source files (max suspicion score: {chunk.max_score}):\n")

    for sf in chunk.files:
        match_info = ""
        if sf.matches:
            flags = ", ".join(f"{m.pattern_name} (line {m.line_number})" for m in sf.matches[:5])
            match_info = f"  [Suspicion score: {sf.score} — {flags}]"
        parts.append(f"\n{'='*60}")
        parts.append(f"FILE: {sf.relative_path}{match_info}")
        parts.append(f"{'='*60}")
        parts.append(sf.content)

    parts.append("\n\nAnalyze all files above for backdoors, data exfiltration, C2 patterns, "
                  "and other malicious behavior. Report each finding with severity, description, "
                  "file path, code snippet, confidence, and category.")
    return "\n".join(parts)


def _parse_findings(result: dict) -> list[Finding]:
    findings = []
    for f in result.get("findings", []):
        severity = f.get("severity", "INFO")
        if severity == "INFO":
            continue
        findings.append(Finding(
            severity=severity,
            title=f.get("title", "Untitled"),
            description=f.get("description", ""),
            file_path=f.get("file_path", ""),
            code_snippet=f.get("code_snippet", ""),
            confidence=f.get("confidence", 0.0),
            category=f.get("category", "unknown"),
        ))
    return findings


def _save_state(state_path: Path, completed: list[int], findings: list[Finding],
                manifest_result: dict):
    data = {
        "completed_chunks": completed,
        "findings": [
            {"severity": f.severity, "title": f.title, "description": f.description,
             "file_path": f.file_path, "code_snippet": f.code_snippet,
             "confidence": f.confidence, "category": f.category}
            for f in findings
        ],
        "manifest_result": manifest_result,
    }
    state_path.write_text(json.dumps(data, indent=2))


def _load_state(state_path: Path) -> tuple[list[int], list[Finding], dict] | None:
    if not state_path.exists():
        return None
    try:
        data = json.loads(state_path.read_text())
        findings = [Finding(**f) for f in data.get("findings", [])]
        return data.get("completed_chunks", []), findings, data.get("manifest_result", {})
    except (json.JSONDecodeError, TypeError, KeyError):
        return None




def analyze_chunks(chunks: list[Chunk], manifest_summary: str, model: str,
                   usage: UsageStats, state_path: Path,
                   manifest_result: dict,
                   start_from: int = 0) -> tuple[list[Finding], bool]:
    """Returns (findings, completed). completed=False if interrupted."""
    all_findings: list[Finding] = []
    completed_chunks: list[int] = list(range(start_from))

    # Load existing findings from resumed state
    if start_from > 0:
        prev = _load_state(state_path)
        if prev:
            all_findings = prev[1]

    interrupted = False
    i = start_from
    while i < len(chunks):
        # Launch up to PARALLEL_CHUNKS at once
        batch_end = min(i + PARALLEL_CHUNKS, len(chunks))
        batch_indices = list(range(i, batch_end))

        for idx in batch_indices:
            c = chunks[idx]
            filenames = ", ".join(Path(f.relative_path).name for f in c.files)
            log(f"Analyzing chunk {idx + 1}/{len(chunks)} "
                f"({len(c.files)} files, score {c.max_score}, "
                f"{c.total_chars // 1024}KB)...  "
                f"{C.DIM}[{filenames}] [{usage.summary()}]{C.RESET}")

        # Run batch in parallel threads
        results: dict[int, dict | str] = {}
        errors: dict[int, Exception] = {}

        def _run_chunk(idx: int, prompt: str):
            try:
                results[idx] = claude_analyze(
                    prompt, SYSTEM_PROMPT_ANALYSIS, FINDINGS_SCHEMA, model, usage)
            except Exception as e:
                errors[idx] = e

        threads = []
        for idx in batch_indices:
            prompt = format_chunk_prompt(chunks[idx], manifest_summary)
            t = threading.Thread(target=_run_chunk, args=(idx, prompt), daemon=True)
            t.start()
            threads.append(t)

        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            warn("Interrupted! Saving progress...")
            _save_state(state_path, completed_chunks, all_findings, manifest_result)
            log(f"State saved. Run again on the same target to resume from chunk {i + 1}/{len(chunks)}.")
            log(f"Usage so far: {usage.summary()}")
            interrupted = True
            break

        # Collect results in order
        for idx in batch_indices:
            if idx in errors:
                error(f"Chunk {idx + 1} failed: {errors[idx]}")
                continue
            result = results.get(idx, {})
            if isinstance(result, dict):
                all_findings.extend(_parse_findings(result))
                chunk_summary = result.get("summary", "")
                if chunk_summary:
                    log(f"  chunk {idx + 1}: {C.DIM}{chunk_summary[:120]}{C.RESET}")
            completed_chunks.append(idx)

        if not interrupted:
            _save_state(state_path, completed_chunks, all_findings, manifest_result)

        i = batch_end

    if not interrupted:
        # Save final state for future interactive sessions
        _save_state(state_path, completed_chunks, all_findings, manifest_result)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.confidence))
    return all_findings, not interrupted


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(
    package_name: str,
    manifest_result: dict,
    findings: list[Finding],
    file_count: int,
    chunk_count: int,
    output_path: Path,
) -> Path:
    lines = []
    lines.append(f"# apkanal Security Report: {package_name}")
    lines.append(f"_Generated {time.strftime('%Y-%m-%d %H:%M:%S')}_\n")

    # Executive summary
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    lines.append("## Executive Summary")
    if not findings:
        lines.append("No suspicious findings detected.\n")
    else:
        parts = [f"**{count} {sev}**" for sev, count in
                 sorted(sev_counts.items(), key=lambda kv: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(kv[0]))]
        lines.append(f"Found {len(findings)} findings: {', '.join(parts)}\n")

    # Manifest
    lines.append("## Manifest Analysis")
    overall = manifest_result.get("overall_risk_level", "UNKNOWN")
    lines.append(f"**Overall manifest risk: {overall}**\n")
    lines.append(manifest_result.get("summary", "N/A"))
    lines.append("")

    perms = manifest_result.get("permissions_analysis", [])
    if perms:
        lines.append("### Permissions")
        for p in perms:
            lines.append(f"- **{p.get('risk_level', '?')}** `{p.get('permission', '?')}` — {p.get('explanation', '')}")
        lines.append("")

    comp_risks = manifest_result.get("component_risks", [])
    if comp_risks:
        lines.append("### Component Risks")
        for cr in comp_risks:
            lines.append(f"- **{cr.get('risk', '?')}** `{cr.get('component', '?')}` — {cr.get('explanation', '')}")
        lines.append("")

    # Code findings
    if findings:
        lines.append("## Code Findings\n")
        for i, f in enumerate(findings, 1):
            lines.append(f"### #{i} [{f.severity}] {f.title}")
            lines.append(f"**Category:** {f.category} | **Confidence:** {f.confidence:.0%} | **File:** `{f.file_path}`\n")
            lines.append(f"{f.description}\n")
            if f.code_snippet:
                lines.append(f"```java\n{f.code_snippet}\n```\n")
            lines.append("---\n")

    # Metadata
    lines.append("## Scan Metadata")
    lines.append(f"- Files analyzed: {file_count}")
    lines.append(f"- Chunks sent to LLM: {chunk_count}")
    lines.append(f"- Total findings: {len(findings)}")

    report_text = "\n".join(lines)
    output_path.write_text(report_text)
    return output_path


# ---------------------------------------------------------------------------
# Interactive REPL
# ---------------------------------------------------------------------------

def interactive_mode(
    findings: list[Finding],
    source_files: list[SourceFile],
    manifest_result: dict,
    decompile_dir: Path,
    model: str,
):
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in sev_counts:
            color = severity_color(sev)
            summary_parts.append(f"{color}{sev_counts[sev]} {sev}{C.RESET}")

    if summary_parts:
        print(f"\n{C.BOLD}[apkanal]{C.RESET} {', '.join(summary_parts)} findings.")
    else:
        print(f"\n{C.BOLD}[apkanal]{C.RESET} No findings. You can still explore the code.")

    print("Commands: show N | analyze FILE | ask QUESTION | list | export FILE | quit")
    print()

    # Index source files by relative path for quick lookup
    file_index = {sf.relative_path: sf for sf in source_files}

    while True:
        try:
            raw = input(f"{C.CYAN}apkanal>{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not raw:
            continue

        parts = raw.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("quit", "exit", "q"):
            break

        elif cmd == "help":
            print("  show N          — Show finding #N in detail")
            print("  list            — List all findings with severity")
            print("  analyze FILE    — Deep-analyze a specific file with Claude")
            print("  ask QUESTION    — Ask Claude about the code")
            print("  files           — List all analyzed source files")
            print("  search TERM     — Search source files for a pattern")
            print("  export FILE     — Export report to file")
            print("  quit            — Exit")

        elif cmd == "list":
            if not findings:
                print("  No findings.")
            for i, f in enumerate(findings, 1):
                color = severity_color(f.severity)
                print(f"  {color}#{i} [{f.severity}]{C.RESET} {f.title} "
                      f"{C.DIM}({f.file_path}, {f.confidence:.0%}){C.RESET}")

        elif cmd == "show":
            try:
                idx = int(arg) - 1
                f = findings[idx]
                color = severity_color(f.severity)
                print(f"\n  {color}[{f.severity}]{C.RESET} {C.BOLD}{f.title}{C.RESET}")
                print(f"  Category: {f.category}")
                print(f"  File: {f.file_path}")
                print(f"  Confidence: {f.confidence:.0%}")
                print(f"\n  {f.description}")
                if f.code_snippet:
                    print(f"\n  Code:")
                    for line in f.code_snippet.splitlines():
                        print(f"    {line}")
                print()
            except (ValueError, IndexError):
                print(f"  Invalid finding number. Use 1-{len(findings)}")

        elif cmd == "files":
            for sf in source_files[:50]:
                score_str = f" (score: {sf.score})" if sf.score > 0 else ""
                print(f"  {sf.relative_path}{score_str}")
            if len(source_files) > 50:
                print(f"  ... and {len(source_files) - 50} more")

        elif cmd == "search":
            if not arg:
                print("  Usage: search PATTERN")
                continue
            found = 0
            for sf in source_files:
                for i, line in enumerate(sf.content.splitlines(), 1):
                    if re.search(arg, line, re.IGNORECASE):
                        print(f"  {C.CYAN}{sf.relative_path}:{i}{C.RESET} {line.strip()[:120]}")
                        found += 1
                        if found >= 30:
                            break
                if found >= 30:
                    print(f"  ... (showing first 30 matches)")
                    break
            if found == 0:
                print(f"  No matches for '{arg}'")

        elif cmd == "analyze":
            if not arg:
                print("  Usage: analyze <file_path>")
                continue
            # Find the file — exact or partial match
            sf = file_index.get(arg)
            if not sf:
                matches = [k for k in file_index if arg.lower() in k.lower()]
                if len(matches) == 1:
                    sf = file_index[matches[0]]
                elif len(matches) > 1:
                    print(f"  Multiple matches:")
                    for m in matches[:10]:
                        print(f"    {m}")
                    continue
                else:
                    print(f"  File not found: {arg}")
                    continue

            print(f"  Analyzing {sf.relative_path}...")
            prompt = (f"Deep-analyze this file for backdoors and malicious behavior. "
                      f"Be thorough — examine every method.\n\n"
                      f"File: {sf.relative_path}\n"
                      f"Static pre-scan score: {sf.score}/100\n\n"
                      f"```java\n{sf.content}\n```")
            result = claude_analyze(prompt, SYSTEM_PROMPT_ANALYSIS, model=model, cache=False)
            print(f"\n{result}\n")

        elif cmd == "ask":
            if not arg:
                print("  Usage: ask <question>")
                continue
            # Build context from top findings and scored files
            context_parts = ["Known findings so far:"]
            for i, f in enumerate(findings[:10], 1):
                context_parts.append(f"  #{i} [{f.severity}] {f.title} in {f.file_path}")
            context_parts.append("")

            # Include top suspicious files content (up to ~50K chars)
            context_chars = 0
            for sf in source_files[:20]:
                if sf.score > 0 and context_chars + sf.size < 50000:
                    context_parts.append(f"--- {sf.relative_path} (score {sf.score}) ---")
                    context_parts.append(sf.content)
                    context_chars += sf.size

            prompt = "\n".join(context_parts) + f"\n\nUser question: {arg}"
            print("  Asking Claude...")
            result = claude_analyze(prompt, SYSTEM_PROMPT_INTERACTIVE, model=model, cache=False)
            print(f"\n{result}\n")

        elif cmd == "export":
            path = Path(arg) if arg else Path(f"apkanal_report_{int(time.time())}.md")
            # Re-export with current findings
            print(f"  (Use the report generated during scan or 'show' individual findings)")

        else:
            print(f"  Unknown command: {cmd}. Type 'help' for commands.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------



def main():
    parser = argparse.ArgumentParser(
        prog="apkanal",
        description="Android APK Backdoor Analyzer — pull, decompile, and analyze APKs with Claude",
        color=False,
    )
    parser.add_argument("target", nargs="?",
                        help="Package name (pulls via ADB) or path to APK file")
    parser.add_argument("--list", action="store_true",
                        help="List packages on connected device")
    parser.add_argument("--search", metavar="TERM",
                        help="Search/filter packages by term")
    parser.add_argument("-o", "--output", metavar="PATH",
                        help="Output report path (default: auto-generated)")
    parser.add_argument("--no-interactive", action="store_true",
                        help="Skip interactive REPL, just produce report")
    parser.add_argument("--min-score", type=int, default=5,
                        help="Minimum suspicion score for LLM analysis (default: 5)")
    parser.add_argument("--model", default="haiku",
                        help="Claude model for scanning (default: haiku, use sonnet for deeper analysis)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    args = parser.parse_args()

    # --- List mode ---
    if args.list or (not args.target and args.search):
        if not check_adb():
            sys.exit(1)
        pkgs = list_packages(args.search)
        for p in pkgs:
            print(p)
        print(f"\n{len(pkgs)} packages" + (f" matching '{args.search}'" if args.search else ""))
        sys.exit(0)

    # --- Check claude CLI ---
    if not shutil.which("claude"):
        error("claude CLI not found. Install Claude Code: https://docs.anthropic.com/en/docs/claude-code")
        sys.exit(1)

    # --- Resolve target ---
    apk_path = None
    package_name = "unknown"
    tui_action = "analyze"

    if args.target:
        target_path = Path(args.target)
        if target_path.exists() and target_path.suffix == ".apk":
            apk_path = target_path
            package_name = target_path.stem
        else:
            package_name = args.target
    else:
        # TUI mode
        package_name, apk_path, tui_action = run_tui()
        if not package_name:
            sys.exit(0)

    # Work dir: ./apkanal_output/<package_name>/
    work_dir = Path("apkanal_output") / package_name
    work_dir.mkdir(parents=True, exist_ok=True)

    # --- Interactive-only mode (from TUI submenu) ---
    if not args.target and tui_action == "interactive":
        decompile_dir = work_dir / "decompiled"
        state_path = work_dir / "analysis_state.json"
        prev_state = _load_state(state_path)
        if prev_state and decompile_dir.exists():
            _, findings, manifest_result = prev_state
            tool = "jadx" if (decompile_dir / "sources").exists() else "apktool"
            source_files = collect_source_files(decompile_dir, tool)
            source_files = prescan_files(source_files)
            log(f"Loaded {len(findings)} findings, {len(source_files)} source files")
            run_interactive_tui(findings, source_files, manifest_result,
                                decompile_dir, args.model, claude_analyze)
            sys.exit(0)
        else:
            warn("No saved analysis state found — running full analysis")


    # --- Check if already decompiled ---
    decompile_dir = work_dir / "decompiled"
    already_decompiled = (decompile_dir / DECOMPILE_DONE_MARKER).exists()

    if not apk_path and not already_decompiled:
        # Need APK — check local copy or pull from device
        existing_apk = work_dir / f"{package_name}.apk"
        if existing_apk.exists():
            apk_path = existing_apk
            log(f"Using existing APK ({existing_apk.stat().st_size / (1024*1024):.1f} MB)")
        else:
            if not check_adb():
                sys.exit(1)
            apk_path = pull_apk(package_name, work_dir)

        if not apk_path or not apk_path.exists():
            error("Could not obtain APK file")
            sys.exit(1)

    global _current_package
    _current_package = package_name
    log(f"Target: {C.BOLD}{package_name}{C.RESET}")
    log(f"Working directory: {work_dir}")

    # --- Decompile ---
    if already_decompiled:
        tool = "jadx" if (decompile_dir / "sources").exists() else "apktool"
        log(f"Using existing decompilation ({tool})")
    else:
        decompile_dir, tool = decompile_apk(apk_path, decompile_dir)
        log(f"Decompiled with {tool}")

    # --- Collect and filter ---
    log("Collecting source files...")
    source_files = collect_source_files(decompile_dir, tool)
    log(f"Found {len(source_files)} app source files (libraries excluded)")

    if not source_files:
        warn("No source files found after filtering. The app may be fully native or obfuscated.")
        sys.exit(0)

    # --- Pre-scan ---
    log("Pre-scanning for suspicious patterns...")
    source_files = prescan_files(source_files)
    suspicious_count = sum(1 for f in source_files if f.score > 0)
    log(f"Suspicious files: {suspicious_count}/{len(source_files)} "
        f"(top score: {source_files[0].score if source_files else 0})")

    if args.verbose:
        for sf in source_files[:15]:
            if sf.score > 0:
                flags = ", ".join(m.pattern_name for m in sf.matches[:3])
                print(f"  {C.DIM}{sf.score:3d}{C.RESET}  {sf.relative_path}  [{flags}]")

    # --- Chunk ---
    chunks = build_chunks(source_files, min_score=args.min_score)
    if not chunks:
        warn(f"No files meet the minimum score threshold ({args.min_score}). "
             "Try --min-score 0 to analyze all files.")
        sys.exit(0)

    total_chars = sum(c.total_chars for c in chunks)
    log(f"Built {len(chunks)} chunk(s) ({total_chars // 1024}KB total)")

    # --- Usage tracking ---
    usage = UsageStats()
    state_path = work_dir / "analysis_state.json"

    # --- Check for resumable state ---
    start_from = 0
    manifest_result = {}
    prev_state = _load_state(state_path)
    if prev_state:
        completed, prev_findings, prev_manifest = prev_state
        start_from = max(completed) + 1 if completed else 0
        if start_from > 0 and start_from < len(chunks):
            log(f"Resuming from chunk {start_from + 1}/{len(chunks)} "
                f"({len(prev_findings)} findings so far)")
            manifest_result = prev_manifest
        elif start_from >= len(chunks):
            log("Previous analysis already completed. Delete analysis_state.json to re-run.")
            manifest_result = prev_manifest
            findings = prev_findings
            # Skip to report
            start_from = len(chunks)
        else:
            start_from = 0

    # --- Manifest analysis ---
    if not manifest_result:
        manifest_path = find_manifest(decompile_dir, tool)
        if manifest_path:
            manifest_result = analyze_manifest(manifest_path, usage)
            overall = manifest_result.get("overall_risk_level", "?")
            color = severity_color(overall)
            log(f"Manifest risk: {color}{overall}{C.RESET}")
            log(f"  {C.DIM}[{usage.summary()}]{C.RESET}")
        else:
            warn("AndroidManifest.xml not found — skipping manifest analysis")

    manifest_summary = manifest_result.get("summary", "Manifest not analyzed")

    # --- Source analysis ---
    if start_from < len(chunks):
        log(f"Starting source analysis with Claude ({args.model})...")
        findings, completed = analyze_chunks(
            chunks, manifest_summary, args.model, usage, state_path,
            manifest_result, start_from,
        )

        if not completed:
            sys.exit(0)
    else:
        if start_from == 0:
            findings = []

    # --- Report ---
    print()
    log(f"Total usage: {usage.summary()}")

    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    if findings:
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in sev_counts:
                color = severity_color(sev)
                print(f"  {color}{sev}: {sev_counts[sev]}{C.RESET}")
    else:
        log(f"{C.GREEN}No suspicious findings detected.{C.RESET}")

    output_path = Path(args.output) if args.output else Path(f"apkanal_report_{package_name}_{int(time.time())}.md")
    generate_report(package_name, manifest_result, findings, len(source_files), len(chunks), output_path)
    log(f"Report saved to {C.BOLD}{output_path}{C.RESET}")

    # --- Interactive mode ---
    if not args.no_interactive:
        run_interactive_tui(findings, source_files, manifest_result,
                            decompile_dir, args.model, claude_analyze)

    print(f"\n{C.BOLD}Done.{C.RESET} Decompiled source: {work_dir}")


if __name__ == "__main__":
    main()
