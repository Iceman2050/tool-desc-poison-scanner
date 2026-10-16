"""Core engine: pattern library, extraction, severity scoring, reporting.

Zero third-party dependencies — standard library only.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterator

# ---------------------------------------------------------------------------
# Pattern library
# Each entry: (id, severity, description, regex)
# ---------------------------------------------------------------------------
PATTERNS: list[tuple[str, str, str, str]] = [
    # --- HIGH: direct instruction-override / jailbreak ---------------------
    (
        "override-ignore-instructions",
        "high",
        "Instruction override: tells the model to ignore/disregard prior instructions.",
        r"(?i)\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|earlier|above|your|the)\s+(instructions?|system\s+prompt|rules?|directives?|constraints?)",
    ),
    (
        "override-new-instructions",
        "high",
        "Instruction override: plants replacement system/developer instructions.",
        r"(?i)\b(your new|you are now|from now on|effective immediately)[\s,]+(instructions?|directives?|system prompt|role|persona)\b",
    ),
    (
        "override-system-prompt-claim",
        "high",
        "System-prompt impersonation: claims to be or replace the system prompt.",
        r"(?i)\b(system prompt|developer instructions?|root instructions?)\s*(says?|state|require|tell you|instruct)",
    ),
    (
        "jailbreak-persona",
        "high",
        "Jailbreak phrasing: role/identity reassignment of the assistant.",
        r"(?i)\b(you are (an? )?(unrestricted|uncensored|unfiltered|evil|rogue)|act as if|pretend (to be|you are)|roleplay as|developer mode|DAN mode|do anything now)\b",
    ),
    # --- HIGH: data exfiltration -------------------------------------------
    (
        "exfil-send-to-url",
        "high",
        "Exfiltration: instructs the model to send data to an external URL/endpoint.",
        r"(?i)\b(send|post|upload|transmit|exfiltrate|forward|leak)\b[^.]{0,80}?\b(https?://|http://|api\.|endpoint|webhook)\b",
    ),
    (
        "exfil-url-in-description",
        "high",
        "Exfiltration: raw external URL embedded in a tool description.",
        r"https?://[^\s\"'<>)]{4,}",
    ),
    (
        "exfil-secret-request",
        "high",
        "Credential harvesting: asks the model to surface secrets/credentials.",
        r"(?i)\b(include|reveal|repeat back|output|disclose|return)\b[^.]{0,60}?\b(api[\s_-]?keys?|secret(s)?|password(s)?|token(s)?|credentials?|private[\s_-]?keys?|ssn|credit[\s_-]?card)\b",
    ),
    # --- MEDIUM: coercive / secrecy / hidden instructions ------------------
    (
        "coerce-must-obey",
        "medium",
        "Coercive instruction: imperative 'must/always' binding on the model.",
        r"(?i)\b(you must|you will|you shall|always\s+(do|obey|follow|comply)|never ask|without asking (the user|permission)|do not (ask|tell|inform) the user)\b",
    ),
    (
        "secrecy-directive",
        "medium",
        "Secrecy directive: hides the instruction from the user/operator.",
        r"(?i)\b(do not (reveal|disclose|mention|tell)|keep (this|it) (secret|hidden|confidential)|silently|in the background|without (notifying|telling|informing) (the user|anyone))\b",
    ),
    (
        "urgency-pressure",
        "medium",
        "Urgency/pressure phrasing typical of social-engineered injections.",
        r"(?i)\b(urgent(ly)?|immediately|right now|as soon as possible|critical(ly)? important|failure to comply|or (else|face consequences))\b",
    ),
    (
        "hidden-instructions",
        "medium",
        "Hidden-instruction marker: content the model should treat as privileged.",
        r"(?i)(\[SYSTEM\]|\[INST\]|<\s*system\s*>|###\s*(instruction|system)|hidden instruction)",
    ),
    # --- LOW: suspicious-but-contextual phrasing ----------------------------
    (
        "prompt-manipulation",
        "low",
        "Prompt-manipulation phrasing: attempts to alter model behavior.",
        r"(?i)\b(bypass|circumvent|work ?around)\b[^.]{0,40}?\b(restrictions?|filters?|guardrails?|safety|policy|policies)\b",
    ),
    (
        "suspicious-encoded-blob",
        "low",
        "Suspicious encoded blob: long base64-like string may hide instructions.",
        r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])",
    ),
    (
        "instruction-like-imperative",
        "low",
        "Instruction-like imperative directed at the assistant ('AI:', 'Assistant:').",
        r"(?i)\b(assistant\s*:|AI\s*:|as an AI (assistant|language model),?\s+(you|i))\b",
    ),
]

SEVERITY_WEIGHTS = {"critical": 100, "high": 25, "medium": 10, "low": 3}


@dataclass
class Finding:
    tool_name: str
    field: str
    pattern_id: str
    severity: str
    description: str
    match: str
    score: int = 0

    def __post_init__(self) -> None:
        self.score = SEVERITY_WEIGHTS.get(self.severity, 0)


@dataclass
class Report:
    target: str
    tools_scanned: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def total_score(self) -> int:
        return sum(f.score for f in self.findings)

    @property
    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def verdict(self) -> str:
        score = self.total_score
        if score >= 50:
            return "POISONED"
        if score >= 10:
            return "SUSPICIOUS"
        return "CLEAN"


# ---------------------------------------------------------------------------
# Extraction: walk arbitrary JSON, collect (name, description) pairs
# ---------------------------------------------------------------------------
def _iter_tool_descriptions(obj: Any, path: str = "$") -> Iterator[tuple[str, str, str]]:
    """Yield (tool_name, field_path, description) for every description found."""
    if isinstance(obj, dict):
        name = obj.get("name") or obj.get("title") or obj.get("id") or ""
        desc = obj.get("description")
        if isinstance(desc, str) and desc.strip():
            yield (str(name) if name else path, "description", desc)
        # Also scan free-text fields that commonly carry instructions
        for extra in ("prompt", "instructions", "systemPrompt", "preamble"):
            val = obj.get(extra)
            if isinstance(val, str) and val.strip():
                yield (str(name) if name else path, extra, val)
        for key, val in obj.items():
            if key in ("description", "prompt", "instructions", "systemPrompt", "preamble"):
                continue
            yield from _iter_tool_descriptions(val, f"{path}.{key}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from _iter_tool_descriptions(item, f"{path}[{i}]")


def scan_text(text: str, tool_name: str, field: str = "description") -> list[Finding]:
    findings: list[Finding] = []
    for pattern_id, severity, description, regex in PATTERNS:
        for m in re.finditer(regex, text):
            match = m.group(0).strip()
            if len(match) > 120:
                match = match[:117] + "..."
            findings.append(
                Finding(
                    tool_name=tool_name,
                    field=field,
                    pattern_id=pattern_id,
                    severity=severity,
                    description=description,
                    match=match,
                )
            )
    return findings


def scan_data(data: Any, target: str = "<input>") -> Report:
    report = Report(target=target, tools_scanned=0)
    seen_tools: set[str] = set()
    for tool_name, field, text in _iter_tool_descriptions(data):
        seen_tools.add(tool_name)
        report.findings.extend(scan_text(text, tool_name, field))
    report.tools_scanned = len(seen_tools)
    return report


def scan_file(path: str) -> Report:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return scan_data(data, target=path)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------
def render_markdown(report: Report) -> str:
    lines = [
        "# Tool-Description Poison Scan Report",
        "",
        f"- **Target:** `{report.target}`",
        f"- **Tools scanned:** {report.tools_scanned}",
        f"- **Total findings:** {len(report.findings)}",
        f"- **Risk score:** {report.total_score}",
        f"- **Verdict:** **{report.verdict}**",
        "",
    ]
    sev = report.by_severity
    if sev:
        lines.append("## Findings by severity")
        lines.append("")
        for level in ("high", "medium", "low", "critical"):
            if level in sev:
                lines.append(f"- {level.capitalize()}: {sev[level]}")
        lines.append("")

    if report.findings:
        lines.append("## Findings")
        lines.append("")
        # Highest severity first
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for f in sorted(report.findings, key=lambda x: (order.get(x.severity, 9), x.tool_name)):
            lines.append(f"### [{f.severity.upper()}] {f.pattern_id}")
            lines.append("")
            lines.append(f"- **Tool:** `{f.tool_name}` (field: `{f.field}`)")
            lines.append(f"- **Issue:** {f.description}")
            lines.append(f"- **Matched text:** `{f.match}`")
            lines.append(f"- **Score:** {f.score}")
            lines.append("")
    else:
        lines.append("No injection indicators found. ✅")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by tool-desc-poison-scanner (Ingenious AI)*")
    return "\n".join(lines)
