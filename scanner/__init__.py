"""tool-desc-poison-scanner — scan MCP/tool description files for prompt-injection payloads."""
from .core import scan_file, scan_text, Finding, Report, PATTERNS

__all__ = ["scan_file", "scan_text", "Finding", "Report", "PATTERNS"]
__version__ = "1.0.0"
