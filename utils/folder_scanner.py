from .report_creator import generate_html_report
from .lua_deobfuscator import LuaDeobfuscator
from urllib.parse import urlparse
from pathlib import Path
from tqdm import tqdm
import json
import html
import stat
import os
import re

_SEV_VALUE = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SEV_MAP   = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
_SCAN_EXTS = {".lua", ".js"}

def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _compile_checks(raw: dict) -> dict:
    """Pre-compile every pattern once at startup."""
    compiled = {}
    for name, rule in raw.items():
        compiled[name] = {
            **rule,
            "patterns": [
                re.compile(p, re.IGNORECASE | re.DOTALL)
                for p in rule["patterns"]
            ],
        }
    return compiled

_RAW_CHECKS = _load_json("./utils/checks.json")
CHECKS      = _compile_checks(_RAW_CHECKS)
WHITELIST   = _load_json("./utils/whitelist.json")

def _is_whitelisted(url: str) -> bool:
    """Check only the netloc (domain), not the full URL string."""
    try:
        domain = urlparse(url).netloc.lower()
        return any(allowed in domain for allowed in WHITELIST["http_whitelist_domains"])
    except Exception:
        return False


class FolderScanner:
    def __init__(self, logger, server_path):
        self._logger      = logger
        self._server_path = server_path
        self._deobfuscator = LuaDeobfuscator()
        self._findings    = []

    def scan(self):
        hidden = self._scan_hidden_files()
        if hidden:
            self._findings.append({
                "path": "__HIDDEN_FILES__",
                "score": len(hidden) * 2,
                "severity": "HIGH",
                "matches": [{
                    "check": "hidden_files_detected",
                    "severity": "HIGH",
                    "snippet": str(hidden[:10]),
                }],
            })

        files_to_scan = [
            os.path.join(root, f)
            for root, _, files in os.walk(self._server_path)
            for f in files
            if Path(f).suffix.lower() in _SCAN_EXTS
        ]

        for file_path in tqdm(files_to_scan, desc="Scanning files", unit="file"):
            self._scan_file(file_path)

        generate_html_report(self._findings)
        return self._findings

    def _extract_snippet(self, text: str, match: re.Match, radius: int = 80) -> str:
        start   = max(0, match.start() - radius)
        end     = min(len(text), match.end() + radius)
        snippet = re.sub(r"\s+", " ", text[start:end])[:300]
        return html.escape(snippet)

    def _scan_hidden_files(self) -> list:
        hidden_items = []
        for root, dirs, files in os.walk(self._server_path):
            for name, is_dir in [(d, True) for d in dirs] + [(f, False) for f in files]:
                full_path = os.path.join(root, name)
                try:
                    attrs     = os.stat(full_path).st_file_attributes
                    is_hidden = bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
                    is_system = bool(attrs & stat.FILE_ATTRIBUTE_SYSTEM)
                    if is_hidden or is_system:
                        hidden_items.append({
                            "type":   "dir" if is_dir else "file",
                            "path":   os.path.relpath(full_path, self._server_path),
                            "hidden": is_hidden,
                            "system": is_system,
                        })
                except Exception:
                    continue
        return hidden_items

    def _scan_file(self, path: str):
        try:
            data = Path(path).read_bytes()
            ext  = Path(path).suffix.lower()

            text = data.decode(errors="ignore")
            deobf = self._deobfuscator.deobfuscate(text)

            score         = 0
            matches       = []
            max_sev_value = 1

            for name, rule in CHECKS.items():
                for pattern in rule["patterns"]:
                    m = pattern.search(deobf)
                    if m:
                        score += rule["score"]
                        sev    = rule["severity"]
                        max_sev_value = max(max_sev_value, _SEV_VALUE.get(sev, 1))
                        matches.append({
                            "check":    name,
                            "severity": sev,
                            "snippet":  self._extract_snippet(deobf, m),
                        })
                        break

            seen_domains: set[str] = set()

            if score > 0 and matches:
                self._findings.append({
                    "path":     os.path.relpath(path, self._server_path),
                    "score":    score,
                    "severity": _SEV_MAP[max_sev_value],
                    "matches":  matches,
                })

        except Exception as e:
            self._logger.warning(f"Scan error {path}: {e}")
