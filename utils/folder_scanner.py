from .report_creator import generate_html_report
from .lua_deobfuscator import LuaDeobfuscator
from pathlib import Path
import json
import html
import os
import re

def load_checks(path="./utils/checks.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

CHECKS = load_checks()

class FolderScanner:
    def __init__(self, logger, server_path):
        self._logger = logger
        self._server_path = server_path
        self._deobfuscator = LuaDeobfuscator()
        self._findings = []

    def scan(self):
        for root, _, files in os.walk(self._server_path):
            for f in files:
                if f.lower().endswith((".lua", ".txt", ".js", ".png")):
                    self._scan_file(os.path.join(root, f))

        generate_html_report(self._findings)
        return self._findings

    def _extract_snippet(self, text, match, radius=80):
        start = max(0, match.start() - radius)
        end = min(len(text), match.end() + radius)

        snippet = text[start:end]
        snippet = re.sub(r"\s+", " ", snippet)
        snippet = snippet[:300]

        return html.escape(snippet)

    def _scan_file(self, path):
        try:
            data = Path(path).read_bytes()

            if path.lower().endswith(".png"):
                if b"os.execute" in data or b"loadstring" in data:
                    self._logger.error(f"Lua in PNG: {path}")
                return

            text = data.decode(errors="ignore")

            deobf = self._deobfuscator.deobfuscate(text)
            score = 0
            matches = []
            max_sev = "LOW"

            for name, rule in CHECKS.items():
                for pat in rule["patterns"]:
                    m = re.search(pat, deobf, re.IGNORECASE | re.DOTALL)
                    if m:
                        score += rule["score"]
                        matches.append({
                            "check": name,
                            "severity": rule["severity"],
                            "snippet": self._extract_snippet(deobf, m)
                        })
                        max_sev = max(
                            max_sev,
                            rule["severity"],
                            key=lambda s: {"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}[s]
                        )
                        break

            if score > 0:
                self._findings.append({
                    "path": os.path.relpath(path, self._server_path),
                    "score": score,
                    "severity": max_sev,
                    "matches": matches
                })

        except Exception as e:
            self._logger.warn(f"Scan error {path}: {e}")
