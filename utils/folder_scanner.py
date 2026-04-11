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

def load_checks(path="./utils/checks.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

CHECKS = load_checks()

def load_whitelist(path="./utils/whitelist.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

WHITELIST = load_whitelist()

def is_whitelisted_url(url: str) -> bool:
    try:
        domain = urlparse(url).netloc.lower()
        return any(allowed in domain for allowed in WHITELIST["http_whitelist_domains"])
    except:
        return False

class FolderScanner:
    def __init__(self, logger, server_path):
        self._logger = logger
        self._server_path = server_path
        self._deobfuscator = LuaDeobfuscator()
        self._findings = []

    def scan(self):
        files_to_scan = []

        hidden = self.scan_hidden_files()

        if hidden:
            self._findings.append({
                "path": "__HIDDEN_FILES__",
                "score": len(hidden) * 2,
                "severity": "HIGH",
                "matches": [{
                    "check": "hidden_files_detected",
                    "severity": "HIGH",
                    "snippet": str(hidden[:10])
                }]
            })

        for root, _, files in os.walk(self._server_path):
            for f in files:
                if f.lower().endswith((".lua", ".txt", ".js", ".png")):
                    files_to_scan.append(os.path.join(root, f))

        for file_path in tqdm(files_to_scan, desc="Scanning files", unit="file"):
            self._scan_file(file_path)

        generate_html_report(self._findings)
        return self._findings

    def _extract_snippet(self, text, match, radius=80):
        start = max(0, match.start() - radius)
        end = min(len(text), match.end() + radius)

        snippet = text[start:end]
        snippet = re.sub(r"\s+", " ", snippet)
        snippet = snippet[:300]

        return html.escape(snippet)

    def scan_hidden_files(self):
        hidden_items = []

        for root, dirs, files in os.walk(self._server_path):
            for d in dirs:
                full_path = os.path.join(root, d)

                try:
                    attrs = os.stat(full_path).st_file_attributes

                    is_hidden = bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
                    is_system = bool(attrs & stat.FILE_ATTRIBUTE_SYSTEM)

                    if is_hidden or is_system:
                        hidden_items.append({
                            "type": "dir",
                            "path": os.path.relpath(full_path, self._server_path),
                            "hidden": is_hidden,
                            "system": is_system
                        })

                except Exception:
                    continue

            for f in files:
                full_path = os.path.join(root, f)

                try:
                    attrs = os.stat(full_path).st_file_attributes

                    is_hidden = bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
                    is_system = bool(attrs & stat.FILE_ATTRIBUTE_SYSTEM)

                    if is_hidden or is_system:
                        hidden_items.append({
                            "type": "file",
                            "path": os.path.relpath(full_path, self._server_path),
                            "hidden": is_hidden,
                            "system": is_system
                        })

                except Exception:
                    continue

        return hidden_items

    def _scan_file(self, path):
        try:
            data = Path(path).read_bytes()

            if path.lower().endswith(".png"):
                if b"os.execute" in data or b"loadstring" in data:
                    self._logger.error(f"Lua embedded in PNG: {path}")

                    self._findings.append({
                        "path": os.path.relpath(path, self._server_path),
                        "score": 10,
                        "severity": "CRITICAL",
                        "matches": [{
                            "check": "polyglot_lua_png",
                            "severity": "CRITICAL",
                            "snippet": "Lua-like payload detected inside PNG binary"
                        }]
                    })
                return

            text = data.decode(errors="ignore")

            deobf = self._deobfuscator.deobfuscate(text)

            score = 0
            matches = []
            max_sev_value = 1

            def sev_value(s):
                return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(s, 1)

            for name, rule in CHECKS.items():
                for pat in rule["patterns"]:
                    m = re.search(pat, deobf, re.IGNORECASE | re.DOTALL)
                    if m:
                        score += rule["score"]

                        sev = rule["severity"]
                        max_sev_value = max(max_sev_value, sev_value(sev))

                        matches.append({
                            "check": name,
                            "severity": sev,
                            "snippet": self._extract_snippet(deobf, m)
                        })
                        break

            url_pattern = r"https?://[^\s\"'<>]+"
            urls = re.findall(url_pattern, deobf)

            for url in urls:
                try:
                    domain = url.lower()

                    if any(w in domain for w in WHITELIST["http_whitelist_domains"]):
                        continue

                    score += 3
                    max_sev_value = max(max_sev_value, 2)

                    matches.append({
                        "check": "http_remote_untrusted",
                        "severity": "MEDIUM",
                        "snippet": url[:200]
                    })

                except Exception:
                    continue

            if path.lower().endswith(".js"):
                if any(k in deobf.lower() for k in ["eval(", "function(", "fromcharcode", "atob("]):
                    score += 2
                    max_sev_value = max(max_sev_value, 2)

            sev_map = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
            max_sev = sev_map[max_sev_value]

            if score > 0:
                self._findings.append({
                    "path": os.path.relpath(path, self._server_path),
                    "score": score,
                    "severity": max_sev,
                    "matches": matches
                })

        except Exception as e:
            self._logger.warning(f"Scan error {path}: {e}")
