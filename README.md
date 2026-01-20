# 🛡 GPBDS — GP Backdoor Scanner

GPBDS (GP Backdoor Scanner) is a **static analysis tool** designed to detect **malicious backdoors, remote code execution, and persistence mechanisms** in **Lua-based projects**, with a specific focus on **FiveM resources**.

The scanner analyzes source code **without executing it**, using pattern-based detection, deobfuscation techniques, and severity scoring, and generates a **detailed HTML security report**.

## Usage
```bash
python3 main.py --path /path/to/server
```

---

## 🧠 Limitations

Pattern-based detection (not a full Lua interpreter)

Obfuscation beyond implemented decoders may evade detection

False positives are possible in complex legitimate scripts

---

## ⚠️ Disclaimer

This tool is intended **only for defensive, educational, and research purposes**.

GPBDS performs **static analysis only** and does not execute any scanned code.
However, the files you scan **may contain real malware**.

> **Never scan untrusted files on a production system.**

The author assumes **no responsibility** for misuse of this tool or for any damage caused by executing malicious code found during analysis.

---

# License

This project is licensed under the MIT License.

You are free to:
- use the software for any purpose
- modify the source code
- distribute copies
- include it in commercial or private projects

Under the following conditions:
- the original copyright notice and license text must be included
- the software is provided **"as is"**, without warranty of any kind

The authors are not responsible for any damage, data loss, or misuse.

See the `LICENSE` file for the full license text.
