import re, base64

class LuaDeobfuscator:
    def __init__(self):
        self.max_iterations = 5
        self.iterations = 0

    def deobfuscate(self, code):
        original = code
        for i in range(self.max_iterations):
            self.iterations = i + 1
            code = self._hex(code)
            code = self._string_char(code)
            code = self._concat(code)
            code = self._base64(code)
            code = self._reverse(code)
            if code == original:
                break
            original = code
        return code

    def _hex(self, c):
        return re.sub(r'(?:\\x[0-9a-fA-F]{2})+',
                      lambda m: f'"{bytes.fromhex(m.group(0).replace("\\x","")).decode("utf-8","ignore")}"',
                      c)

    def _string_char(self, c):
        return re.sub(r'string\.char\s*\(([^)]+)\)',
                      lambda m: '"' + ''.join(chr(int(n)) for n in re.findall(r'\d+', m.group(1)) if int(n)<128) + '"',
                      c)

    def _concat(self, c):
        return re.sub(r'"[^"]*"(?:\s*\.\.\s*"[^"]*")+',
                      lambda m: '"' + ''.join(re.findall(r'"([^"]*)"', m.group(0))) + '"',
                      c)

    def _base64(self, c):
        return re.sub(
            r'(?:base64\.decode|decode64)\s*\(\s*(["\'])([^"\']+)\1\s*\)',
            lambda m: '"' + base64.b64decode(m.group(2)).decode("utf-8","ignore") + '"',
            c
        )

    def _reverse(self, c):
        return re.sub(
            r'string\.reverse\s*\(\s*(["\'])([^"\']+)\1\s*\)',
            lambda m: '"' + m.group(2)[::-1] + '"',
            c
        )
