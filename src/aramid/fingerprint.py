import hashlib, re
_WS = re.compile(r"\s+")

def normalize_path(path: str) -> str:
    return path.replace("\\", "/").casefold()

def normalize_line(line: str) -> str:
    return _WS.sub(" ", line).strip()

def compute_fingerprint(tool, rule, path, line_content, occurrence_index) -> str:
    line_hash = hashlib.sha256(normalize_line(line_content).encode()).hexdigest()
    key = "\x1f".join([tool, rule, normalize_path(path), line_hash, str(occurrence_index)])
    return hashlib.sha256(key.encode()).hexdigest()
