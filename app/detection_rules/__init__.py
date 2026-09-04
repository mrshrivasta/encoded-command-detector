"""
Detection Rules — Encoded Command Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule is a pure function that inspects a REAL candidate string found by
the Security Engine's regex scan and the REAL decoded text produced by a
REAL decode attempt (base64 / hex / URL-decode / char-code). Rules never
decode anything themselves and never execute anything — decoding happens
once in app.security_engine, and these rules only classify the result.

Severity scale used consistently across the whole project.
"""
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# Small bundled keyword list applied to REAL decoded content (never to the
# raw encoded blob) to separate confirmed suspicious payloads from harmless
# encoded-looking noise (base64 config blobs, hashes, random IDs, etc.).
SUSPICIOUS_KEYWORDS = [
    "iex",
    "invoke-expression",
    "downloadstring",
    "http://",
    "https://",
    "/bin/sh",
    "cmd.exe",
    "rundll32",
    "regsvr32",
]

PREVIEW_LEN = 200


def _find_suspicious_keyword(decoded_text):
    """Real, case-insensitive substring match of decoded_text against the
    bundled keyword list. Returns the matched keyword or None."""
    if not decoded_text:
        return None
    lowered = decoded_text.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lowered:
            return kw
    return None


def _preview(text, n=PREVIEW_LEN):
    if text is None:
        return None
    text = text.replace("\n", "\\n").replace("\r", "")
    return text if len(text) <= n else text[:n] + "…"


def rule_base64_suspicious_keyword(candidate, decoded_text):
    """ECD-001 (critical): a real base64-decoded payload contains a real
    suspicious keyword from the bundled list — a confirmed, malicious-looking
    encoded command (e.g. a PowerShell `-EncodedCommand` blob whose decoded
    text contains `iex`, `downloadstring`, a URL, or a shell invocation)."""
    keyword = _find_suspicious_keyword(decoded_text)
    if not keyword:
        return None
    return {
        "rule_id": "ECD-001",
        "rule_name": "Base64-Encoded Suspicious Command",
        "severity": SEVERITY_CRITICAL,
        "description": (
            f"A base64-encoded blob decoded to text containing the suspicious "
            f"keyword '{keyword}'. Encoded candidate: {_preview(candidate, 80)} "
            f"| Decoded content: {_preview(decoded_text)}"
        ),
        "permissions_octal": _preview(decoded_text),
    }


def rule_base64_binary_payload(candidate, decoded_text, is_binary):
    """ECD-002 (high): a real base64-decodable blob was found but its real
    decoded bytes are NOT printable text — an embedded binary/shellcode-
    looking payload disguised as base64 text."""
    if not is_binary:
        return None
    return {
        "rule_id": "ECD-002",
        "rule_name": "Base64-Encoded Binary Payload",
        "severity": SEVERITY_HIGH,
        "description": (
            f"A base64-encoded blob decoded successfully to raw bytes that are "
            f"NOT printable text — consistent with an embedded binary or "
            f"shellcode payload disguised as base64 text. Encoded candidate: "
            f"{_preview(candidate, 80)}"
        ),
        "permissions_octal": "<non-printable binary payload>",
    }


def rule_hex_suspicious_keyword(candidate, decoded_text):
    """ECD-003 (high): a real hex-decoded payload contains a real suspicious
    keyword from the bundled list."""
    keyword = _find_suspicious_keyword(decoded_text)
    if not keyword:
        return None
    return {
        "rule_id": "ECD-003",
        "rule_name": "Hex-Encoded Suspicious Command",
        "severity": SEVERITY_HIGH,
        "description": (
            f"A hex-encoded blob decoded to text containing the suspicious "
            f"keyword '{keyword}'. Encoded candidate: {_preview(candidate, 80)} "
            f"| Decoded content: {_preview(decoded_text)}"
        ),
        "permissions_octal": _preview(decoded_text),
    }


def rule_urlencoded_suspicious_keyword(candidate, decoded_text):
    """ECD-004 (medium): a real URL-decoded payload contains a real
    suspicious keyword from the bundled list."""
    keyword = _find_suspicious_keyword(decoded_text)
    if not keyword:
        return None
    return {
        "rule_id": "ECD-004",
        "rule_name": "URL-Encoded Suspicious Command",
        "severity": SEVERITY_MEDIUM,
        "description": (
            f"A URL-encoded (percent-encoded) sequence decoded to text "
            f"containing the suspicious keyword '{keyword}'. Encoded "
            f"candidate: {_preview(candidate, 80)} | Decoded content: "
            f"{_preview(decoded_text)}"
        ),
        "permissions_octal": _preview(decoded_text),
    }


def rule_charcode_obfuscation_technique(candidate, decoded_text):
    """ECD-005 (medium): a real char-code / ASCII-array-obfuscated string
    (PowerShell `[char]NN` or JavaScript `String.fromCharCode(...)`) was
    found and successfully real-decoded. Flagged regardless of keyword
    match — the obfuscation TECHNIQUE itself is the signal, since legitimate
    scripts rarely build strings one character code at a time."""
    if not decoded_text:
        return None
    keyword = _find_suspicious_keyword(decoded_text)
    note = f" (also matched keyword '{keyword}')" if keyword else ""
    return {
        "rule_id": "ECD-005",
        "rule_name": "Char-Code / ASCII-Array Obfuscation",
        "severity": SEVERITY_MEDIUM,
        "description": (
            f"A char-code/ASCII-array obfuscated string was found and decoded "
            f"successfully{note}. Encoded candidate: {_preview(candidate, 120)} "
            f"| Decoded content: {_preview(decoded_text)}"
        ),
        "permissions_octal": _preview(decoded_text),
    }


def rule_undecodable_candidate(candidate, encoding_kind):
    """ECD-006 (low/informational): a real base64/hex-looking candidate
    string was found but did NOT successfully decode to valid/printable
    content — likely a false-positive-looking string such as a hash, random
    ID, or unrelated data. Reported as a low-confidence parse-note, not a
    strong finding."""
    if encoding_kind not in ("base64", "hex"):
        return None
    return {
        "rule_id": "ECD-006",
        "rule_name": "Undecodable Encoding-Shaped Candidate",
        "severity": SEVERITY_LOW,
        "description": (
            f"A {encoding_kind}-shaped candidate string was found but did not "
            f"decode to printable/meaningful text — likely a hash, random ID, "
            f"or unrelated data rather than an encoded command. Candidate: "
            f"{_preview(candidate, 80)}"
        ),
        "permissions_octal": "<did not decode to printable text>",
    }


ALL_RULES = [
    rule_base64_suspicious_keyword,
    rule_base64_binary_payload,
    rule_hex_suspicious_keyword,
    rule_urlencoded_suspicious_keyword,
    rule_charcode_obfuscation_technique,
    rule_undecodable_candidate,
]
