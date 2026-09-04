"""
Security Engine — Encoded Command Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real, static text-scanning engine. Given a real local path — a single text/
script/log file, a directory (real-walked), or a CSV export containing a
`CommandLine`/text-like column — this engine REAL-reads the actual text
content and REAL-scans it for embedded encoded command payloads:

    1. Base64            (real base64.b64decode attempts on candidate runs)
    2. Hex                (real bytes.fromhex attempts on candidate runs)
    3. URL-encoding        (real urllib.parse.unquote attempts)
    4. Char-code / ASCII-array obfuscation (real chr() decoding)

Every decode is a REAL attempt against the REAL matched substring — nothing
is fabricated, and nothing that is decoded is ever executed. Decoded text is
then checked against a small bundled keyword list to separate confirmed
suspicious payloads from harmless encoded-looking noise.

Designed to never crash: unreadable files, decode failures, and malformed
CSV rows are all caught and counted as errors, never fabricated as findings.
"""
import base64
import csv
import io
import os
import re
import time
from urllib.parse import unquote

from app.detection_rules import (
    rule_base64_suspicious_keyword,
    rule_base64_binary_payload,
    rule_hex_suspicious_keyword,
    rule_urlencoded_suspicious_keyword,
    rule_charcode_obfuscation_technique,
    rule_undecodable_candidate,
)

# File extensions treated as text/script/log candidates when walking a directory.
TEXT_EXTENSIONS = {
    ".txt", ".log", ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".sh", ".bash",
    ".js", ".vbs", ".py", ".pl", ".rb", ".php", ".html", ".htm", ".xml",
    ".json", ".yaml", ".yml", ".ini", ".conf", ".cfg", ".csv", ".md", "",
}

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB safety cap per file read
CSV_TEXT_COLUMNS = ("commandline", "command_line", "command", "text", "line", "content", "message")


class EncodedCommandDetector:
    """Real static scanner: reads real files/CSV rows and real-decodes
    embedded base64/hex/URL/char-code encoded command payloads."""

    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set()
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes if ex)

    def run(self):
        """Perform the real, synchronous scan. Returns summary dict."""
        start = time.time()

        if not os.path.exists(self.target_path):
            self.errors_count += 1
        elif os.path.isfile(self.target_path):
            if self.target_path.lower().endswith(".csv"):
                self._scan_csv_file(self.target_path)
            else:
                self._scan_text_file(self.target_path)
        elif os.path.isdir(self.target_path):
            self._walk(self.target_path, depth=0)
        else:
            self.errors_count += 1

        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    # ------------------------------------------------------------------ #
    # Real filesystem walking
    # ------------------------------------------------------------------ #
    def _walk(self, path, depth):
        if self.files_scanned >= self.max_files:
            return
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return

        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self.files_scanned >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                self.errors_count += 1
                continue

            if is_dir:
                self._walk(full_path, depth + 1)
            elif is_file:
                ext = os.path.splitext(full_path)[1].lower()
                if ext == ".csv":
                    self._scan_csv_file(full_path)
                elif ext in TEXT_EXTENSIONS:
                    self._scan_text_file(full_path)

    # ------------------------------------------------------------------ #
    # Real file readers
    # ------------------------------------------------------------------ #
    def _read_text(self, path):
        """Real-read a file's actual bytes and decode as UTF-8 (best-effort)."""
        try:
            size = os.path.getsize(path)
            if size > MAX_FILE_BYTES:
                self.errors_count += 1
                return None
            with open(path, "rb") as fh:
                raw = fh.read()
            return raw.decode("utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            self.errors_count += 1
            return None

    def _scan_text_file(self, path):
        text = self._read_text(path)
        self.files_scanned += 1
        if text is None:
            return
        try:
            findings = analyze_text(text)
        except Exception:
            self.errors_count += 1
            return
        for f in findings:
            f["file_path"] = path
            f["owner_uid"] = None
            f["owner_gid"] = None
            self.findings.append(f)

    def _scan_csv_file(self, path):
        """Real-read a CSV export and real-scan a CommandLine/text-like column
        row by row; each row is treated as one scanned unit."""
        try:
            with open(path, "r", newline="", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            self.errors_count += 1
            return

        try:
            reader = csv.DictReader(io.StringIO(content))
            fieldnames = reader.fieldnames or []
        except csv.Error:
            self.errors_count += 1
            return

        target_col = None
        lowered = {name.lower(): name for name in fieldnames if name}
        for candidate in CSV_TEXT_COLUMNS:
            if candidate in lowered:
                target_col = lowered[candidate]
                break

        row_num = 0
        try:
            for row in reader:
                row_num += 1
                if self.files_scanned >= self.max_files:
                    break
                if target_col:
                    text = row.get(target_col) or ""
                else:
                    # No recognizable column header — scan the whole row as text.
                    text = " ".join(str(v) for v in row.values() if v)

                self.files_scanned += 1
                if not text:
                    continue
                try:
                    findings = analyze_text(text)
                except Exception:
                    self.errors_count += 1
                    continue
                for f in findings:
                    f["file_path"] = f"{path}:row{row_num}"
                    f["owner_uid"] = None
                    f["owner_gid"] = None
                    self.findings.append(f)
        except csv.Error:
            self.errors_count += 1


# ------------------------------------------------------------------------ #
# Backwards-compatible alias (template used ScanEngine as the class name).
# ------------------------------------------------------------------------ #
ScanEngine = EncodedCommandDetector


# -------------------------------------------------------------------------- #
# Real regex-based candidate detection + real decode helpers
# -------------------------------------------------------------------------- #
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){10,}")
URLENC_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){5,}")
POWERSHELL_CHARCODE_RE = re.compile(r"(?:\[char\]\s*\d{1,3}\s*[,+]?\s*){5,}", re.IGNORECASE)
JS_FROMCHARCODE_RE = re.compile(r"String\.fromCharCode\(\s*(\d{1,3}(?:\s*,\s*\d{1,3}){4,})\s*\)", re.IGNORECASE)
CHARCODE_NUM_RE = re.compile(r"\d{1,3}")

def _is_printable_text(s, min_ratio=0.85, min_len=4):
    """Real heuristic: is this decoded string 'meaningful' printable text?"""
    if not s or len(s) < min_len:
        return False
    printable = sum(1 for ch in s if ch.isprintable() or ch in "\t\n\r")
    return (printable / len(s)) >= min_ratio


def _try_decode_base64(candidate):
    """Real base64 decode attempt with padding correction. Returns
    (decoded_text_or_None, is_binary_bool)."""
    padded = candidate
    missing = len(padded) % 4
    if missing:
        padded += "=" * (4 - missing)
    try:
        raw = base64.b64decode(padded, validate=False)
    except Exception:
        return None, False
    if not raw:
        return None, False
    # Try UTF-8 first (most common), then UTF-16LE (common for PowerShell -EncodedCommand)
    for encoding in ("utf-8", "utf-16le"):
        try:
            text = raw.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
        if _is_printable_text(text):
            return text, False
    return None, True  # decoded to bytes but not recognizable printable text -> binary-looking


def _try_decode_hex(candidate):
    try:
        raw = bytes.fromhex(candidate)
    except ValueError:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if _is_printable_text(text) else None


def _try_decode_urlenc(candidate):
    try:
        text = unquote(candidate)
    except Exception:
        return None
    if text == candidate:
        return None
    if _is_printable_text(text) or any(marker in text.lower() for marker in ("http", "cmd", "powershell", "/bin/")):
        return text
    return None


def _try_decode_charcode(match_text):
    """Real chr() decode of every matched numeric code, joined into a string."""
    codes = [int(n) for n in CHARCODE_NUM_RE.findall(match_text)]
    codes = [c for c in codes if 0 <= c <= 0x10FFFF]
    if len(codes) < 5:
        return None
    try:
        decoded = "".join(chr(c) for c in codes)
    except (ValueError, OverflowError):
        return None
    return decoded if decoded else None


def analyze_text(text):
    """Real, pure analysis of one blob of ACTUAL text content. Returns a list
    of Finding dicts (rule_id/rule_name/severity/description/permissions_octal).
    Never executes anything — pure regex + decode + keyword matching."""
    findings = []
    seen_spans = set()

    # --- 1. Base64 candidates ---
    for m in BASE64_RE.finditer(text):
        span = m.span()
        if span in seen_spans:
            continue
        seen_spans.add(span)
        candidate = m.group(0)
        decoded_text, is_binary = _try_decode_base64(candidate)
        result = rule_base64_suspicious_keyword(candidate, decoded_text)
        if result:
            findings.append(result)
            continue
        result = rule_base64_binary_payload(candidate, decoded_text, is_binary)
        if result:
            findings.append(result)
            continue
        if decoded_text is None and not is_binary:
            result = rule_undecodable_candidate(candidate, "base64")
            if result:
                findings.append(result)

    # --- 2. Hex candidates ---
    for m in HEX_RE.finditer(text):
        candidate = m.group(0)
        decoded_text = _try_decode_hex(candidate)
        result = rule_hex_suspicious_keyword(candidate, decoded_text)
        if result:
            findings.append(result)
        elif decoded_text is None:
            result = rule_undecodable_candidate(candidate, "hex")
            if result:
                findings.append(result)

    # --- 3. URL-encoding candidates ---
    for m in URLENC_RE.finditer(text):
        candidate = m.group(0)
        decoded_text = _try_decode_urlenc(candidate)
        result = rule_urlencoded_suspicious_keyword(candidate, decoded_text)
        if result:
            findings.append(result)

    # --- 4. Char-code / ASCII-array obfuscation candidates ---
    for m in POWERSHELL_CHARCODE_RE.finditer(text):
        candidate = m.group(0)
        decoded_text = _try_decode_charcode(candidate)
        result = rule_charcode_obfuscation_technique(candidate, decoded_text)
        if result:
            findings.append(result)

    for m in JS_FROMCHARCODE_RE.finditer(text):
        candidate = m.group(0)
        decoded_text = _try_decode_charcode(m.group(1))
        result = rule_charcode_obfuscation_technique(candidate, decoded_text)
        if result:
            findings.append(result)

    return findings
