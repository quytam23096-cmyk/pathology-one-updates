#!/usr/bin/env python3
"""Public metadata monitor, not an updater. Never holds a signing key or installs files."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "quytam23096-cmyk/pathology-one-updates"
FEED = "https://github.com/" + REPOSITORY + "/releases/latest/download/"
KEY_ID = "p1-rsa3072-0a63ae07c43b3e7c15c2fcdd2afd120b"
SPKI = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAsejLm+sm6Hzua66b7T+19VAJHWh2E9OLKu7t9X15zJGSggAayDZcdKWEbQSEFRBDYP8ErzGN2U18fcLzNQMoIu0ZPikYerPbT7E0OwW1RJUA5n2K3vEO3l8uKL9loFEwcR9Z7qxOYyi5V3zDR1HL5OLTcGyxkU77QNrTMwDTuhyPXICYRIEPrVEGwKxkwMABM86QKTrFdk2Hc/p7KCTkHEfIY1JaNFDXjHwDGJ+cL1TS61ci0ySb/9cquj8X99ddZjq2D8ZWQFTqwy92glVZqMhJMZqz44igl8cyMKj3ECsnDA9sNz/62dmLKe4ix5qL8tGpFkNDkrwAgrQ+Sw6i9kTtkZ2e9+4voVFk2GdzUzWnLgXGPFHiRBwalK0S9Wl7FhdJV80cMTuKBrJutq3YfmfvlEWY2+yqRYP1ciU9wJRGHFw8nvgmesd5P/hLuKy+YH0YWPwDyG1UTxLCMFD29GyS21hs1VHK1hFVmJT5Tx+H1KZZVWzu/I4Px5XhblRlAgMBAAE="
SPKI_SHA256 = "0a63ae07c43b3e7c15c2fcdd2afd120b1d49feb9dc7e6febcc6d7f0c4c3db736"
MINIMUM_SEQUENCE = 1010
MINIMUM_VERSION = (1, 0, 0, 9)
MAX_MANIFEST = 65536
MAX_INDEX = 8 * 1024 * 1024
MAX_PART = 64 * 1024 * 1024
MAX_PARTS = 64
ISSUE_MARKER = "<!-- pathology-one-signed-manifest-monitor-v1 -->"
ISSUE_TITLE = "Pathology One: signed update manifest needs attention"
TEST_ISSUE_TITLE = "[TEST] Pathology One signed manifest notification"
FIELDS = (
    "contract", "productId", "channel", "version", "sequence", "publishedUtc",
    "expiresUtc", "packageName", "packageLength", "packageSha256", "publisherKeyId",
    "manifestSignature", "packageSignature", "releaseNotes", "minimumHostVersion",
    "minimumSchemaVersion", "maximumSchemaVersion", "parsedVersion", "parsedMinimumHostVersion",
    "targetOs", "targetArchitecture", "minimumApiVersion", "maximumApiVersion",
)
REQUIRED_FIELDS = set(FIELDS[:19])


class MonitorError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise MonitorError(code)


def unique_object(pairs):
    value = {}
    for key, child in pairs:
        require(key not in value, "JSON_DUPLICATE_FIELD")
        value[key] = child
    return value


def parse_json(raw, limit):
    require(isinstance(raw, bytes) and 0 < len(raw) <= limit, "JSON_SIZE_INVALID")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(MonitorError("JSON_NUMBER_INVALID")))
    except (UnicodeError, ValueError, RecursionError):
        raise MonitorError("JSON_INVALID") from None
    require(isinstance(value, dict), "JSON_OBJECT_REQUIRED")
    return value


def version(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9]{1,9}(\.[0-9]{1,9}){3}", value) is not None,
            "VERSION_INVALID")
    return tuple(int(part) for part in value.split("."))


def utc(value):
    require(isinstance(value, str) and len(value) <= 40, "UTC_INVALID")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise MonitorError("UTC_INVALID") from None
    require(parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(0), "UTC_REQUIRED")
    return parsed


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def signature(value):
    require(isinstance(value, str) and len(value) <= 2048, "SIGNATURE_INVALID")
    try:
        result = base64.b64decode(value, validate=True)
    except ValueError:
        raise MonitorError("SIGNATURE_INVALID") from None
    require(len(result) == 384, "SIGNATURE_INVALID")
    return result


def dotnet_string(value):
    """System.Text.Json default ASCII escaping used by the signed v1 contract."""
    encoded = []
    for char in value:
        point = ord(char)
        if char == "\\":
            encoded.append("\\\\")
        elif char in '\"&\'+<>`' or point < 32 or point > 126:
            if point <= 0xFFFF:
                encoded.append("\\u%04X" % point)
            else:
                point -= 0x10000
                encoded.append("\\u%04X\\u%04X" % (0xD800 + (point >> 10), 0xDC00 + (point & 1023)))
        else:
            encoded.append(char)
    return '"' + "".join(encoded) + '"'


def canonical_manifest(manifest):
    parts = []
    for key in FIELDS:
        if key not in manifest:
            continue
        value = "" if key == "manifestSignature" else manifest[key]
        require(isinstance(value, (str, int)) and not isinstance(value, bool), "MANIFEST_TYPE_INVALID")
        if key in ("publishedUtc", "expiresUtc"):
            # System.Text.Json's DateTimeOffset writer emits the '+' offset directly.
            # The publisher emits UTC with 0-7 fractional digits; retain the signed precision.
            require(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,7})?\+00:00", value)
                    is not None, "PUBLISHER_DATE_FORMAT_INVALID")
            serialized = '"' + value + '"'
        else:
            serialized = dotnet_string(value) if isinstance(value, str) else str(value)
        parts.append(dotnet_string(key) + ":" + serialized)
    return ("{" + ",".join(parts) + "}").encode("ascii")


def openssl_verify(data, signed, spki=SPKI, executable="openssl"):
    try:
        public = base64.b64decode(spki, validate=True)
        require(hashlib.sha256(public).hexdigest() == SPKI_SHA256, "PUBLIC_KEY_PIN_INVALID")
        with tempfile.TemporaryDirectory(prefix="p1-public-monitor-") as folder:
            root = Path(folder)
            (root / "key.pem").write_text("-----BEGIN PUBLIC KEY-----\n" + "\n".join(
                spki[i:i + 64] for i in range(0, len(spki), 64)) + "\n-----END PUBLIC KEY-----\n", encoding="ascii")
            (root / "data").write_bytes(data)
            (root / "signature").write_bytes(signed)
            run = subprocess.run([executable, "dgst", "-sha256", "-verify", str(root / "key.pem"),
                                  "-signature", str(root / "signature"), str(root / "data")],
                                 capture_output=True, timeout=15, check=False)
            require(run.returncode == 0, "RSA_SIGNATURE_INVALID")
    except (OSError, subprocess.SubprocessError, ValueError):
        raise MonitorError("SIGNATURE_CHECK_UNAVAILABLE") from None


def validate_manifest(manifest, now, verifier=openssl_verify):
    require(REQUIRED_FIELDS <= set(manifest) <= set(FIELDS), "MANIFEST_FIELDS_INVALID")
    require(manifest["contract"] == "pathology-one-update-v1" and manifest["productId"] == "PathologyOne"
            and manifest["channel"] == "stable", "MANIFEST_IDENTITY_INVALID")
    require(version(manifest["version"]) >= MINIMUM_VERSION, "VERSION_ROLLBACK")
    require(version(manifest["minimumHostVersion"]) <= version(manifest["version"]), "MINIMUM_HOST_INVALID")
    require(manifest["parsedVersion"] == manifest["version"]
            and manifest["parsedMinimumHostVersion"] == manifest["minimumHostVersion"], "PARSED_VERSION_INVALID")
    require(integer(manifest["sequence"], MINIMUM_SEQUENCE, 2**63 - 1), "SEQUENCE_ROLLBACK")
    require(manifest["publisherKeyId"] == KEY_ID, "PUBLISHER_UNTRUSTED")
    require(isinstance(manifest["packageName"], str) and re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,179}",
            manifest["packageName"]) is not None and ".." not in manifest["packageName"], "PACKAGE_NAME_INVALID")
    require(integer(manifest["packageLength"], 1, MAX_PART), "PACKAGE_SIZE_INVALID")
    require(isinstance(manifest["packageSha256"], str) and re.fullmatch(r"[A-Fa-f0-9]{64}",
            manifest["packageSha256"]) is not None, "PACKAGE_HASH_INVALID")
    require(integer(manifest["minimumSchemaVersion"], 1, 2**31 - 1)
            and integer(manifest["maximumSchemaVersion"], manifest["minimumSchemaVersion"], 2**31 - 1),
            "SCHEMA_RANGE_INVALID")
    require(manifest.get("targetOs") in (None, "windows")
            and manifest.get("targetArchitecture") in (None, "x64", "arm64", "x86"), "TARGET_INVALID")
    require(("minimumApiVersion" in manifest) == ("maximumApiVersion" in manifest), "API_RANGE_INVALID")
    if "minimumApiVersion" in manifest:
        require(integer(manifest["minimumApiVersion"], 1, 2**31 - 1)
                and integer(manifest["maximumApiVersion"], manifest["minimumApiVersion"], 2**31 - 1), "API_RANGE_INVALID")
    notes = manifest["releaseNotes"]
    require(isinstance(notes, str) and len(notes) <= 16384 and not any(ord(c) < 32 for c in notes), "NOTES_INVALID")
    published, expiry = utc(manifest["publishedUtc"]), utc(manifest["expiresUtc"])
    require(published <= now + dt.timedelta(minutes=5) and expiry > published, "MANIFEST_TIME_INVALID")
    verifier(canonical_manifest(manifest), signature(manifest["manifestSignature"]))
    signature(manifest["packageSignature"])
    return expiry


def safe_download_url(url):
    part = urllib.parse.urlsplit(url)
    require(part.scheme == "https" and part.username is None and part.password is None
            and part.port in (None, 443) and not part.fragment, "DOWNLOAD_URL_REJECTED")
    require((part.hostname == "github.com" and part.path.startswith("/" + REPOSITORY + "/releases/"))
            or (part.hostname == "release-assets.githubusercontent.com" and part.path.startswith("/github-production-release-asset/")),
            "DOWNLOAD_HOST_REJECTED")


class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        safe_download_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, limit):
    safe_download_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "PathologyOne-Public-Expiry-Monitor/1"})
    try:
        with urllib.request.build_opener(RestrictedRedirect()).open(request, timeout=30) as response:
            safe_download_url(response.url)
            body = response.read(limit + 1)
            require(len(body) <= limit, "DOWNLOAD_LIMIT_EXCEEDED")
            return body
    except (urllib.error.URLError, TimeoutError, OSError):
        raise MonitorError("PUBLIC_FEED_UNAVAILABLE") from None


def inspect_metadata(raw_manifest, raw_index, now, verifier=openssl_verify):
    manifest = parse_json(raw_manifest, MAX_MANIFEST)
    expiry = validate_manifest(manifest, now, verifier)
    require(manifest["packageName"] == "release-index.json" and manifest["packageLength"] <= MAX_INDEX,
            "RELEASE_INDEX_REQUIRED")
    require(len(raw_index) == manifest["packageLength"] and hashlib.sha256(raw_index).hexdigest()
            == manifest["packageSha256"].lower(), "INDEX_HASH_INVALID")
    verifier(raw_index, signature(manifest["packageSignature"]))
    index = parse_json(raw_index, MAX_INDEX)
    require(set(index) == {"format", "productId", "version", "entryExecutable", "archiveLength", "archiveSha256",
                           "expandedLength", "files", "parts"}, "INDEX_FIELDS_INVALID")
    require(index["format"] == "pathology-one-full-release-chunks-v1" and index["productId"] == "PathologyOne"
            and index["version"] == manifest["version"] and index["entryExecutable"] == "PathologyCopilot.exe",
            "INDEX_IDENTITY_INVALID")
    require(isinstance(index["parts"], list) and 1 <= len(index["parts"]) <= MAX_PARTS, "PARTS_INVALID")
    require(isinstance(index["files"], list) and 1 <= len(index["files"]) <= 100000, "FILE_LIST_INVALID")
    total, names = 0, set()
    for position, part in enumerate(index["parts"]):
        require(isinstance(part, dict) and set(part) == {"position", "manifest"}
                and type(part["position"]) is int and part["position"] == position, "PART_POSITION_INVALID")
        child = part["manifest"]
        require(isinstance(child, dict), "CHILD_MANIFEST_INVALID")
        expiry = min(expiry, validate_manifest(child, now, verifier))
        require(all(child[key] == manifest[key] for key in (
            "version", "sequence", "publisherKeyId", "publishedUtc", "minimumHostVersion", "minimumSchemaVersion",
            "maximumSchemaVersion")), "CHILD_IDENTITY_INVALID")
        require(re.fullmatch(r"part-[0-9]{3}\.bin", child["packageName"]) is not None
                and child["packageName"] not in names, "PART_NAME_INVALID")
        names.add(child["packageName"])
        total += child["packageLength"]
    require(integer(index["archiveLength"], 1, MAX_PARTS * MAX_PART) and index["archiveLength"] == total
            and integer(index["expandedLength"], 1, 16 * 1024**3), "ARCHIVE_SIZE_INVALID")
    require(isinstance(index["archiveSha256"], str) and re.fullmatch(r"[A-Fa-f0-9]{64}",
            index["archiveSha256"]) is not None, "ARCHIVE_HASH_INVALID")
    seconds = (expiry - now).total_seconds()
    level = "EXPIRED" if seconds <= 0 else "T7" if seconds <= 7 * 86400 else "T14" if seconds <= 14 * 86400 else "OK"
    return {"status": level, "version": manifest["version"], "sequence": manifest["sequence"],
            "earliestExpiryUtc": expiry.isoformat(), "daysRemaining": math.floor(seconds / 86400),
            "manifestSha256": hashlib.sha256(raw_manifest).hexdigest(),
            "indexSha256": hashlib.sha256(raw_index).hexdigest(), "childManifestsVerified": len(index["parts"]),
            "payloadDownloaded": False, "installedOrSigned": False}


def github_api(method, path, token, data=None):
    require(path.startswith("/repos/" + REPOSITORY + "/issues"), "API_PATH_REJECTED")
    request = urllib.request.Request("https://api.github.com" + path, method=method,
        data=None if data is None else json.dumps(data).encode(),
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "PathologyOne-Public-Expiry-Monitor/1",
                 "Content-Type": "application/json"})
    try:
        # A token is never forwarded to a redirect, another host, or release asset.
        opener = urllib.request.build_opener(type("NoRedirect", (urllib.request.HTTPRedirectHandler,),
            {"redirect_request": lambda *args: None})())
        with opener.open(request, timeout=30) as response:
            raw = response.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024, "ISSUE_API_LIMIT")
            return json.loads(raw)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise MonitorError("ISSUE_NOTIFICATION_FAILED") from None


def notify(report):
    token = os.environ.get("GITHUB_TOKEN", "")
    require(token and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "NOTIFICATION_CONTEXT_INVALID")
    issue = None
    for page in range(1, 11):
        items = github_api("GET", "/repos/" + REPOSITORY + "/issues?state=open&per_page=100&page=" + str(page), token)
        require(isinstance(items, list), "ISSUE_API_INVALID")
        matches = [item for item in items if item.get("title") in (ISSUE_TITLE, TEST_ISSUE_TITLE)
                   and ISSUE_MARKER in (item.get("body") or "") and not item.get("pull_request")]
        require(len(matches) <= 1 and not (issue and matches), "DUPLICATE_MONITOR_ISSUES")
        if matches:
            issue = matches[0]
        if len(items) < 100:
            break
    else:
        raise MonitorError("ISSUE_SCAN_LIMIT")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    require(re.fullmatch(r"[0-9]+", run_id) is not None, "RUN_CONTEXT_INVALID")
    run = "https://github.com/" + REPOSITORY + "/actions/runs/" + run_id
    if report["status"] == "OK":
        if issue:
            message = ("Notification test complete: actual signed public metadata remains healthy. "
                       if issue.get("title") == TEST_ISSUE_TITLE else
                       "Recovered: public signed metadata verified outside the 14-day warning window. ")
            github_api("POST", "/repos/" + REPOSITORY + "/issues/" + str(issue["number"]) + "/comments", token,
                       {"body": message + run})
            github_api("PATCH", "/repos/" + REPOSITORY + "/issues/" + str(issue["number"]), token, {"state": "closed"})
        return
    level_marker = "<!-- last-level:" + report["status"] + " -->"
    is_test = report["status"] == "TEST"
    title = TEST_ISSUE_TITLE if is_test else ISSUE_TITLE
    introduction = ("TEST notification only. Actual signed public metadata was verified healthy. "
                    "This is not an expiry or security alarm. This monitor does not renew or sign anything.\n\n"
                    if is_test else
                    "Signed update metadata requires owner attention. This monitor does not renew or sign anything.\n\n")
    action = ("No renewal is requested by this TEST. Run the workflow normally to close this monitor-marked test issue."
              if is_test else
              "Renew locally with the authorized protected key and increasing sequence before expiry. "
              "Keep the accepted payload and installer unchanged; verify with the actual client.")
    body = (ISSUE_MARKER + "\n" + level_marker + "\n@quytam23096-cmyk\n\n" + introduction
            + "```json\n" + json.dumps(report, indent=2, sort_keys=True) + "\n```\n\nRun: " + run
            + "\n\n" + action + " Offline use is not disabled by this monitor.")
    if not issue:
        github_api("POST", "/repos/" + REPOSITORY + "/issues", token, {"title": title, "body": body})
    elif level_marker not in (issue.get("body") or ""):
        path = "/repos/" + REPOSITORY + "/issues/" + str(issue["number"])
        github_api("PATCH", path, token, {"title": title, "body": body})
        github_api("POST", path + "/comments", token,
                   {"body": "@quytam23096-cmyk " + ("Notification TEST requested" if is_test else
                             "Alert changed to " + report["status"]) + ". " + run})


def require_notification_test_context(notifications_enabled):
    require(notifications_enabled and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and os.environ.get("P1_NOTIFICATION_TEST") == "true", "NOTIFICATION_TEST_CONTEXT_REJECTED")


def notification_test_report(report):
    require(report.get("status") == "OK", "NOTIFICATION_TEST_REQUIRES_HEALTHY_METADATA")
    return dict(report, status="TEST", realFeedStatus="OK", notificationTest=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--notify", action="store_true", help="Create/update only this repository's monitor issue")
    parser.add_argument("--notification-test", action="store_true", help="Manual-only marked notification test after healthy real verification")
    args = parser.parse_args()
    if args.notification_test:
        try:
            require_notification_test_context(args.notify)
        except MonitorError as error:
            print("::error::" + str(error))
            return 2
    try:
        now = dt.datetime.now(dt.timezone.utc)
        manifest = download(FEED + "manifest.json", MAX_MANIFEST)
        value = parse_json(manifest, MAX_MANIFEST)
        validate_manifest(value, now)
        require(value["packageName"] == "release-index.json" and value["packageLength"] <= MAX_INDEX,
                "RELEASE_INDEX_REQUIRED")
        report = inspect_metadata(manifest, download(FEED + "release-index.json", value["packageLength"]), now)
    except MonitorError as error:
        report = {"status": "ERROR", "code": str(error), "installedOrSigned": False}
    except Exception:
        report = {"status": "ERROR", "code": "MONITOR_INTERNAL_ERROR", "installedOrSigned": False}
    if args.notification_test and report["status"] == "OK":
        report = notification_test_report(report)
    print(json.dumps(report, sort_keys=True))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        Path(summary).write_text("## Public signed manifest monitor\n\n```json\n" + json.dumps(report, indent=2)
                                 + "\n```\n", encoding="utf-8")
    if args.notify:
        try:
            notify(report)
        except MonitorError as error:
            print("::error::" + str(error))
            return 2
    if report["status"] not in ("OK", "TEST"):
        print("::error::Signed update metadata needs attention: " + report["status"])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
