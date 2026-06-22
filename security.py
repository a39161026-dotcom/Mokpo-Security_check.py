"""
security_check.py - 핵심 보안 엔진 (개선판)
VirusTotal API 기반 실시간 악성코드 탐지 및 격리 시스템
"""

import os
import sys
import json
import time
import shutil
import hashlib
import requests
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

QUARANTINE_DIR = Path("./quarantine")
REPORT_FILE    = "./security_report.json"
VT_API_URL     = "https://www.virustotal.com/api/v3/files/{}"
REQUEST_DELAY  = 15

_SAVED_API_KEY = ""

def calculate_sha256(filepath: str) -> Optional[str]:
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError) as e:
        print(f"  [error] hash failed: {filepath} -> {e}")
        return None

def query_virustotal(sha256_hash: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"status": "error", "detections": 0, "total": 0, "engines": [], "message": "API key missing"}

    headers = {"x-apikey": api_key}
    url = VT_API_URL.format(sha256_hash)

    try:
        response = requests.get(url, headers=headers, timeout=10)
        print(f"[DEBUG-RAW] VT response code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            attrs = data["data"]["attributes"]
            stats = attrs["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            if malicious >= 3:
                status = "malicious"
            elif malicious >= 1 or suspicious >= 3:
                status = "suspicious"
            else:
                status = "clean"

            raw_engine_results = attrs.get("last_analysis_results", {})
            flagged_engines = [
                {
                    "engine": name,
                    "category": info.get("category"),
                    "result": info.get("result") or "-",
                }
                for name, info in raw_engine_results.items()
                if info.get("category") in ("malicious", "suspicious")
            ]

            return {
                "status": status,
                "detections": malicious + suspicious,
                "total": total,
                "engines": flagged_engines,
            }

        elif response.status_code == 404:
            return {"status": "unknown", "detections": 0, "total": 0, "engines": []}

        elif response.status_code == 401:
            print("  [error] invalid api key")
            return {"status": "error", "detections": 0, "total": 0, "engines": []}

        elif response.status_code == 429:
            print("  [warn] rate limited, retry after 60s")
            time.sleep(60)
            return query_virustotal(sha256_hash, api_key)

        else:
            print(f"  [error] VT response code: {response.status_code}")
            return {"status": "error", "detections": 0, "total": 0, "engines": []}

    except requests.RequestException as e:
        print(f"  [error] network error: {e}")
        return {"status": "error", "detections": 0, "total": 0, "engines": []}

def quarantine_file(filepath: str) -> Optional[str]:
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        filename = os.path.basename(filepath)
        dest = QUARANTINE_DIR / filename

        if dest.exists():
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = QUARANTINE_DIR / f"{dest.stem}_{ts}{dest.suffix}"

        shutil.move(filepath, str(dest))
        return str(dest)
    except Exception as e:
        print(f"  [error] quarantine failed: {e}")
        return None

STATUS_ICON = {
    "clean": "ok", "suspicious": "warn", "malicious": "danger",
    "unknown": "unknown", "error": "error"
}

def print_result(filename: str, status: str, detections: int, total: int, quarantined: bool):
    icon = STATUS_ICON.get(status, "?")
    det = f"({detections}/{total})" if total > 0 else ""
    qstr = " -> [quarantined]" if quarantined else ""
    print(f"  {icon} {det}  {filename}{qstr}")

def scan_directory(target_dir: str, api_key: str) -> List[Dict]:
    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        print(f"[error] path not found: {target_dir}")
        return []

    quarantine_path = Path(QUARANTINE_DIR).resolve()
    files = [f for f in target_path.rglob("*")
             if f.is_file() and not str(f.resolve()).startswith(str(quarantine_path))]

    if not files:
        print("no files to scan")
        return []

    print(f"scanning {len(files)} files...")
    results = []

    for idx, filepath in enumerate(files, 1):
        print(f"[{idx}/{len(files)}] {filepath.name}")
        sha256 = calculate_sha256(str(filepath))

        if not sha256:
            results.append({"file": str(filepath), "status": "error", "quarantined": False})
            continue

        vt_result = query_virustotal(sha256, api_key)
        status = vt_result["status"]

        is_quarantined = False
        q_path = None
        if status in ("malicious", "suspicious"):
            q_path = quarantine_file(str(filepath))
            is_quarantined = bool(q_path)

        print_result(filepath.name, status, vt_result["detections"], vt_result["total"], is_quarantined)

        results.append({
            "file": str(filepath), "sha256": sha256, "status": status,
            "detections": vt_result["detections"], "total": vt_result["total"],
            "quarantined": is_quarantined, "quarantine_path": q_path,
            "scanned_at": datetime.now().isoformat()
        })

        if idx < len(files): time.sleep(REQUEST_DELAY)

    return results

def save_report(results: List[Dict]):
    summary = {
        "scan_time": datetime.now().isoformat(),
        "total": len(results),
        "clean": sum(1 for r in results if r["status"] == "clean"),
        "malicious": sum(1 for r in results if r["status"] == "malicious"),
    }
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "details": results}, f, ensure_ascii=False, indent=2)
    print(f"report saved: {REPORT_FILE}")

def check_security(file_name: str) -> Dict[str, Any]:
    global _SAVED_API_KEY
    if not _SAVED_API_KEY:
        _SAVED_API_KEY = input("VirusTotal API key: ").strip()

    sha256 = calculate_sha256(file_name)
    if not sha256:
        return {"is_safe": False, "status": "error", "detections": 0, "total": 0, "sha256": "", "engines": []}

    result = query_virustotal(sha256, _SAVED_API_KEY)
    print_result(os.path.basename(file_name), result["status"], result["detections"], result["total"], False)

    is_safe = result["status"] in ("clean", "unknown")
    return {
        "is_safe": is_safe,
        "status": result["status"],
        "detections": result["detections"],
        "total": result["total"],
        "sha256": sha256,
        "engines": result.get("engines", []),
    }

def quarantine(file_name: str):
    dest = quarantine_file(file_name)
    if dest: print(f"  quarantined: {os.path.basename(file_name)}")

if __name__ == "__main__":
    api_input = input("API key: ").strip()
    target_input = input("folder (default .): ").strip() or "."
    scan_results = scan_directory(target_input, api_input)
    if scan_results: save_report(scan_results)
