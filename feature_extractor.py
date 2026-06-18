"""
feature_extractor.py
VirusTotal 결과가 오기 전에, 파일 자체의 특징만으로 위험도를 사전 예측하는 모듈.

지금은 룰 기반(rule-based) 스코어링으로 시작 — ScanLog에 데이터가 충분히 쌓이면
이 feature들(file_size, file_extension, entropy)을 학습 데이터로 써서
실제 ML 모델(RandomForest 등)로 교체하기 쉽게 설계되어 있음.
"""

import math
import os
from collections import Counter
from typing import Dict, Any

# ──────────────────────────────────────────────
# 확장자별 기본 위험 가중치 (0~100)
# 실행 가능/스크립트 계열일수록 높게, 문서/이미지는 낮게
# ──────────────────────────────────────────────
EXTENSION_RISK = {
    ".exe": 40, ".dll": 35, ".scr": 45, ".bat": 35, ".cmd": 35,
    ".ps1": 35, ".vbs": 35, ".js": 25, ".jar": 30,
    ".zip": 15, ".rar": 15, ".7z": 15,
    ".docm": 30, ".xlsm": 30, ".pptm": 30,  # 매크로 포함 가능 오피스 파일
    ".doc": 10, ".docx": 5, ".xls": 10, ".xlsx": 5, ".pdf": 8,
    ".png": 2, ".jpg": 2, ".jpeg": 2, ".gif": 2,
    ".txt": 1, ".csv": 1,
}
DEFAULT_EXTENSION_RISK = 12  # 목록에 없는 확장자 기본값


def calculate_entropy(filepath: str, sample_size: int = 1024 * 256) -> float:
    """
    파일의 섀넌 엔트로피(0~8)를 계산.
    너무 큰 파일은 앞부분 일부(sample_size)만 읽어서 속도 확보.
    엔트로피가 높을수록(7.5+) 암호화/압축/난독화된 코드일 가능성이 큼.
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read(sample_size)
    except (OSError, PermissionError):
        return 0.0

    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def extract_features(filepath: str) -> Dict[str, Any]:
    """파일에서 사전 위험도 예측에 쓸 feature들을 뽑아낸다."""
    file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
    extension = os.path.splitext(filepath)[1].lower()
    entropy = calculate_entropy(filepath)

    return {
        "file_size": file_size,
        "file_extension": extension,
        "entropy": entropy,
    }


def calculate_risk_score(features: Dict[str, Any]) -> float:
    """
    룰 기반 사전 위험도 점수 (0~100).
    - 확장자 기본 위험도
    - 엔트로피 높음 (난독화/암호화 의심) → 가중치 추가
    - 파일 크기가 매우 작은데 실행 파일 계열 → 가중치 추가 (드로퍼 의심)
    """
    score = EXTENSION_RISK.get(features["file_extension"], DEFAULT_EXTENSION_RISK)

    entropy = features.get("entropy", 0.0)
    if entropy >= 7.5:
        score += 30
    elif entropy >= 7.0:
        score += 15
    elif entropy >= 6.5:
        score += 5

    size = features.get("file_size", 0)
    is_executable_like = features["file_extension"] in (
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".jar"
    )
    if is_executable_like and 0 < size < 20 * 1024:  # 20KB 미만 실행파일 = 드로퍼 의심
        score += 15

    return round(min(score, 100.0), 1)


def analyze_file(filepath: str) -> Dict[str, Any]:
    """feature 추출 + risk_score 계산을 한 번에 처리하는 외부 호출용 함수."""
    features = extract_features(filepath)
    risk_score = calculate_risk_score(features)
    features["risk_score"] = risk_score
    return features


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else __file__
    result = analyze_file(target)
    print(f"파일: {target}")
    print(f"크기: {result['file_size']} bytes")
    print(f"확장자: {result['file_extension']}")
    print(f"엔트로피: {result['entropy']}")
    print(f"사전 위험도 점수: {result['risk_score']} / 100")
