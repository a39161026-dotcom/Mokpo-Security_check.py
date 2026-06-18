import os

try:
    import security as sc
except ImportError:
    sc = None

try:
    import file_mover as fm
except ImportError:
    fm = None

try:
    import data_logger as dl
except ImportError:
    dl = None

# 1. 설정: 테스트할 폴더 경로
TARGET_DIR = "./test_files"


def setup_test_environment():
    """발표용 테스트 파일들을 자동으로 생성합니다."""
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)

    samples = {
        "malware_01.txt": r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        "clean_doc.txt": "이 파일은 안전한 일반 문서 내용입니다.",
        "suspicious_script.py": "import os; os.system('format c:')",
        "normal_photo.png": "이미지 데이터 샘플"
    }

    for name, content in samples.items():
        with open(os.path.join(TARGET_DIR, name), "w", encoding="utf-8") as f:
            f.write(content)
    print(f"✅ {TARGET_DIR} 폴더에 테스트 파일 4개가 생성되었습니다.")


def main():
    if not sc:
        print("security 모듈 없음")
        return

    setup_test_environment()

    files = [os.path.join(TARGET_DIR, f) for f in os.listdir(TARGET_DIR) if os.path.isfile(os.path.join(TARGET_DIR, f))]
    safe_files = []

    print("\n🚀 지능형 AI 보안 스캔 시스템 가동 (66/75 탐지 모드)")
    print("-" * 50)

    for f_path in files:
        f_name = os.path.basename(f_path)

        scan_result = sc.check_security(f_path)
        is_safe = scan_result["is_safe"]

        status = "안전" if is_safe else "위험(격리)"
        if dl:
            dl.save_log(f_name, status)

        if is_safe:
            print(f"[PASS] {f_name} - 안전함")
            safe_files.append(f_path)
        else:
            print(f"[BLOCK] {f_name} - 악성코드 탐지! 격리 조치합니다.")
            sc.quarantine(f_path)

    if safe_files and fm:
        fm.run_file_mover(safe_files)

    print("-" * 50)
    print("✅ 모든 작업 완료. 'program_log.xlsx'를 확인하세요.")


if __name__ == '__main__':
    main()