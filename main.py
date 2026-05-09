import os
import security as sc  # 성헌님 엔진
import file_mover as fm  # 지민님 모듈
import data_logger as dl  # 성환님 모듈

# 1. 설정: 테스트할 폴더 경로
TARGET_DIR = "./test_files"


def setup_test_environment():
    """발표용 테스트 파일들을 자동으로 생성합니다."""
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)

    # 성헌님 엔진이 잡을 수 있는 패턴을 가진 가짜 악성 파일들
    samples = {
        "malware_01.txt": "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",  # EICAR 테스트 문자열
        "clean_doc.txt": "이 파일은 안전한 일반 문서 내용입니다.",
        "suspicious_script.py": "import os; os.system('format c:')",  # 위험해 보이는 패턴
        "normal_photo.png": "이미지 데이터 샘플"
    }

    for name, content in samples.items():
        with open(os.path.join(TARGET_DIR, name), "w", encoding="utf-8") as f:
            f.write(content)
    print(f"✅ {TARGET_DIR} 폴더에 테스트 파일 4개가 생성되었습니다.")


def main():
    # 환경 세팅
    setup_test_environment()

    # 폴더 내 파일 목록 가져오기
    files = [os.path.join(TARGET_DIR, f) for f in os.listdir(TARGET_DIR) if os.path.isfile(os.path.join(TARGET_DIR, f))]
    safe_files = []

    print("\n🚀 지능형 AI 보안 스캔 시스템 가동 (66/75 탐지 모드)")
    print("-" * 50)

    for f_path in files:
        f_name = os.path.basename(f_path)

        # 1. 성헌 엔진 스캔
        is_safe = sc.check_security(f_path)

        # 2. 성환 로그 저장 (실시간)
        status = "안전" if is_safe else "위험(격리)"
        dl.save_log(f_name, status)

        if is_safe:
            print(f"[PASS] {f_name} - 안전함")
            safe_files.append(f_path)
        else:
            print(f"[BLOCK] {f_name} - 악성코드 탐지! 격리 조치합니다.")
            sc.quarantine(f_path)  # 성헌님의 격리 함수

    # 3. 지민 이동 모듈 실행 (안전한 파일만 이동)
    if safe_files:
        fm.run_file_mover(safe_files)

    print("-" * 50)
    print("✅ 모든 작업 완료. 'program_log.xlsx'를 확인하세요.")


if __name__ == '__main__':
    main()