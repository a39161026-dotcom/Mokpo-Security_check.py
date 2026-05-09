"""
data_logger.py
담당: 김성환 | Pandas 기반 작업 내역 및 보안 로그 저장
"""

import os
import pandas as pd
from datetime import datetime

# ──────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────
LOG_FILE_PATH = "program_log.xlsx"  # 저장될 로그 파일 이름


# ──────────────────────────────────────────────
# 공개 함수 (main.py에서 호출)
# ──────────────────────────────────────────────
def save_log(file_name: str, status: str):
    """
    [main.py -> dl.save_log(file_name, status)]
    작업 내역을 Pandas DataFrame을 통해 엑셀로 저장
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. 새 데이터 생성
    new_data = {
        "일시": [now],
        "파일명": [file_name],
        "상태": [status]
    }
    new_df = pd.DataFrame(new_data)

    try:
        # 2. 기존 로그 파일이 있는지 확인
        if os.path.exists(LOG_FILE_PATH):
            # 기존 데이터를 불러와서 새 데이터와 합침 (append 방식)
            existing_df = pd.read_excel(LOG_FILE_PATH)
            combined_df = pd.concat([existing_df, new_df], ignore_index=True)
            combined_df.to_excel(LOG_FILE_PATH, index=False)
        else:
            # 파일이 없으면 새로 생성
            new_df.to_excel(LOG_FILE_PATH, index=False)

        print(f"  📊 로그 기록 성공: {LOG_FILE_PATH}")

    except Exception as e:
        print(f"  [오류] 로그 기록 실패: {e}")
        print("  팁: 엑셀 파일이 열려있다면 닫고 다시 실행하세요.")


# ──────────────────────────────────────────────
# 단독 테스트 (data_logger.py만 실행할 때)
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  📊 Logger - 작업 내역 엑셀 저장 (단독 실행 테스트)")
    print("=" * 60)

    test_file = "test_sample.txt"
    test_status = "성공(테스트)"

    save_log(test_file, test_status)
    print("\n[확인] 현재 폴더에 'program_log.xlsx' 파일이 생성되었는지 확인하세요.")