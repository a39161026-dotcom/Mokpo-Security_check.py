"""
file_mover.py
담당: 김지민
기능: 안전 파일 이동
"""

import os
import shutil
from datetime import datetime

# ──────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────
SAFE_DIR = "./safe_files"


# ──────────────────────────────────────────────
# 공개 함수
# ──────────────────────────────────────────────
def run_file_mover(safe_files):
    """
    안전 파일 리스트를 받아
    safe_files 폴더로 이동

    입력:
        safe_files (list)

    출력:
        move_count (int)
    """

    os.makedirs(SAFE_DIR, exist_ok=True)

    move_count = 0

    print("\n 파일 이동 시작")

    for file_path in safe_files:

        if not os.path.exists(file_path):
            print(f"파일 없음: {file_path}")
            continue

        filename = os.path.basename(file_path)

        dest = os.path.join(SAFE_DIR, filename)

        if os.path.exists(dest):
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")

            name, ext = os.path.splitext(filename)

            dest = os.path.join(
                SAFE_DIR,
                f"{name}_{ts}{ext}"
            )

        try:

            shutil.move(file_path, dest)

            print(f"이동 완료: {filename}")

            move_count += 1

        except (PermissionError, OSError) as e:

            print(f"이동 실패: {e}")

    print(f"\n 총 이동 파일 수: {move_count}")

    return move_count


# ──────────────────────────────────────────────
# 단독 테스트
# ──────────────────────────────────────────────
if __name__ == "__main__":
    test_files = [
        "./test1.txt",
        "./test2.png"
    ]

    result = run_file_mover(test_files)

    print(f"\n최종 결과: {result}개 이동")