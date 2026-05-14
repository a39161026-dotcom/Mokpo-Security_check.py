import time
import os
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import security as sc


class SecurityHandler(FileSystemEventHandler):
    def __init__(self, api_key):
        self.api_key = api_key

    def on_created(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        filename = os.path.basename(file_path)

        print(f"\n🔍 새 파일 감지: {filename}")

        # API 키 설정 후 스캔
        sc._SAVED_API_KEY = self.api_key
        is_safe = sc.check_security(file_path)

        if is_safe:
            print(f"✅ 안전: {filename}")
        else:
            print(f"🚨 악성 탐지! 격리 중: {filename}")
            sc.quarantine(file_path)


def start_watching(watch_dir: str, api_key: str):
    os.makedirs(watch_dir, exist_ok=True)
    event_handler = SecurityHandler(api_key)
    observer = Observer()
    observer.schedule(event_handler, watch_dir, recursive=False)
    observer.start()
    print(f"👁️ 실시간 감시 시작: {watch_dir}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()