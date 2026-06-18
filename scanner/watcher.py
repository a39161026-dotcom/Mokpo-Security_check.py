import time
import os
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class SecurityHandler(FileSystemEventHandler):
    def __init__(self, api_key):
        self.api_key = api_key

    def on_created(self, event):
        if event.is_directory:
            return

        import django
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

        file_path = event.src_path
        filename = os.path.basename(file_path)

        # 임시파일 무시
        if filename.startswith('.') or filename.startswith('_'):
            return

        print(f"\n🔍 새 파일 감지: {filename}")

        try:
            import security as sc
            from scanner.models import ScanLog

            sc._SAVED_API_KEY = self.api_key
            scan_result = sc.check_security(file_path)
            is_safe = scan_result["is_safe"]
            status = 'clean' if is_safe else scan_result["status"]
            if status not in dict(ScanLog.STATUS_CHOICES):
                status = 'malicious'

            ScanLog.objects.create(
                file_name=filename,
                status=status,
                detections=scan_result["detections"],
                total_engines=scan_result["total"],
                is_compressed=False,
                saved_path=file_path
            )

            if is_safe:
                print(f"✅ 안전: {filename}")
            else:
                print(f"🚨 악성 탐지! 격리 중: {filename}")
                sc.quarantine(file_path)

        except Exception as e:
            print(f"오류: {e}")


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


def start_media_watching(media_dir: str, api_key: str):
    """서버 시작 시 media 폴더 자동 감시"""
    os.makedirs(media_dir, exist_ok=True)
    event_handler = SecurityHandler(api_key)
    observer = Observer()
    observer.schedule(event_handler, media_dir, recursive=False)
    observer.start()
    print(f"👁️ media 폴더 자동 감시 시작: {media_dir}")
    return observer