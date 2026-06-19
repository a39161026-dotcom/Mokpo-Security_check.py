from django.apps import AppConfig


class ScannerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scanner'

    # media 폴더 자동 감시 기능은 views.py의 업로드 즉시 스캔과 중복되어
    # 업로드마다 VT API가 두 번 호출되고, SHA256/엔진 정보가 빠진 중복 ScanLog가
    # 생성되는 문제가 있어 비활성화함.
    def ready(self):
        pass
