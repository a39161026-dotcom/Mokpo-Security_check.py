from django.apps import AppConfig


class ScannerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scanner'

    def ready(self):
        import threading
        import os
        from .watcher import start_media_watching

        api_key = os.environ.get('VT_API_KEY', '')
        if api_key:
            media_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'media'
            )
            thread = threading.Thread(
                target=start_media_watching, args=(media_dir, api_key), daemon=True
            )
            thread.start()