import os
import sys
import threading

from django.shortcuts import render
from .forms import UploadFileForm
from .watcher import start_watching
from .models import ScanLog

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import security as sc

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'media')

watch_thread = None
is_watching = False

def index(request):
    global watch_thread, is_watching
    result = None
    form = UploadFileForm()

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'scan':
            if request.FILES.get('file'):
                form = UploadFileForm(request.POST, request.FILES)
                if form.is_valid():
                    api_key = form.cleaned_data['api_key']
                    uploaded_file = request.FILES['file']

                    os.makedirs(UPLOAD_DIR, exist_ok=True)
                    file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
                    with open(file_path, 'wb') as f:
                        for chunk in uploaded_file.chunks():
                            f.write(chunk)

                    sc._SAVED_API_KEY = api_key
                    is_safe = sc.check_security(file_path)

                    status = 'clean' if is_safe else 'malicious'

                    # DB에 스캔 기록 저장
                    ScanLog.objects.create(
                        filename=uploaded_file.name,
                        status=status,
                        detections=0,
                        total=0
                    )

                    result = {
                        'filename': uploaded_file.name,
                        'status': '✅ 안전' if is_safe else '🚨 악성 — 격리 완료',
                        'is_safe': is_safe
                    }

                    if not is_safe:
                        sc.quarantine(file_path)

        elif action == 'watch':
            api_key = request.POST.get('api_key', '')
            if not is_watching and api_key:
                watch_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'watch_folder')
                watch_thread = threading.Thread(
                    target=start_watching, args=(watch_dir, api_key), daemon=True
                )
                watch_thread.start()
                is_watching = True
                result = {'watch': True, 'watch_dir': watch_dir}

    # 스캔 히스토리 최근 10개
    logs = ScanLog.objects.order_by('-scanned_at')[:10]

    return render(request, 'scanner/index.html', {
        'form': form,
        'result': result,
        'is_watching': is_watching,
        'logs': logs
    })