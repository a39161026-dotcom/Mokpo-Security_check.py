import os
import sys
import threading

from django.shortcuts import render
from .forms import UploadFileForm, FolderScanForm
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
    folder_form = FolderScanForm()
    folder_results = None

    if not request.session.session_key:
        request.session.create()
    session_id = request.session.session_key

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
                    saved = file_path if is_safe else os.path.join(
                        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'quarantine', uploaded_file.name
                    )

                    ScanLog.objects.create(
                        session_id=session_id,
                        file_name=uploaded_file.name,
                        status=status,
                        detections=0,
                        total_engines=75,
                        is_compressed=False,
                        saved_path=saved
                    )

                    result = {
                        'filename': uploaded_file.name,
                        'status': '✅ 안전' if is_safe else '🚨 악성 — 격리 완료',
                        'is_safe': is_safe
                    }

                    if not is_safe:
                        sc.quarantine(file_path)

        elif action == 'folder_scan':
            folder_form = FolderScanForm(request.POST)
            if folder_form.is_valid():
                api_key = folder_form.cleaned_data['api_key']
                folder_path = folder_form.cleaned_data['folder_path'].strip()
                folder_path = os.path.normpath(folder_path)

                if os.path.exists(folder_path):
                    sc._SAVED_API_KEY = api_key
                    files = [
                        os.path.join(folder_path, f)
                        for f in os.listdir(folder_path)
                        if os.path.isfile(os.path.join(folder_path, f))
                    ]

                    folder_results = []
                    for file_path in files:
                        filename = os.path.basename(file_path)
                        is_safe = sc.check_security(file_path)
                        status = 'clean' if is_safe else 'malicious'

                        ScanLog.objects.create(
                            session_id=session_id,
                            file_name=filename,
                            status=status,
                            detections=0,
                            total_engines=75,
                            is_compressed=False,
                            saved_path=file_path
                        )

                        folder_results.append({
                            'filename': filename,
                            'status': '✅ 안전' if is_safe else '🚨 악성',
                            'is_safe': is_safe
                        })

                        if not is_safe:
                            sc.quarantine(file_path)
                else:
                    folder_results = [{'filename': '오류', 'status': '❌ 폴더를 찾을 수 없습니다', 'is_safe': False}]

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

    logs = ScanLog.objects.filter(session_id=session_id).order_by('-created_at')[:10]

    return render(request, 'scanner/index.html', {
        'form': form,
        'folder_form': folder_form,
        'result': result,
        'folder_results': folder_results,
        'is_watching': is_watching,
        'logs': logs
    })

def dashboard(request):
    if not request.session.session_key:
        request.session.create()
    session_id = request.session.session_key
    logs = ScanLog.objects.filter(session_id=session_id).order_by('-created_at')
    clean_count = logs.filter(status='clean').count()
    malicious_count = logs.filter(status='malicious').count()
    return render(request, 'scanner/dashboard.html', {
        'logs': logs,
        'clean_count': clean_count,
        'malicious_count': malicious_count,
    })