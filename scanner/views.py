import os
import sys
import threading

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from .forms import UploadFileForm, FolderScanForm
from .watcher import start_watching
from .models import ScanLog

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import security as sc

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'media')

watch_thread = None
is_watching = False


@login_required
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

                    try:
                        is_safe = sc.check_security(file_path)
                        if is_safe is None:
                            is_safe = False
                    except Exception as sc_error:
                        print(f"⚠️ security.py 검사 중 예외 발생: {sc_error}")
                        is_safe = False

                    status = 'clean' if is_safe else 'malicious'
                    saved = file_path if is_safe else os.path.join(
                        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'quarantine', uploaded_file.name
                    )

                    try:
                        ScanLog.objects.create(
                            session_id=session_id,
                            file_name=uploaded_file.name,
                            status=status,
                            detections=0,
                            total_engines=75,
                            is_compressed=False,
                            saved_path=saved
                        )
                    except Exception as db_error:
                        print(f"❌ [DB 에러]: {db_error}")

                    result = {
                        'filename': uploaded_file.name,
                        'status': '✅ 안전' if is_safe else '🚨 악성 또는 스캔 오류',
                        'is_safe': is_safe
                    }

                    if not is_safe:
                        try:
                            sc.quarantine(file_path)
                        except Exception:
                            pass

        elif action == 'folder_scan':
            api_key = request.POST.get('api_key', '')
            uploaded_files = request.FILES.getlist('files')

            if api_key and uploaded_files:
                sc._SAVED_API_KEY = api_key
                folder_results = []
                os.makedirs(UPLOAD_DIR, exist_ok=True)

                for uploaded_file in uploaded_files:
                    file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
                    with open(file_path, 'wb') as f:
                        for chunk in uploaded_file.chunks():
                            f.write(chunk)

                    try:
                        is_safe = sc.check_security(file_path)
                        if is_safe is None:
                            is_safe = False
                    except Exception as sc_error:
                        print(f"⚠️ 폴더 검사 중 예외 발생: {sc_error}")
                        is_safe = False

                    status = 'clean' if is_safe else 'malicious'

                    try:
                        ScanLog.objects.create(
                            session_id=session_id,
                            file_name=uploaded_file.name,
                            status=status,
                            detections=0,
                            total_engines=75,
                            is_compressed=False,
                            saved_path=file_path
                        )
                    except Exception as db_error:
                        print(f"❌ [DB 폴더 에러]: {db_error}")

                    folder_results.append({
                        'filename': uploaded_file.name,
                        'status': '✅ 안전' if is_safe else '🚨 악성/오류',
                        'is_safe': is_safe
                    })

                    if not is_safe:
                        try:
                            sc.quarantine(file_path)
                        except Exception:
                            pass

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

    try:
        logs = ScanLog.objects.all().order_by('-created_at')[:10]
    except Exception as log_error:
        print(f"❌ [로그 불러오기 에러]: {log_error}")
        logs = []

    return render(request, 'scanner/index.html', {
        'form': form,
        'folder_form': folder_form,
        'result': result,
        'folder_results': folder_results,
        'is_watching': is_watching,
        'logs': logs
    })


@login_required
def dashboard(request):
    try:
        logs = ScanLog.objects.all()

        search_query = request.GET.get('search', '').strip()
        status_filter = request.GET.get('status', '').strip()

        if search_query:
            logs = logs.filter(file_name__icontains=search_query)

        if status_filter:
            logs = logs.filter(status=status_filter)

        logs = logs.order_by('-created_at')
        clean_count = logs.filter(status='clean').count()
        malicious_count = logs.filter(status='malicious').count()
    except Exception as dash_error:
        print(f"❌ [대시보드 에러]: {dash_error}")
        logs = []
        clean_count = 0
        malicious_count = 0
        search_query = ''
        status_filter = ''

    return render(request, 'scanner/dashboard.html', {
        'logs': logs,
        'clean_count': clean_count,
        'malicious_count': malicious_count,
        'search_query': search_query,
        'status_filter': status_filter,
    })


def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('index')
    else:
        form = UserCreationForm()
    return render(request, 'registration/register.html', {'form': form})


@login_required
def scan_detail(request, pk):
    try:
        log = ScanLog.objects.get(pk=pk)
    except ScanLog.DoesNotExist:
        return redirect('dashboard')
    return render(request, 'scanner/scan_detail.html', {'log': log})