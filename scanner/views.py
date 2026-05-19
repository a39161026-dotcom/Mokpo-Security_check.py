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

                    # [안전장치] 만약 입력된 API key에 경로 형태나 한글이 섞여있다면 걸러내기
                    if "manage.py" in api_key or "Users" in api_key:
                        result = {
                            'filename': uploaded_file.name,
                            'status': '🚨 올바르지 않은 API Key 형식입니다. 진짜 바이러스토탈 키를 입력해주세요.',
                            'is_safe': False
                        }
                        return render(request, 'scanner/index.html', {'form': form, 'folder_form': folder_form, 'result': result, 'logs': []})

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

                    # 데이터베이스 저장 시도 및 에러 출력(디버깅용)
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
                        print(f"❌ [DB 인덱스 에러 발생]: {db_error}")
                        try:
                            # session_id 없이 백업 저장 시도
                            ScanLog.objects.create(
                                file_name=uploaded_file.name,
                                status=status,
                                detections=0,
                                total_engines=75,
                                is_compressed=False,
                                saved_path=saved
                            )
                        except Exception as backup_error:
                            print(f"❌ [DB 백업 저장도 실패]: {backup_error}")

                    result = {
                        'filename': uploaded_file.name,
                        'status': '✅ 안전' if is_safe else '🚨 악성 — 격리 완료',
                        'is_safe': is_safe
                    }

                    if not is_safe:
                        sc.quarantine(file_path)

        # 다중 파일 스캔
        elif action == 'folder_scan':
            api_key = request.POST.get('api_key', '')
            uploaded_files = request.FILES.getlist('files')

            if "manage.py" in api_key or "Users" in api_key:
                 return render(request, 'scanner/index.html', {'form': form, 'folder_form': folder_form, 'result': {'status': '올바른 API Key를 쓰세요.'}, 'logs': []})

            if api_key and uploaded_files:
                sc._SAVED_API_KEY = api_key
                folder_results = []
                os.makedirs(UPLOAD_DIR, exist_ok=True)

                for uploaded_file in uploaded_files:
                    file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
                    with open(file_path, 'wb') as f:
                        for chunk in uploaded_file.chunks():
                            f.write(chunk)

                    is_safe = sc.check_security(file_path)
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
                        print(f"❌ [DB 폴더 에러 발생]: {db_error}")
                        try:
                            ScanLog.objects.create(
                                file_name=uploaded_file.name,
                                status=status,
                                detections=0,
                                total_engines=75,
                                is_compressed=False,
                                saved_path=file_path
                            )
                        except Exception as backup_error:
                            print(f"❌ [DB 폴더 백업 저장 실패]: {backup_error}")

                    folder_results.append({
                        'filename': uploaded_file.name,
                        'status': '✅ 안전' if is_safe else '🚨 악성',
                        'is_safe': is_safe
                    })

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

    # [수정] 세션 필터를 제거하고 데이터베이스에 있는 모든 스캔 기록을 최근 순으로 10개 가져옵니다.
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

def dashboard(request):
    # [수정] 대시보드도 세션 제한 없이 전체 스캔 로그의 통계를 보여주도록 변경합니다.
    try:
        logs = ScanLog.objects.all().order_by('-created_at')
        clean_count = logs.filter(status='clean').count()
        malicious_count = logs.filter(status='malicious').count()
    except Exception as dash_error:
        print(f"❌ [대시보드 에러]: {dash_error}")
        logs = []
        clean_count = 0
        malicious_count = 0
    return render(request, 'scanner/dashboard.html', {
        'logs': logs,
        'clean_count': clean_count,
        'malicious_count': malicious_count,
    })