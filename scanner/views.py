import os
import sys
import threading

from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from .forms import UploadFileForm, FolderScanForm
from .watcher import start_watching
from .models import ScanLog

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import security as sc
import feature_extractor as fe
import report_generator as rg

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

                    # ── VT 응답 오기 전, 파일 자체 특징으로 사전 위험도 계산 ──
                    try:
                        pre_analysis = fe.analyze_file(file_path)
                    except Exception as fe_error:
                        print(f"⚠️ 사전 분석 실패: {fe_error}")
                        pre_analysis = {"file_size": 0, "file_extension": "", "entropy": None, "risk_score": None}

                    try:
                        scan_result = sc.check_security(file_path)
                    except Exception as sc_error:
                        print(f"⚠️ security.py 검사 중 예외 발생: {sc_error}")
                        scan_result = {"is_safe": False, "status": "error", "detections": 0, "total": 0}

                    is_safe = scan_result["is_safe"]
                    status = 'clean' if is_safe else scan_result["status"]
                    if status not in dict(ScanLog.STATUS_CHOICES):
                        status = 'malicious'
                    saved = file_path if is_safe else os.path.join(
                        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'quarantine', uploaded_file.name
                    )

                    try:
                        ScanLog.objects.create(
                            session_id=session_id,
                            file_name=uploaded_file.name,
                            status=status,
                            detections=scan_result["detections"],
                            total_engines=scan_result["total"],
                            is_compressed=False,
                            saved_path=saved,
                            file_size=pre_analysis["file_size"],
                            file_extension=pre_analysis["file_extension"],
                            entropy=pre_analysis["entropy"],
                            risk_score=pre_analysis["risk_score"],
                            sha256=scan_result.get("sha256", ""),
                            engine_results=scan_result.get("engines", []),
                        )
                    except Exception as db_error:
                        print(f"❌ [DB 에러]: {db_error}")

                    result = {
                        'filename': uploaded_file.name,
                        'status': '✅ 안전' if is_safe else '🚨 악성 또는 스캔 오류',
                        'is_safe': is_safe,
                        'risk_score': pre_analysis["risk_score"],
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
                        pre_analysis = fe.analyze_file(file_path)
                    except Exception as fe_error:
                        print(f"⚠️ 사전 분석 실패: {fe_error}")
                        pre_analysis = {"file_size": 0, "file_extension": "", "entropy": None, "risk_score": None}

                    try:
                        scan_result = sc.check_security(file_path)
                    except Exception as sc_error:
                        print(f"⚠️ 폴더 검사 중 예외 발생: {sc_error}")
                        scan_result = {"is_safe": False, "status": "error", "detections": 0, "total": 0}

                    is_safe = scan_result["is_safe"]
                    status = 'clean' if is_safe else scan_result["status"]
                    if status not in dict(ScanLog.STATUS_CHOICES):
                        status = 'malicious'

                    try:
                        ScanLog.objects.create(
                            session_id=session_id,
                            file_name=uploaded_file.name,
                            status=status,
                            detections=scan_result["detections"],
                            total_engines=scan_result["total"],
                            is_compressed=False,
                            saved_path=file_path,
                            file_size=pre_analysis["file_size"],
                            file_extension=pre_analysis["file_extension"],
                            entropy=pre_analysis["entropy"],
                            risk_score=pre_analysis["risk_score"],
                            sha256=scan_result.get("sha256", ""),
                            engine_results=scan_result.get("engines", []),
                        )
                    except Exception as db_error:
                        print(f"❌ [DB 폴더 에러]: {db_error}")

                    folder_results.append({
                        'filename': uploaded_file.name,
                        'status': '✅ 안전' if is_safe else '🚨 악성/오류',
                        'is_safe': is_safe,
                        'risk_score': pre_analysis["risk_score"],
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
    import json
    from datetime import timedelta
    from django.utils import timezone
    from django.db.models import Avg, Count
    from django.db.models.functions import TruncDate

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
        suspicious_count = logs.filter(status='suspicious').count()

        avg_risk = ScanLog.objects.filter(risk_score__isnull=False).aggregate(avg=Avg('risk_score'))['avg']
        avg_risk = round(avg_risk, 1) if avg_risk is not None else None

        # 최근 14일 일별 추세 (전체 로그 기준, 검색/필터와 무관하게 큰 그림 보여줌)
        since = timezone.now() - timedelta(days=14)
        daily = (
            ScanLog.objects.filter(created_at__gte=since)
            .annotate(day=TruncDate('created_at'))
            .values('day', 'status')
            .annotate(count=Count('id'))
            .order_by('day')
        )
        trend_map = {}
        for row in daily:
            day_str = row['day'].strftime('%m-%d')
            trend_map.setdefault(day_str, {'clean': 0, 'malicious': 0, 'suspicious': 0, 'unknown': 0})
            trend_map[day_str][row['status']] = row['count']

        trend_labels = list(trend_map.keys())
        trend_clean = [trend_map[d]['clean'] for d in trend_labels]
        trend_malicious = [trend_map[d]['malicious'] for d in trend_labels]
        trend_suspicious = [trend_map[d]['suspicious'] for d in trend_labels]

    except Exception as dash_error:
        print(f"❌ [대시보드 에러]: {dash_error}")
        logs = []
        clean_count = 0
        malicious_count = 0
        suspicious_count = 0
        avg_risk = None
        search_query = ''
        status_filter = ''
        trend_labels, trend_clean, trend_malicious, trend_suspicious = [], [], [], []

    return render(request, 'scanner/dashboard.html', {
        'logs': logs,
        'clean_count': clean_count,
        'malicious_count': malicious_count,
        'suspicious_count': suspicious_count,
        'avg_risk': avg_risk,
        'search_query': search_query,
        'status_filter': status_filter,
        'trend_labels_json': json.dumps(trend_labels),
        'trend_clean_json': json.dumps(trend_clean),
        'trend_malicious_json': json.dumps(trend_malicious),
        'trend_suspicious_json': json.dumps(trend_suspicious),
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
    safe_engines = max(log.total_engines - log.detections, 0)
    return render(request, 'scanner/scan_detail.html', {'log': log, 'safe_engines': safe_engines})


@login_required
def scan_report_pdf(request, pk):
    try:
        log = ScanLog.objects.get(pk=pk)
    except ScanLog.DoesNotExist:
        return redirect('dashboard')

    try:
        buffer = rg.generate_scan_report_pdf(log)
    except Exception as pdf_error:
        print(f"❌ [PDF 생성 에러]: {pdf_error}")
        return redirect('scan_detail', pk=pk)

    response = HttpResponse(buffer.read(), content_type='application/pdf')
    safe_name = "".join(c for c in log.file_name if c.isalnum() or c in "._-") or "scan"
    response['Content-Disposition'] = f'attachment; filename="report_{pk}_{safe_name}.pdf"'
    return response