import os
import sys
import time
import re

from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from django.core.cache import cache
from .forms import UploadFileForm, FolderScanForm
from .models import ScanLog

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import security as sc
import feature_extractor as fe
import report_generator as rg

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'media')

SHARED_KEY_COOLDOWN = 16
SHARED_KEY_CACHE_KEY = 'vt_shared_last_call'
VT_KEY_PATTERN = re.compile(r'^[0-9a-fA-F]{64}$')


def get_effective_api_key(user_provided_key):
    user_provided_key = (user_provided_key or '').strip()
    if user_provided_key and VT_KEY_PATTERN.match(user_provided_key):
        return user_provided_key, True
    return os.environ.get('VT_API_KEY', '').strip(), False


def check_shared_throttle():
    last = cache.get(SHARED_KEY_CACHE_KEY)
    now = time.time()
    if last and (now - last) < SHARED_KEY_COOLDOWN:
        wait = int(SHARED_KEY_COOLDOWN - (now - last)) + 1
        return f"공용 API 키 보호를 위해 {wait}초 후 다시 시도해주세요. (급하면 고급설정에서 본인 API 키 입력)"
    cache.set(SHARED_KEY_CACHE_KEY, now, timeout=SHARED_KEY_COOLDOWN + 10)
    return None


@login_required
def index(request):
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
                    uploaded_file = request.FILES['file']
                    api_key, is_own_key = get_effective_api_key(form.cleaned_data.get('api_key'))

                    throttle_msg = None if is_own_key else check_shared_throttle()

                    if not api_key:
                        result = {
                            'filename': uploaded_file.name,
                            'status': '서버에 API 키가 설정되어 있지 않습니다. 관리자에게 문의해주세요.',
                            'is_safe': None,
                            'risk_score': None,
                        }
                    elif throttle_msg:
                        result = {
                            'filename': uploaded_file.name,
                            'status': throttle_msg,
                            'is_safe': None,
                            'risk_score': None,
                        }
                    else:
                        os.makedirs(UPLOAD_DIR, exist_ok=True)
                        file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
                        with open(file_path, 'wb') as f:
                            for chunk in uploaded_file.chunks():
                                f.write(chunk)

                        sc._SAVED_API_KEY = api_key

                        try:
                            pre_analysis = fe.analyze_file(file_path)
                        except Exception as fe_error:
                            print(f"WARN pre_analysis failed: {fe_error}")
                            pre_analysis = {"file_size": 0, "file_extension": "", "entropy": None, "risk_score": None}

                        try:
                            scan_result = sc.check_security(file_path)
                        except Exception as sc_error:
                            print(f"WARN check_security failed: {sc_error}")
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
                            print(f"DB ERROR: {db_error}")

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
            form_data = FolderScanForm(request.POST)
            api_key, is_own_key = get_effective_api_key(request.POST.get('api_key', ''))
            uploaded_files = request.FILES.getlist('files')

            throttle_msg = None if is_own_key else check_shared_throttle()

            if not uploaded_files:
                pass
            elif not api_key:
                folder_results = [{'filename': '-', 'status': '서버에 API 키가 설정되어 있지 않습니다.', 'is_safe': None, 'risk_score': None}]
            elif throttle_msg:
                folder_results = [{'filename': '-', 'status': throttle_msg, 'is_safe': None, 'risk_score': None}]
            else:
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
                        print(f"WARN pre_analysis failed: {fe_error}")
                        pre_analysis = {"file_size": 0, "file_extension": "", "entropy": None, "risk_score": None}

                    try:
                        scan_result = sc.check_security(file_path)
                    except Exception as sc_error:
                        print(f"WARN folder check_security failed: {sc_error}")
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
                        print(f"DB folder ERROR: {db_error}")

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

    try:
        logs = ScanLog.objects.all().order_by('-created_at')[:10]
    except Exception as log_error:
        print(f"LOG ERROR: {log_error}")
        logs = []

    return render(request, 'scanner/index.html', {
        'form': form,
        'folder_form': folder_form,
        'result': result,
        'folder_results': folder_results,
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
        print(f"DASHBOARD ERROR: {dash_error}")
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
        print(f"PDF ERROR: {pdf_error}")
        return redirect('scan_detail', pk=pk)

    response = HttpResponse(buffer.read(), content_type='application/pdf')
    safe_name = "".join(c for c in log.file_name if c.isalnum() or c in "._-") or "scan"
    response['Content-Disposition'] = f'attachment; filename="report_{pk}_{safe_name}.pdf"'
    return response
