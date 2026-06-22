import csv
import os
import sys
import time
import re
from datetime import timedelta

from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils import timezone
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

CACHE_FRESH_DAYS = 7

ADMIN_NOTIFY_EMAIL = 'a39161016@gmail.com'


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


def get_cached_scan(sha256_hash):
    if not sha256_hash:
        return None
    cutoff = timezone.now() - timedelta(days=CACHE_FRESH_DAYS)
    return (
        ScanLog.objects.filter(sha256=sha256_hash, created_at__gte=cutoff)
        .exclude(sha256='')
        .order_by('-created_at')
        .first()
    )


def perform_scan(file_path, form_api_key):
    sha256 = sc.calculate_sha256(file_path)
    cached = get_cached_scan(sha256)
    if cached:
        scan_result = {
            "is_safe": cached.status in ("clean", "unknown"),
            "status": cached.status,
            "detections": cached.detections,
            "total": cached.total_engines,
            "sha256": cached.sha256,
            "engines": cached.engine_results,
        }
        return scan_result, None, True

    api_key, is_own_key = get_effective_api_key(form_api_key)
    if not api_key:
        return None, "서버에 API 키가 설정되어 있지 않습니다. 관리자에게 문의해주세요.", False

    throttle_msg = None if is_own_key else check_shared_throttle()
    if throttle_msg:
        return None, throttle_msg, False

    sc._SAVED_API_KEY = api_key
    try:
        scan_result = sc.check_security(file_path)
    except Exception as sc_error:
        print(f"WARN check_security failed: {sc_error}")
        scan_result = {"is_safe": False, "status": "error", "detections": 0, "total": 0}
    return scan_result, None, False


def notify_malicious_detected(file_name, status, detections, total, requested_by):
    try:
        send_mail(
            subject=f"[보안 스캐너] 악성 파일 탐지: {file_name}",
            message=(
                f"파일명: {file_name}\n"
                f"판정: {status}\n"
                f"탐지: {detections} / {total} 엔진\n"
                f"요청 사용자: {requested_by}\n"
                f"확인 시각: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            ),
            from_email=ADMIN_NOTIFY_EMAIL,
            recipient_list=[ADMIN_NOTIFY_EMAIL],
            fail_silently=False,
        )
    except Exception as mail_error:
        print(f"MAIL ERROR: {mail_error}")


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

                    os.makedirs(UPLOAD_DIR, exist_ok=True)
                    file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
                    with open(file_path, 'wb') as f:
                        for chunk in uploaded_file.chunks():
                            f.write(chunk)

                    try:
                        pre_analysis = fe.analyze_file(file_path)
                    except Exception as fe_error:
                        print(f"WARN pre_analysis failed: {fe_error}")
                        pre_analysis = {"file_size": 0, "file_extension": "", "entropy": None, "risk_score": None}

                    scan_result, blocked_msg, from_cache = perform_scan(file_path, form.cleaned_data.get('api_key'))

                    if blocked_msg:
                        result = {
                            'filename': uploaded_file.name,
                            'status': blocked_msg,
                            'is_safe': None,
                            'risk_score': None,
                        }
                    else:
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
                                user=request.user,
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

                        if not is_safe and not from_cache:
                            notify_malicious_detected(
                                uploaded_file.name, status,
                                scan_result["detections"], scan_result["total"],
                                request.user.username,
                            )

                        status_text = '✅ 안전' if is_safe else '🚨 악성 또는 스캔 오류'
                        if from_cache:
                            status_text += ' (🗄️ 최근 검사 결과 재사용)'

                        result = {
                            'filename': uploaded_file.name,
                            'status': status_text,
                            'is_safe': is_safe,
                            'risk_score': pre_analysis["risk_score"],
                        }

                        if not is_safe:
                            try:
                                sc.quarantine(file_path)
                            except Exception:
                                pass

        elif action == 'folder_scan':
            uploaded_files = request.FILES.getlist('files')
            form_api_key = request.POST.get('api_key', '')

            if uploaded_files:
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

                    scan_result, blocked_msg, from_cache = perform_scan(file_path, form_api_key)

                    if blocked_msg:
                        folder_results.append({
                            'filename': uploaded_file.name,
                            'status': blocked_msg,
                            'is_safe': None,
                            'risk_score': None,
                        })
                        continue

                    is_safe = scan_result["is_safe"]
                    status = 'clean' if is_safe else scan_result["status"]
                    if status not in dict(ScanLog.STATUS_CHOICES):
                        status = 'malicious'

                    try:
                        ScanLog.objects.create(
                            user=request.user,
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

                    if not is_safe and not from_cache:
                        notify_malicious_detected(
                            uploaded_file.name, status,
                            scan_result["detections"], scan_result["total"],
                            request.user.username,
                        )

                    status_text = '✅ 안전' if is_safe else '🚨 악성/오류'
                    if from_cache:
                        status_text += ' (🗄️ 캐시)'

                    folder_results.append({
                        'filename': uploaded_file.name,
                        'status': status_text,
                        'is_safe': is_safe,
                        'risk_score': pre_analysis["risk_score"],
                    })

                    if not is_safe:
                        try:
                            sc.quarantine(file_path)
                        except Exception:
                            pass

    try:
        logs = ScanLog.objects.filter(user=request.user).order_by('-created_at')[:10]
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
    from django.db.models import Avg, Count
    from django.db.models.functions import TruncDate

    try:
        logs = ScanLog.objects.filter(user=request.user)

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

        avg_risk = ScanLog.objects.filter(user=request.user, risk_score__isnull=False).aggregate(avg=Avg('risk_score'))['avg']
        avg_risk = round(avg_risk, 1) if avg_risk is not None else None

        since = timezone.now() - timedelta(days=14)
        daily = (
            ScanLog.objects.filter(user=request.user, created_at__gte=since)
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


@login_required
def export_scan_logs_csv(request):
    logs = ScanLog.objects.filter(user=request.user).order_by('-created_at')

    response = HttpResponse(content_type='text/csv; charset=utf-8-sig')
    response['Content-Disposition'] = 'attachment; filename="scan_logs.csv"'

    writer = csv.writer(response)
    writer.writerow(['스캔일시', '파일명', '상태', '탐지엔진', '전체엔진', 'AI위험도', 'SHA256'])
    for log in logs:
        writer.writerow([
            log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            log.file_name,
            log.get_status_display(),
            log.detections,
            log.total_engines,
            log.risk_score if log.risk_score is not None else '',
            log.sha256,
        ])
    return response


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
        log = ScanLog.objects.get(pk=pk, user=request.user)
    except ScanLog.DoesNotExist:
        return redirect('dashboard')
    safe_engines = max(log.total_engines - log.detections, 0)
    return render(request, 'scanner/scan_detail.html', {'log': log, 'safe_engines': safe_engines})


@login_required
def scan_report_pdf(request, pk):
    try:
        log = ScanLog.objects.get(pk=pk, user=request.user)
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
