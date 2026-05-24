"""
scanner/views.py
담당: 김성환 | 로그 조회 페이지 및 검색/필터 로직 처리
"""

from django.shortcuts import render
from .models import ScanLog

# ──────────────────────────────────────────────
# 공개 뷰 함수 (urls.py에서 연결)
# ──────────────────────────────────────────────
def log_dashboard(request):
    """
    [웹 페이지] 모든 스캔 로그를 가져오며, 검색 및 필터링 조건을 반영
    """
    # 1. 기본적으로 전체 로그 최신순 가져오기
    logs = ScanLog.objects.all()

    # 2. GET 요청으로부터 검색어와 필터값 가져오기
    search_query = request.GET.get('search', '').strip()
    status_filter = request.GET.get('status', '').strip()

    # 3. 파일명 검색 조건이 적용된 경우 (대소문자 구분 없음)
    if search_query:
        logs = logs.filter(file_name__icontains=search_query)

    # 4. 보안 상태 필터 조건이 적용된 경우
    if status_filter:
        logs = logs.filter(status=status_filter)

    # 5. 화면(Template)으로 보낼 데이터 묶기
    context = {
        'logs': logs,
        'search_query': search_query,
        'status_filter': status_filter,
    }
    
    return render(request, 'scanner/dashboard.html', context)
