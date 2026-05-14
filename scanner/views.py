import os
import sys
import hashlib
import requests

from django.shortcuts import render
from .forms import UploadFileForm

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import security as sc

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'media')

def index(request):
    result = None

    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            api_key = form.cleaned_data['api_key']
            uploaded_file = request.FILES['file']

            # 파일 저장
            os.makedirs(UPLOAD_DIR, exist_ok=True)
            file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
            with open(file_path, 'wb') as f:
                for chunk in uploaded_file.chunks():
                    f.write(chunk)

            # API 키 설정 후 스캔
            sc._SAVED_API_KEY = api_key
            is_safe = sc.check_security(file_path)

            result = {
                'filename': uploaded_file.name,
                'status': '✅ 안전' if is_safe else '🚨 악성 — 격리 완료',
                'is_safe': is_safe
            }

            if not is_safe:
                sc.quarantine(file_path)

    else:
        form = UploadFileForm()

    return render(request, 'scanner/index.html', {'form': form, 'result': result})