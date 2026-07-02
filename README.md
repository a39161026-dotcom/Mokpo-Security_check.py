# 🔐 세이프 스캐너 (Safe Scanner)

VirusTotal 70여 개 백신 엔진 기반 정밀 검사와 자체 개발 AI 사전 위험도 예측을 결합한 통합 파일 보안 스캐너입니다. 별도의 API 키 발급 없이 누구나 즉시 사용할 수 있습니다.

**🌐 배포 URL**: https://mokpo-security-check-py.onrender.com
**🎬 시연 영상**: https://youtu.be/TwSMa_w8pYk

---

## 📌 프로젝트 소개

출처가 불분명한 파일을 받았을 때 안전성을 확인할 방법이 마땅치 않은 경우가 많습니다. VirusTotal 사이트에 직접 올려서 검사할 수는 있지만, 결과를 한 번 보고 나면 그걸로 끝이라 검사 기록이 남지 않습니다.

이 프로젝트는 VirusTotal의 검사 능력을 그대로 활용하면서, 거기에 빠져 있는 부분(기록 관리, 사전 위험도 예측, 결과 문서화, 알림)을 채우는 것을 목표로 만들었습니다.

## 🛠 핵심 기능

- **AI 사전 위험도 예측**: VT 응답을 기다리지 않고, 파일 자체 특징(크기·확장자·엔트로피)으로 위험도를 룰 기반으로 즉시 산출
- **VirusTotal 70여 개 엔진 검사**: SHA-256 해시 기반 정밀 검사, 엔진별 상세 판정 결과 제공
- **캐싱 + 자동 재검사**: 동일 해시 파일은 7일간 캐시를 재사용해 VT 호출을 절감, 캐시 기간이 지나면 자동으로 재검사
- **검사 기록 대시보드**: 사용자별로 완전히 분리된 기록, 14일 추세 차트, 자주 발견된 위협 유형 Top5 통계
- **한글 PDF 리포트**: 엔진별 결과를 PDF로 1클릭 다운로드 (나눔고딕 폰트 임베드)
- **이메일 알림**: 악성 파일 탐지 시 가입한 이메일로 즉시 알림 발송 (SendGrid API)
- **CSV 내보내기 / 전체 기록 삭제**
- **다중 파일 동시 검사**
- **서버 공용 API 키 자동 적용**: 키 발급 없이 바로 사용 가능

## 💻 기술 스택

| 구분 | 내용 |
|---|---|
| 언어/프레임워크 | Python 3.12, Django 6.0 |
| 데이터베이스 | PostgreSQL (Neon), SQLite (로컬 개발) |
| 외부 API | VirusTotal API v3, SendGrid API |
| 주요 라이브러리 | requests, reportlab, Chart.js |
| 배포 | Render (Gunicorn + Whitenoise), GitHub 연동 자동 배포 |

## 🚀 로컬 실행 방법

```bash
git clone https://github.com/a39161026-dotcom/Mokpo-Security_check.py.git
cd Mokpo-Security_check.py
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

## 📄 라이선스

이 프로젝트는 [MIT License](LICENSE)를 따릅니다.

## 👤 제작자

이성헌 — 국립목포대학교 융합소프트웨어학과
2026 오픈소스 개발자대회 출품작 (팀: 세이프 스캐너)
