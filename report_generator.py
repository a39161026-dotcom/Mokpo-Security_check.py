"""
report_generator.py
ScanLog 한 건을 받아서 PDF 보안 스캔 리포트를 생성하는 모듈.
한글 출력을 위해 reportlab 내장 CID 폰트(HYGothic-Medium / HYSMyeongJo-Medium)를 사용 —
별도 TTF 파일을 서버에 올릴 필요 없이 한글이 정상 출력됨.
"""

import io
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

# ── 한글 폰트 직접 임베드 (나눔고딕) — 어떤 PDF 뷰어에서 열어도 깨지지 않음 ──
_FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fonts')
pdfmetrics.registerFont(TTFont('NanumGothic', os.path.join(_FONT_DIR, 'NanumGothic.ttf')))
pdfmetrics.registerFont(TTFont('NanumGothic-Bold', os.path.join(_FONT_DIR, 'NanumGothicBold.ttf')))

FONT_BOLD = 'NanumGothic-Bold'
FONT_REGULAR = 'NanumGothic'

STATUS_LABEL = {
    'clean': '안전 (Clean)',
    'malicious': '악성 (Malicious)',
    'suspicious': '의심 (Suspicious)',
    'unknown': '미등록 (Unknown)',
}
STATUS_COLOR = {
    'clean': colors.HexColor('#2e7d32'),
    'malicious': colors.HexColor('#c62828'),
    'suspicious': colors.HexColor('#ef6c00'),
    'unknown': colors.HexColor('#757575'),
}


def _styles():
    base = getSampleStyleSheet()
    return {
        'title': ParagraphStyle('title', parent=base['Title'], fontName=FONT_BOLD, fontSize=20, spaceAfter=4),
        'subtitle': ParagraphStyle('subtitle', parent=base['Normal'], fontName=FONT_REGULAR, fontSize=10,
                                    textColor=colors.grey, spaceAfter=14),
        'heading': ParagraphStyle('heading', parent=base['Heading2'], fontName=FONT_BOLD, fontSize=13,
                                   textColor=colors.HexColor('#0A9396'), spaceBefore=14, spaceAfter=8),
        'body': ParagraphStyle('body', parent=base['Normal'], fontName=FONT_REGULAR, fontSize=10, leading=15),
        'small': ParagraphStyle('small', parent=base['Normal'], fontName=FONT_REGULAR, fontSize=8,
                                 textColor=colors.grey),
    }


def generate_scan_report_pdf(log) -> io.BytesIO:
    """ScanLog 객체 하나를 받아서 PDF 바이트 스트림을 반환."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=20 * mm, bottomMargin=20 * mm, leftMargin=20 * mm, rightMargin=20 * mm,
    )
    s = _styles()
    story = []

    # ── 헤더 ──
    story.append(Paragraph("🛡️ 파일 보안 스캔 리포트", s['title']))
    story.append(Paragraph(
        f"생성 일시: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · 국립목포대학교 파일 보안 스캐너",
        s['subtitle']
    ))
    story.append(HRFlowable(width="100%", color=colors.HexColor('#0A9396'), thickness=1.2))
    story.append(Spacer(1, 10))

    # ── 파일 기본 정보 ──
    story.append(Paragraph("파일 정보", s['heading']))
    status_label = STATUS_LABEL.get(log.status, log.status)
    info_rows = [
        ["파일명", log.file_name],
        ["SHA-256", log.sha256 or "정보 없음"],
        ["스캔 일시", log.created_at.strftime('%Y-%m-%d %H:%M:%S') if log.created_at else "-"],
        ["파일 크기", f"{log.file_size:,} bytes" if log.file_size else "-"],
        ["확장자", log.file_extension or "-"],
        ["엔트로피", f"{log.entropy}" if log.entropy is not None else "-"],
    ]
    info_table = Table(info_rows, colWidths=[35 * mm, 125 * mm])
    info_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), FONT_REGULAR),
        ('FONTNAME', (0, 0), (0, -1), FONT_BOLD),
        ('FONTSIZE', (0, 0), (-1, -1), 9.5),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#0A9396')),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -2), 0.4, colors.HexColor('#e0e0e0')),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 14))

    # ── 판정 결과 ──
    story.append(Paragraph("종합 판정", s['heading']))
    verdict_style = ParagraphStyle(
        'verdict', fontName=FONT_BOLD, fontSize=16,
        textColor=STATUS_COLOR.get(log.status, colors.black),
    )
    story.append(Paragraph(status_label, verdict_style))
    story.append(Spacer(1, 6))

    if log.risk_score is not None:
        story.append(Paragraph(
            f"🤖 AI 사전 위험도 점수: <b>{log.risk_score} / 100</b> "
            f"(VirusTotal 응답 전, 파일 자체 특징 기반 사전 예측치)",
            s['body']
        ))
        story.append(Spacer(1, 6))

    safe_engines = max(log.total_engines - log.detections, 0)
    stat_rows = [["전체 엔진", "탐지 엔진", "안전 엔진"], [str(log.total_engines), str(log.detections), str(safe_engines)]]
    stat_table = Table(stat_rows, colWidths=[53.3 * mm] * 3)
    stat_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
        ('FONTNAME', (0, 1), (-1, 1), FONT_BOLD),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTSIZE', (0, 1), (-1, 1), 16),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#132238')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('TEXTCOLOR', (1, 1), (1, 1), colors.HexColor('#c62828')),
        ('TEXTCOLOR', (2, 1), (2, 1), colors.HexColor('#2e7d32')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 14))

    # ── 엔진별 탐지 결과 ──
    story.append(Paragraph("엔진별 탐지 결과", s['heading']))
    engines = log.engine_results or []
    if engines:
        rows = [["보안 엔진", "판정", "탐지 결과"]]
        for e in engines:
            rows.append([e.get('engine', '-'), e.get('category', '-'), e.get('result', '-')])
        engine_table = Table(rows, colWidths=[45 * mm, 30 * mm, 85 * mm])
        engine_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTNAME', (0, 1), (-1, -1), FONT_REGULAR),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0A9396')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('TEXTCOLOR', (1, 1), (1, -1), colors.HexColor('#c62828')),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#cccccc')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7f7f7')]),
        ]))
        story.append(engine_table)
    else:
        msg = "모든 엔진에서 위협이 탐지되지 않았습니다." if log.status == 'clean' \
            else "엔진별 상세 결과가 없습니다 (VT 미등록 파일이거나 검사 오류)."
        story.append(Paragraph(msg, s['body']))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", color=colors.HexColor('#cccccc'), thickness=0.5))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "본 리포트는 VirusTotal API 검사 결과와 자체 AI 사전 위험도 예측 모델을 기반으로 자동 생성되었습니다.",
        s['small']
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer
