import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0005_scanlog_engine_results_scanlog_sha256'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='scanlog',
            name='user',
            field=models.ForeignKey(blank=True, help_text='이 스캔을 실행한 사용자(기존 기록은 비어있을 수 있음)', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='scan_logs', to=settings.AUTH_USER_MODEL),
        ),
    ]
