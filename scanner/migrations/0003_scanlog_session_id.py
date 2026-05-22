from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0002_rename_scanned_at_scanlog_created_at_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanlog',
            name='session_id',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]