# Generated by Django 4.2.9 on 2025-03-19 09:55

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('photobooth', '0007_alter_photoboothuser_salutation'),
    ]

    operations = [
        migrations.AddField(
            model_name='photoboothuser',
            name='employer',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='employees', to='photobooth.photoboothuser'),
        ),
        migrations.AddField(
            model_name='photoboothuser',
            name='owner_code',
            field=models.CharField(blank=True, max_length=8, null=True, unique=True),
        ),
        migrations.AddField(
            model_name='photoboothuser',
            name='user_type',
            field=models.CharField(choices=[('owner', 'Owner'), ('employee', 'Employee')], default='owner', max_length=10),
        ),
    ]
