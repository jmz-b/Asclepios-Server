# -*- coding: utf-8 -*-
# Generated by Django 1.11.24 on 2019-11-27 17:45
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ciphertext',
            name='data',
            field=models.CharField(max_length=300),
        ),
        migrations.AlterField(
            model_name='ciphertext',
            name='jsonId',
            field=models.CharField(max_length=300),
        ),
        migrations.AlterField(
            model_name='map',
            name='address',
            field=models.CharField(max_length=300),
        ),
        migrations.AlterField(
            model_name='map',
            name='location',
            field=models.CharField(max_length=300),
        ),
    ]
