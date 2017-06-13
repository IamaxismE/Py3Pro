#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'Wz'

from django.db import models


# Create your models here.

class Assets(models.Model):
    idc = models.CharField(max_length=200, null=True, default='wuxi')
    rank = models.CharField(max_length=200, null=True)
    hostname = models.CharField(max_length=200, null=True)
    ipaddr = models.CharField(max_length=200, null=True)
    macaddr = models.CharField(max_length=200, null=True)
    cpu = models.CharField(max_length=200, null=True)
    mem = models.CharField(max_length=200, null=True)
    disk = models.CharField(max_length=200, null=True)
    sn = models.CharField(max_length=100, null=True)
    remarks = models.TextField(null=True)
    created_on = models.DateTimeField(auto_now_add=True)
