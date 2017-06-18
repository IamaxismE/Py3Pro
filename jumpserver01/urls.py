#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Auth: Wz

from django.conf.urls import url
from django.views.generic import View, ListView, TemplateView, DetailView, CreateView

urlpatterns = [
    url(r'^about/$', TemplateView.as_view(template_name="about.html")),
]
