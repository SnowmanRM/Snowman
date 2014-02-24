"""
This script file serves to answer url requests for all the main pages in the page structure.

"""

from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision
from update.models import Source
from web.utilities import UserSettings
import logging

def index(request):
	data = {}
	
	data['sources'] = Source.objects.all()
	
	return render(request, "update/index.tpl", data)
