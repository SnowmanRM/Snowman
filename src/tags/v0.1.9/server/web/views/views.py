"""
This script file serves to answer url requests for all the main pages in the page structure.

"""

from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision
from web.utilities import UserSettings
import logging

def index(request):
	"""This method temporary redirects to rules. 
	
	TODO: Should be loading a front page."""
	return redirect('web.views.ruleviews.index')

"""TODO:"""

def ruleSetBySensorActive(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.ruleviews.index')

def ruleSetBySensorNew(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.ruleviews.index')

def ruleClass(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.ruleviews.index')

def update(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.ruleviews.index')

def updates(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.ruleviews.index')

def sensors(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.ruleviews.index')

def tuningBySensor(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.ruleviews.index')

def tuningByRule(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.ruleviews.index')

def tuningBySensorName(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.ruleviews.index')


	
	
