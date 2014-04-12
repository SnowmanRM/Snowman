"""
This script file serves to answer asymmetrical url requests from AJAX calls on the various pages.

"""


from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision
from web.utilities import UserSettings
import logging

"""TODO:"""

def getRulePageByClass(request):
    """This method temporary redirects to rules. 
    
    TODO: Make this."""
    return redirect('wweb.views.ruleviews.index')

def getRuleSet(request):
    """This method temporary redirects to rules. 
    
    TODO: Make this."""
    return redirect('web.views.ruleviews.index')

def getSensor(request):
    """This method temporary redirects to rules. 
    
    TODO: Make this."""
    return redirect('web.views.ruleviews.index')

def postSensorUpdate(request):
    """This method temporary redirects to rules. 
    
    TODO: Make this."""
    return redirect('web.views.ruleviews.index')

def getSensorUpdatesBySensorName(request):
    """This method temporary redirects to rules. 
    
    TODO: Make this."""
    return redirect('web.views.ruleviews.index')