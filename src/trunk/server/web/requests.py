"""
This script file serves to answer asymmetrical url requests from AJAX calls on the various pages.

"""


from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision
from web.utilities import UserSettings
import logging


def getRulePage(request, pagenr):
    """This method is loaded when the /rules/page/<int>/ url is called.
    
    It is used to answer dynamic calls for more pages in the paginated list of RuleRevision objects in /rules/.
    
    The method takes an argument pagenr, which it uses to calculate the minrange and maxrange of objects it needs to get, with the pagelength factored in. 
    If it doesnt find anything, it raises a 404 error.
    If it finds objects, it then sends everything to the template rules/rulepage.tpl through the render method. """
    
    logger = logging.getLogger(__name__)
    
    context = {}
    
    pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
    
    context['pagenr'] = pagenr
    context['pagelength'] = pagelength
    context['ishidden'] = True
    
    minrange = pagelength * int(pagenr)
    
    maxrange = int(minrange) + pagelength
    
    try:
        context['itemcount'] = RuleRevision.objects.count()
        context['rule_list'] = RuleRevision.objects.all()[minrange:maxrange]
    except RuleRevision.DoesNotExist:
        logger.warning("Page request /rules/page/"+str(pagenr)+" could not be resolved, objects in range "+str(minrange)+" - "+str(maxrange)+"not found.")
        raise Http404
    
    return render(request, 'rules/rulepage.tpl', context)

"""TODO:"""

def getRulePageByClass(request):
    """This method temporary redirects to rules. 
    
    TODO: Make this."""
    return redirect('web.views.rules')

def getRuleSet(request):
    """This method temporary redirects to rules. 
    
    TODO: Make this."""
    return redirect('web.views.rules')

def getSensor(request):
    """This method temporary redirects to rules. 
    
    TODO: Make this."""
    return redirect('web.views.rules')

def postSensorUpdate(request):
    """This method temporary redirects to rules. 
    
    TODO: Make this."""
    return redirect('web.views.rules')

def getSensorUpdatesBySensorName(request):
    """This method temporary redirects to rules. 
    
    TODO: Make this."""
    return redirect('web.views.rules')