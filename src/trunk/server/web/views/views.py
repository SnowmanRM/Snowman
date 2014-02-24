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
	return redirect('web.views.views.rules')


def rules(request):
	"""This method is loaded when the /rules/ url is called.
	
	Which is a list of all RuleRevision objects, paginated by the limit set in pagelength.
	
	The method gets a count of the number of objects in the database and then gets all the objects. 
	If it doesnt find anything, it raises a 404 error.
	If it finds objects, it then sends everything to the template rules/rules.tpl through the render method. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	context['pagenr'] = 1
	context['pagelength'] = pagelength
	context['ishidden'] = False
	
	try:
		context['itemcount'] = RuleRevision.objects.count()
		context['rule_list'] = RuleRevision.objects.all()[:pagelength]
	except RuleRevision.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	
	return render(request, 'rules/rules.tpl', context)


"""TODO:"""
	
def ruleSet(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.views.rules')

def ruleSetBySensorActive(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.views.rules')

def ruleSetBySensorNew(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.views.rules')

def ruleclass(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.views.rules')

def update(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.views.rules')

def updates(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.views.rules')

def sensors(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.views.rules')

def tuningBySensor(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.views.rules')

def tuningByRule(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.views.rules')

def tuningBySensorName(request):
	"""This method temporary redirects to rules. 
	
	TODO: Make this."""
	return redirect('web.views.views.rules')


	
	
