from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision, Sensor, RuleSet
from web.utilities import UserSettings
import logging

def index(request):
	"""This method does something."""
	
	logger = logging.getLogger(__name__)
	
	# Spool up context.
	context = {}
	
	# Get pagelength from the utility class.
	#pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	# This is always page nr 1.
	#context['pagenr'] = 1
	
	# We want pagelength with us in the template.
	#context['pagelength'] = pagelength
	
	# The first page isnt hidden.
	#context['ishidden'] = False
	
	try:
		# Get the current sensor count, but we want it in a negative value.
		context['sensorcount'] =  Sensor.objects.count()
		context['sensorcount'] = -context['sensorcount']
		
		# We need to know how many rules there are total.
		context['itemcount'] = RuleSet.objects.count()
		# Get all rules, but limited by the set pagelength.
		context['ruleset_list'] = RuleSet.objects.all()

	except RuleSet.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	
	return render(request, 'ruleset/ruleSet.tpl', context)