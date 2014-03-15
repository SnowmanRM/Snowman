from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision, Sensor, RuleSet, RuleClass
from web.utilities import UserSettings, ruleClassesToTemplate
import logging

def index(request):
	"""This method is called when the url /ruleclass/ is called.
	
	It fetches ruleset objects and sends them to the render.
	
	"""
	
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
		context['itemcount'] = RuleClass.objects.count()
		# Get all rules, but limited by the set pagelength.
		context['ruleclass_list'] = RuleClass.objects.all().order_by('classtype')

	except RuleSet.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleclass_list'] = ruleClassesToTemplate(context['ruleclass_list'])
	#return HttpResponse(ruleClassesToTemplate(context['ruleclass_list']))
	return render(request, 'ruleclass/ruleClass.tpl', context)