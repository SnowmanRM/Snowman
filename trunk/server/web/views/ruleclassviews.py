from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from core.models import Rule, RuleRevision, Sensor, RuleSet, RuleClass
from web.utilities import UserSettings, ruleClassesToTemplate
import logging

@login_required
def index(request):
	"""This method is called when the url /ruleclass/ is called.
	
	It fetches ruleclass objects and sends them to the render.
	
	"""
	
	logger = logging.getLogger(__name__)
	
	# Spool up context.
	context = {}
	
	
	try:
		# We need to know how many ruleclasses there are total.
		context['itemcount'] = RuleClass.objects.count()
		# Get all ruleclasses.
		context['ruleclass_list'] = RuleClass.objects.all().order_by('classtype')

	except RuleClass.DoesNotExist:
		logger.warning("Page request /ruleclass/ could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleclass_list'] = ruleClassesToTemplate(context['ruleclass_list'])
	
	return render(request, 'ruleclass/ruleClass.tpl', context)