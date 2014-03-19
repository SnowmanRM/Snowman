from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision, Sensor, RuleSet
from web.utilities import UserSettings, ruleSetsToTemplate, ruleSetHierarchyListToTemplate
import logging, json

def index(request):
	"""This method is called when the url /ruleset/ is called.
	
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
	context['ismain'] = True
	
	try:
		# Get the current sensor count, but we want it in a negative value.
		#context['sensorcount'] =  Sensor.objects.count()
		#context['sensorcount'] = -context['sensorcount']
		
		# We need to know how many rules there are total.
		context['itemcount'] = RuleSet.objects.count()
		# Get all rules, but limited by the set pagelength.
		context['ruleset_list'] = RuleSet.objects.filter(parent=None).order_by('name')

	except RuleSet.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleset_list'] = ruleSetsToTemplate(context['ruleset_list'])
	#return HttpResponse(ruleSetsToTemplate(context['ruleset_list']))
	return render(request, 'ruleset/ruleSet.tpl', context)

def getRuleSetChildren(request,ruleSetID):
	"""This method is called when the url /ruleset/ is called.
	
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
	context['ismain'] = False
	
	try:
		# Get the current sensor count, but we want it in a negative value.
		#context['sensorcount'] =  Sensor.objects.count()
		#context['sensorcount'] = -context['sensorcount']
		
		# We need to know how many rules there are total.
		context['itemcount'] = RuleSet.objects.count()
		parent = RuleSet.objects.get(id=ruleSetID)
		# Get all rules, but limited by the set pagelength.
		context['ruleset_list'] = RuleSet.objects.filter(parent=parent).order_by('name')

	except RuleSet.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleset_list'] = ruleSetsToTemplate(context['ruleset_list'])
	#return HttpResponse(ruleSetsToTemplate(context['ruleset_list']))
	return render(request, 'ruleset/ruleSetListItems.tpl', context)

def getCreateRuleSetForm(request):
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	try:
		# Get a complete list of sensors.
		context['ruleset_list'] = RuleSet.objects.filter(parent=None).order_by('name')
	
	except Sensor.DoesNotExist:
		logger.warning("No sensors found.")
		raise Http404
	
	context['ruleset_list'] = ruleSetHierarchyListToTemplate(context['ruleset_list'], 0)
	# Send to template.
	#return HttpResponse(context['ruleset_list'])
	return render(request, 'ruleset/createRuleSetForm.tpl', context)

def createRuleSet(request):
	
	logger = logging.getLogger(__name__)
	
	response = []
	if request.POST['rulesetname']:
		ruleSetName = request.POST['rulesetname']
	else:
		response.append({'response': 'noRuleSetName', 'text': 'Please provide a ruleset name.'})
		return HttpResponse(json.dumps(response))
		
	try:
		r = RuleSet.objects.get(name=ruleSetName)
		response.append({'response': 'ruleSetExists', 'text': 'A ruleset with that name already exists, please use another.'})
		return HttpResponse(json.dumps(response))
	except RuleSet.DoesNotExist:
		if request.POST['children'] == "None":
			children = False
		elif request.POST.getlist('children'):
			children = request.POST.getlist('children')
			
		try:
			r = RuleSet.objects.create(name=ruleSetName, active=False, parent=None, description=ruleSetName)
			
			if children:
				for child in children:
					try:
						c = RuleSet.objects.get(id=child)
						r.childSets.add(c)
						logger.info("RuleSet "+str(c)+" is now child of RuleSet "+str(r)+".")
					except:
						logger.debug("Could not find RuleSet with DB ID: "+child+".")
						
			response.append({'response': 'ruleSetCreated', 'text': 'Ruleset successfully created.'})
			logger.info("Ruleset created: "+str(r)+".")
			return HttpResponse(json.dumps(response))
		except:
			response.append({'response': 'ruleSetCreationFailure', 'text': 'Failed when trying to create RuleSet.'})
			logger.error("Failed when trying to add thresholds.")
			return HttpResponse(json.dumps(response))





