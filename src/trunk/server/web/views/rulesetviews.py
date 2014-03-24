from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect
from django.db.models import Count

from core.models import Rule, RuleRevision, Sensor, RuleSet
from update.models import Update
from web.utilities import UserSettings, ruleSetsToTemplate, ruleSetHierarchyListToTemplate, ruleSetsWithNewRulesToTemplate
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

def getRuleSetByUpdate(request, updateID):
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
		update = Update.objects.get(id=updateID)
	except Update.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	try:
		# Get the current sensor count, but we want it in a negative value.
		#context['sensorcount'] =  Sensor.objects.count()
		#context['sensorcount'] = -context['sensorcount']
		
		# We need to know how many rules there are total.
		context['itemcount'] = RuleSet.objects.count()
		# Get all rules, but limited by the set pagelength.
		context['ruleset_list'] = update.ruleSets.order_by('name').all()

	except RuleSet.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleset_list'] = ruleSetsToTemplate(context['ruleset_list'])
	#return HttpResponse(ruleSetsToTemplate(context['ruleset_list']))
	return render(request, 'ruleset/ruleSetListItems.tpl', context)
	
def getRuleSetByUpdateNewRules(request, updateID):
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
		update = Update.objects.get(id=updateID)
	except Update.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	try:
		# Get the current sensor count, but we want it in a negative value.
		#context['sensorcount'] =  Sensor.objects.count()
		#context['sensorcount'] = -context['sensorcount']
		
		# We need to know how many rules there are total.
		context['itemcount'] = RuleSet.objects.count()
		# Get all rules, but limited by the set pagelength.
		context['ruleset_list'] = RuleSet.objects.annotate(c=Count('rules')).filter(c__gt=0).order_by('name')

	except RuleSet.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleset_list'] = ruleSetsWithNewRulesToTemplate(context['ruleset_list'], update)
	
	#return HttpResponse(ruleSetsToTemplate(context['ruleset_list']))
	return render(request, 'ruleset/ruleSetListItems.tpl', context)

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
	
	except RuleSet.DoesNotExist:
		logger.warning("No RuleSet found.")
		raise Http404
	
	context['ruleset_list'] = ruleSetHierarchyListToTemplate(context['ruleset_list'], 0)
	# Send to template.
	#return HttpResponse(context['ruleset_list'])
	return render(request, 'ruleset/createRuleSetForm.tpl', context)

def getEditRuleSetForm(request, ruleSetID):
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	try:
		ruleSet = RuleSet.objects.get(id=ruleSetID)
		context['ruleSetID'] = ruleSet.id
		context['ruleSetName'] = ruleSet.name
		if ruleSet.parent:
			context['ruleSetParent'] = ruleSet.parent.id
		else:
			context['ruleSetParent'] = None
		if ruleSet.childSets.count() > 0:
			context['ruleSetChildren'] = ruleSet.childSets.values_list('id', flat=True)
		else:
			context['ruleSetChildren'] = None
		# Get a complete list of sensors.
		context['ruleset_list'] = RuleSet.objects.filter(parent=None).order_by('name')
	
	except RuleSet.DoesNotExist:
		logger.warning("No RuleSet found.")
		raise Http404
	
	context['ruleset_list'] = ruleSetHierarchyListToTemplate(context['ruleset_list'], 0)
	# Send to template.
	#return HttpResponse(context['ruleSetChildren'])
	return render(request, 'ruleset/editRuleSetForm.tpl', context)

def getReorganizeRulesForm(request):
	logger = logging.getLogger(__name__)
	
	context = {}
	
	try:
		# Get a complete list of sensors.
		context['ruleset_list'] = RuleSet.objects.filter(parent=None).order_by('name')
	
	except RuleSet.DoesNotExist:
		logger.warning("No RuleSet found.")
		raise Http404
	
	context['ruleset_list'] = ruleSetHierarchyListToTemplate(context['ruleset_list'], 0)
	# Send to template.
	#return HttpResponse(context['ruleset_list'])
	return render(request, 'ruleset/reorganizeRulesForm.tpl', context)

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


def editRuleSet(request):
	
	logger = logging.getLogger(__name__)
	
	response = []
	edited = False
	ruleSetID = request.POST['id']
	
	if request.POST['rulesetname']:
		ruleSetName = request.POST['rulesetname']
	else:
		response.append({'response': 'noRuleSetName', 'text': 'Please provide a ruleset name.'})
		return HttpResponse(json.dumps(response))
	
	if request.POST['children'] == "None":
		children = False
	elif request.POST.getlist('children'):
		children = request.POST.getlist('children')
		if "None" in children:
			children.remove("None")
	else:
		children = False
		
	if request.POST['parent'] == "None":
		parent = False
	elif request.POST['parent']:
		parent = request.POST['parent']
	
	try:
		ruleSet = RuleSet.objects.get(id=ruleSetID)
	except RuleSet.DoesNotExist:
		response.append({'response': 'ruleSetDoesNotExists', 'text': 'RuleSet ID '+ruleSetID+' could not be found.'})
		logger.warning("RuleSet ID "+ruleSet+" could not be found.")
		return HttpResponse(json.dumps(response))
	
	if ruleSet.name != ruleSetName:
		ruleSet.name = ruleSetName
		logger.info("RuleSet "+str(ruleSet)+" has been renamed.")
		edited = True
		
	
	if not parent:
		ruleSet.parent = None
		logger.info("RuleSet "+str(ruleSet)+" no longer has a parent.")
		edited = True
		
		
	elif (ruleSet.parent == None and parent) or (ruleSet.parent and int(ruleSet.parent.id) != int(parent)):
		try:
			ruleSetParent = RuleSet.objects.get(id=parent)
		except RuleSet.DoesNotExist:
			response.append({'response': 'ruleSetDoesNotExists', 'text': 'RuleSet ID '+ruleSetID+' could not be found.'})
			logger.warning("RuleSet ID "+str(ruleSet)+" could not be found.")
			return HttpResponse(json.dumps(response))
		
		if ruleSetParent != ruleSet:
			ruleSet.parent = ruleSetParent
			logger.info("RuleSet "+str(ruleSetParent)+" is now the parent of "+str(ruleSet)+".")
			edited = True
		elif ruleSetParent == ruleSet:
			response.append({'response': 'ruleSetParentInbreeding', 'text': 'Inbreeding problem:\nA RuleSet cannot become its own parent.'})
			return HttpResponse(json.dumps(response))		
			
		
	ruleSetChildren = ruleSet.childSets.values_list('id', flat=True)
	
	if children and not len(ruleSetChildren):
		ruleSetChildren = []
		try:
			for child in children:
				ruleSetChildren.append(RuleSet.objects.get(id=child))
		except RuleSet.DoesNotExist:
			response.append({'response': 'ruleSetDoesNotExists', 'text': 'RuleSet list of IDs '+children+' could not be found.'})
			logger.warning("RuleSet list of IDs "+str(children)+" could not be found.")
			return HttpResponse(json.dumps(response))
		
		setParent = ruleSet.parent
		
		for child in ruleSetChildren:
			inbreeding = False
			
			while setParent != None:
				if setParent == child:
					inbreeding = True
				setParent = setParent.parent
				
			if not inbreeding and child != ruleSet:
				ruleSet.childSets.add(child)
				edited = True
				response.append({'response': 'test'})
				
			elif inbreeding or child == ruleSet:
				response.append({'response': 'ruleSetChildInbreeding', 'text': 'Inbreeding problem:\nA RuleSet cannot become its own child. \nA RuleSets parent cannot become its child.'})
				return HttpResponse(json.dumps(response))
			
		
		
	elif children and set(children) != set(ruleSetChildren):
		oldRuleSetChildren = []
		newRuleSetChildren = []
		try:
			for child in ruleSetChildren:
				oldRuleSetChildren.append(RuleSet.objects.get(id=child))
			for child in children:
				newRuleSetChildren.append(RuleSet.objects.get(id=child))
		except RuleSet.DoesNotExist:
			response.append({'response': 'ruleSetDoesNotExists', 'text': 'RuleSet list of IDs '+children+' could not be found.'})
			logger.warning("RuleSet list of IDs "+children+" could not be found.")
			return HttpResponse(json.dumps(response))
		
		for child in oldRuleSetChildren:
			if child not in newRuleSetChildren:
				ruleSet.childSets.remove(child)
				edited = True
				
				logger.info("RuleSet "+str(ruleSet)+" is no longer the parent of "+str(child)+".")
			
		setParent = ruleSet.parent
		
		for child in newRuleSetChildren:
			if child not in oldRuleSetChildren:
				inbreeding = False
				
				while setParent != None:
					if setParent == child:
						inbreeding = True
					setParent = setParent.parent
					
				if not inbreeding and child != ruleSet:
					ruleSet.childSets.add(child)
					edited = True
					logger.info("RuleSet "+str(ruleSet)+" is now the parent of "+str(child)+".")
				elif inbreeding or child == ruleSet:
					response.append({'response': 'ruleSetChildInbreeding', 'text': 'Inbreeding problem:\nA RuleSet cannot become its own child. \nA RuleSets parent cannot become its child.'})
					return HttpResponse(json.dumps(response))
			

	elif (not children and len(ruleSetChildren) > 0 ):
		ruleSet.childSets.clear()
		logger.info("RuleSet "+str(ruleSet)+" no longer has children.")
		edited = True
		
		
	if edited:
		ruleSet.save()
		response.append({'response': 'ruleSetSuccessfullyEdited', 'text': 'RuleSet was successfully edited.'})
	else:
		response.append({'response': 'ruleSetNoChanges', 'text': 'Edit complete, no changes.'})
	
	return HttpResponse(json.dumps(response))

def deleteRuleSet(request):
	logger = logging.getLogger(__name__)
	
	response = []
	
	if request.POST.getlist('id'):
		ruleSetIDs = request.POST.getlist('id')
	else:
		response.append({'response': 'noIDsGiven', 'text': 'No RuleSet ID was given, deletion cancelled.'})
		return HttpResponse(json.dumps(response))
	
	for ruleSetID in ruleSetIDs:
		try:
			ruleSet = RuleSet.objects.get(id=ruleSetID)

		except RuleSet.DoesNotExist:
			response.append({'response': 'ruleSetDoesNotExists', 'text': 'RuleSet ID '+ruleSetID+' could not be found.'})
			logger.warning("RuleSet ID "+str(ruleSet)+" could not be found.")
			return HttpResponse(json.dumps(response))
	
		if ruleSet.childSets.count() > 0:
				for child in ruleSet.childSets.all():
					child.parent = ruleSet.parent
					child.save()
					logger.info("RuleSet "+str(child)+" is now child of RuleSet "+str(ruleSet.parent)+".")
			
		ruleSet.parent = None
		ruleSet.save()
		
		logger.info("RuleSet "+str(ruleSet)+" has been deleted, along with all its rules.")
		
		ruleSet.delete()
	
	response.append({'response': 'ruleSetSuccessfulDeletion', 'text': 'Ruleset(s) was successfully deleted.'})
	return HttpResponse(json.dumps(response))












