from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect
from django.db.models import Count
from django.contrib.auth.decorators import login_required
from core.models import Rule, RuleRevision, Sensor, RuleSet
from update.models import Update
from web.utilities import UserSettings, ruleSetsToTemplate, ruleSetHierarchyListToTemplate, ruleSetsWithNewRulesToTemplate, ruleSetsWithNewRuleRevisionsToTemplate
import logging, json

@login_required
def index(request):
	"""This method is called when the url /ruleset/ is called.
	
	It fetches ruleset objects and sends them to the render.
	
	"""
	
	logger = logging.getLogger(__name__)
	
	# Spool up context.
	context = {}
	
	context['ismain'] = True
	
	try:
		
		# We need to know how many rulesets there are total.
		context['itemcount'] = RuleSet.objects.count()
		# Get all rulesets.
		context['ruleset_list'] = RuleSet.objects.filter(parent=None).order_by('name')

	except RuleSet.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleset_list'] = ruleSetsToTemplate(context['ruleset_list'])
	
	return render(request, 'ruleset/ruleSet.tpl', context)

@login_required
def getRuleSetByUpdate(request, updateID):
	"""This method is called when the url /ruleset/byUpdate/ is called.
	
	It fetches ruleset objects based on its update ID and sends them to the render.
	
	"""
	
	logger = logging.getLogger(__name__)
	
	# Spool up context.
	context = {}
	
	context['ismain'] = True
	
	# We fetch the update object in question.
	try:
		update = Update.objects.get(id=updateID)
	except Update.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	try:		
		# We need to know how many rulesets there are total.
		context['itemcount'] = update.ruleSets.count()
		# Get all rulesets belonging to the update.
		context['ruleset_list'] = update.ruleSets.order_by('name').all()

	except RuleSet.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleset_list'] = ruleSetsToTemplate(context['ruleset_list'])

	return render(request, 'ruleset/ruleSetListItems.tpl', context)
	
@login_required
def getRuleSetByUpdateNewRules(request, updateID):
	"""This method is called when the url /ruleset/byNewRules is called.
	
	It fetches ruleset objects based on them having rules from an update and sends them to the render.
	
	"""
	
	logger = logging.getLogger(__name__)
	
	# Spool up context.
	context = {}
	
	context['ismain'] = True
	
	# We fetch the update object in question.
	try:
		update = Update.objects.get(id=updateID)
	except Update.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	try:
		# We need to know how many rulesets there are total.
		context['itemcount'] = RuleSet.objects.count()
		# Get all rulesets.
		context['ruleset_list'] = RuleSet.objects.order_by('name')

	except RuleSet.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleset_list'] = ruleSetsWithNewRulesToTemplate(context['ruleset_list'], update)
	
	#return HttpResponse(ruleSetsToTemplate(context['ruleset_list']))
	return render(request, 'ruleset/ruleSetListItems.tpl', context)

@login_required
def getRuleSetByUpdateNewRuleRevisions(request, updateID):
	"""This method is called when the url /ruleset/byNewRuleRevisions is called.
	
	It fetches ruleset objects based on them containing rules with new revisions and sends them to the render.
	
	"""
	
	logger = logging.getLogger(__name__)
	
	# Spool up context.
	context = {}
	
	context['ismain'] = True
	
	# We fetch the update object in question.
	try:
		update = Update.objects.get(id=updateID)
	except Update.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	try:
		# We need to know how many rulesets there are total.
		context['itemcount'] = RuleSet.objects.count()
		# Get all rulesets.
		context['ruleset_list'] = RuleSet.objects.order_by('name')

	except RuleSet.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleset_list'] = ruleSetsWithNewRuleRevisionsToTemplate(context['ruleset_list'], update)
	
	#return HttpResponse(context['ruleset_list'])
	return render(request, 'ruleset/ruleSetListItems.tpl', context)

@login_required
def getRuleSetChildren(request,ruleSetID):
	"""This method is called when the url /ruleset/children/ is called.
	
	It fetches the children of a ruleset object and sends them to the render.
	
	"""
	
	logger = logging.getLogger(__name__)
	
	# Spool up context.
	context = {}
	
	context['ismain'] = False
	
	try:
		
		# We need to know how many rulesets there are total.
		context['itemcount'] = RuleSet.objects.count()
		#Get the parent ruleset.
		parent = RuleSet.objects.get(id=ruleSetID)
		# Get all ruleset children.
		context['ruleset_list'] = RuleSet.objects.filter(parent=parent).order_by('name')

	except RuleSet.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleset_list'] = ruleSetsToTemplate(context['ruleset_list'])

	return render(request, 'ruleset/ruleSetListItems.tpl', context)

@login_required
def getCreateRuleSetForm(request):
	"""This method is called when the url /ruleset/getCreateRuleSetForm/ is called.
	It delivers a form to the render.
	"""
	logger = logging.getLogger(__name__)
	
	context = {}
	
	try:
		# Get all the parent rulesets.
		context['ruleset_list'] = RuleSet.objects.filter(parent=None).order_by('name')
	
	except RuleSet.DoesNotExist:
		logger.warning("No RuleSet found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleset_list'] = ruleSetHierarchyListToTemplate(context['ruleset_list'], 0)
	# Send to template.
	return render(request, 'ruleset/createRuleSetForm.tpl', context)

@login_required
def getEditRuleSetForm(request, ruleSetID):
	"""This method is called when the url /ruleset/getEditRuleSetForm/ is called.
	It delivers a form to the render.
	"""
	logger = logging.getLogger(__name__)
	
	context = {}
	
	# We only edit one ruleset at a time.
	try:
		#Fetch the ruleset.
		ruleSet = RuleSet.objects.get(id=ruleSetID)
		context['ruleSetID'] = ruleSet.id
		context['ruleSetName'] = ruleSet.name
		# We deliver lists of parent and child IDs so that they can be matched.
		if ruleSet.parent:
			context['ruleSetParent'] = ruleSet.parent.id
		else:
			context['ruleSetParent'] = None
		if ruleSet.childSets.count() > 0:
			context['ruleSetChildren'] = ruleSet.childSets.values_list('id', flat=True)
		else:
			context['ruleSetChildren'] = None
		# Get all the parent rulesets.
		context['ruleset_list'] = RuleSet.objects.filter(parent=None).order_by('name')
	
	except RuleSet.DoesNotExist:
		logger.warning("No RuleSet found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleset_list'] = ruleSetHierarchyListToTemplate(context['ruleset_list'], 0)
	# Send to template.
	return render(request, 'ruleset/editRuleSetForm.tpl', context)

@login_required
def getReorganizeRulesForm(request):
	"""This method is called when the url /ruleset/getReorganizeRulesForm/ is called.
	It delivers a form to the render.
	"""
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	try:
		# Get all the parent rulesets
		context['ruleset_list'] = RuleSet.objects.filter(parent=None).order_by('name')
	
	except RuleSet.DoesNotExist:
		logger.warning("No RuleSet found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['ruleset_list'] = ruleSetHierarchyListToTemplate(context['ruleset_list'], 0)
	# Send to template.
	return render(request, 'ruleset/reorganizeRulesForm.tpl', context)

@login_required
def createRuleSet(request):
	"""This method is called when the url /ruleset/createRuleSet/ is called.
	It takes a set of variables through POST and then creates a RuleSet object based on them.
	It returns JSON objects of the results.
	"""
	
	# We set up the logger and a few lists.
	logger = logging.getLogger(__name__)
	response = []
	
	# We check to see if theres a ruleset name given.
	if request.POST['rulesetname']:
		ruleSetName = request.POST['rulesetname']
	else:
		response.append({'response': 'noRuleSetName', 'text': 'Please provide a ruleset name.'})
		return HttpResponse(json.dumps(response))
	
	# We try to see if theres a ruleset with that name already.
	try:
		r = RuleSet.objects.get(name=ruleSetName)
		response.append({'response': 'ruleSetExists', 'text': 'A ruleset with that name already exists, please use another.'})
		return HttpResponse(json.dumps(response))
	#If not, we make one.
	except RuleSet.DoesNotExist:
		# We determine if the new ruleset is to have children.
		if request.POST['children'] == "None":
			children = False
		elif request.POST.getlist('children'):
			children = request.POST.getlist('children')
		else:
			children = False
		# We create the new ruleset.
		try:
			r = RuleSet.objects.create(name=ruleSetName, active=False, parent=None, description=ruleSetName)
			
			# If the new ruleset is to have children, we add them.
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


@login_required
def editRuleSet(request):
	"""This method is called when the url /ruleset/editRuleSet/ is called.
	It takes a set of variables through POST and then updates a RuleSet object based on them.
	It returns JSON objects of the results.
	"""
	
	# We set up the logger and a few lists.
	logger = logging.getLogger(__name__)
	response = []
	
	edited = False
	
	# We get the ID of the ruleset we're editing.
	if request.POST.get('id'):
		ruleSetID = request.POST['id']
	else:
		response.append({'response': 'noRuleSetID', 'text': 'The POST did not deliver a RuleSet ID.'})
		return HttpResponse(json.dumps(response))
	
	# We check to see if the ruleset we want to edit exists.
	try:
		ruleSet = RuleSet.objects.get(id=ruleSetID)
	except RuleSet.DoesNotExist:
		response.append({'response': 'ruleSetDoesNotExists', 'text': 'RuleSet ID '+ruleSetID+' could not be found.'})
		logger.warning("RuleSet ID "+ruleSetID+" could not be found.")
		return HttpResponse(json.dumps(response))
	
	# We check to see if theres a ruleset name given.
	if request.POST['rulesetname']:
		ruleSetName = request.POST['rulesetname']
	else:
		response.append({'response': 'noRuleSetName', 'text': 'Please provide a ruleset name.'})
		return HttpResponse(json.dumps(response))
	
	# We check the values for children given. 
	if request.POST['children'] == "None":
		children = False
	elif request.POST.getlist('children'):
		children = request.POST.getlist('children')
		if "None" in children:
			children.remove("None")
	else:
		children = False
		
	# We check the values for parents given.
	if request.POST['parent'] == "None":
		parent = False
	elif request.POST['parent']:
		parent = request.POST['parent']
	
	
	# If a new name was given, we change it.
	if ruleSet.name != ruleSetName:
		ruleSet.name = ruleSetName
		logger.info("RuleSet "+str(ruleSet)+" has been renamed.")
		edited = True
		
	# If the ruleset is not to have a parent, we set the parent to be None.
	if not parent:
		ruleSet.parent = None
		logger.info("RuleSet "+str(ruleSet)+" no longer has a parent.")
		edited = True
		
	# If the ruleset is assigned a new parent, we assign the parent to the ruleset.
	elif (ruleSet.parent == None and parent) or (ruleSet.parent and int(ruleSet.parent.id) != int(parent)):
		# We check to see if the parent exists.
		try:
			ruleSetParent = RuleSet.objects.get(id=parent)
		except RuleSet.DoesNotExist:
			response.append({'response': 'ruleSetDoesNotExists', 'text': 'RuleSet ID '+ruleSetID+' could not be found.'})
			logger.warning("RuleSet ID "+str(ruleSet)+" could not be found.")
			return HttpResponse(json.dumps(response))
		
		# We make sure the ruleset isnt setting itself as a parent.
		if ruleSetParent != ruleSet:
			ruleSet.parent = ruleSetParent
			logger.info("RuleSet "+str(ruleSetParent)+" is now the parent of "+str(ruleSet)+".")
			edited = True
		elif ruleSetParent == ruleSet:
			response.append({'response': 'ruleSetParentInbreeding', 'text': 'Inbreeding problem:\nA RuleSet cannot become its own parent.'})
			return HttpResponse(json.dumps(response))		
			
	# We get the rulesets current list of children.	
	ruleSetChildren = ruleSet.childSets.values_list('id', flat=True)
	
	# If the ruleset is given children but doesnt have any atm.
	if children and not len(ruleSetChildren):
		ruleSetChildren = []
		# We iterate over the children to make sure they all exist and put them in the list.
		try:
			for child in children:
				ruleSetChildren.append(RuleSet.objects.get(id=child))
		except RuleSet.DoesNotExist:
			response.append({'response': 'ruleSetDoesNotExists', 'text': 'RuleSet list of IDs '+children+' could not be found.'})
			logger.warning("RuleSet list of IDs "+str(children)+" could not be found.")
			return HttpResponse(json.dumps(response))
		
		# We get the parent of the ruleset.
		setParent = ruleSet.parent
		
		# We iterate over the children again to add them to the ruleset.
		for child in ruleSetChildren:
			inbreeding = False
			
			# We make sure the new child isnt one of the current rulesets parents. Grandfather-paradox.
			while setParent != None:
				if setParent == child:
					inbreeding = True
				setParent = setParent.parent
			
			# If there was no inbreeding and the child isnt the ruleset itself, we add it to the list of children.
			if not inbreeding and child != ruleSet:
				ruleSet.childSets.add(child)
				edited = True
			
			# If there was some form of inbreeding.
			elif inbreeding or child == ruleSet:
				response.append({'response': 'ruleSetChildInbreeding', 'text': 'Inbreeding problem:\nA RuleSet cannot become its own child. \nA RuleSets parent cannot become its child.'})
				return HttpResponse(json.dumps(response))
			
		
	# If the ruleset is given children and they are different from the current children.	
	elif children and set(children) != set(ruleSetChildren):
		
		oldRuleSetChildren = []
		newRuleSetChildren = []
		
		# We verify that all children exist and make two lists of both the new children and the current children of the ruleset.
		try:
			for child in ruleSetChildren:
				oldRuleSetChildren.append(RuleSet.objects.get(id=child))
			for child in children:
				newRuleSetChildren.append(RuleSet.objects.get(id=child))
		except RuleSet.DoesNotExist:
			response.append({'response': 'ruleSetDoesNotExists', 'text': 'RuleSet list of IDs '+children+' could not be found.'})
			logger.warning("RuleSet list of IDs "+children+" could not be found.")
			return HttpResponse(json.dumps(response))
		
		# If there are old children that are not in the new children list, we remove them from the rulesets current children.
		for child in oldRuleSetChildren:
			if child not in newRuleSetChildren:
				ruleSet.childSets.remove(child)
				edited = True
				
				logger.info("RuleSet "+str(ruleSet)+" is no longer the parent of "+str(child)+".")
		
		# We get the parent of the ruleset.
		setParent = ruleSet.parent
		
		# We iterate over the children again to add them to the ruleset.
		for child in newRuleSetChildren:
			# We only add a new child if it isnt in the old child list.
			if child not in oldRuleSetChildren:
				inbreeding = False
				
				# We make sure the new child isnt one of the current rulesets parents. Grandfather-paradox.
				while setParent != None:
					if setParent == child:
						inbreeding = True
					setParent = setParent.parent
				
				# If there was no inbreeding and the child isnt the ruleset itself, we add it to the list of children.	
				if not inbreeding and child != ruleSet:
					ruleSet.childSets.add(child)
					edited = True
					logger.info("RuleSet "+str(ruleSet)+" is now the parent of "+str(child)+".")
				# If there was some form of inbreeding.
				elif inbreeding or child == ruleSet:
					response.append({'response': 'ruleSetChildInbreeding', 'text': 'Inbreeding problem:\nA RuleSet cannot become its own child. \nA RuleSets parent cannot become its child.'})
					return HttpResponse(json.dumps(response))
			
	# If the ruleset is to not have any children and has children, we clear any current relations.
	elif (not children and len(ruleSetChildren) > 0 ):
		ruleSet.childSets.clear()
		logger.info("RuleSet "+str(ruleSet)+" no longer has children.")
		edited = True
		
	# If anything was edited, we save the object just in case and report a successful edit.	
	if edited:
		ruleSet.save()
		response.append({'response': 'ruleSetSuccessfullyEdited', 'text': 'RuleSet was successfully edited.'})
	# Nothing was edited.
	else:
		response.append({'response': 'ruleSetNoChanges', 'text': 'Edit complete, no changes.'})
	
	return HttpResponse(json.dumps(response))

@login_required
def deleteRuleSet(request):
	"""This method is called when the url /ruleset/editRuleSet/ is called.
	It takes a set of variables through POST and then deletes RuleSet objects based on them.
	It returns JSON objects of the results.
	"""
	
	# We set up the logger and a few lists.
	logger = logging.getLogger(__name__)
	response = []
	
	# We check to see if there are ruleset IDs given.
	if request.POST.getlist('id'):
		ruleSetIDs = request.POST.getlist('id')
	else:
		response.append({'response': 'noIDsGiven', 'text': 'No RuleSet ID was given, deletion cancelled.'})
		return HttpResponse(json.dumps(response))
	
	# We iterate over the ruleset IDs given.
	for ruleSetID in ruleSetIDs:
		# We check to see if the ruleset exists first.
		try:
			ruleSet = RuleSet.objects.get(id=ruleSetID)

		except RuleSet.DoesNotExist:
			response.append({'response': 'ruleSetDoesNotExists', 'text': 'RuleSet ID '+ruleSetID+' could not be found.'})
			logger.warning("RuleSet ID "+str(ruleSetID)+" could not be found.")
			return HttpResponse(json.dumps(response))
	
		# If the ruleset has children, we have to deal with their relations.
		if ruleSet.childSets.count() > 0:
				for child in ruleSet.childSets.all():
					# We give set all the childrens parent to be the deleted rulesets parent.
					child.parent = ruleSet.parent
					child.save()
					logger.info("RuleSet "+str(child)+" is now child of RuleSet "+str(ruleSet.parent)+".")
		
		# We remove the parent relation.	
		ruleSet.parent = None
		ruleSet.save()
		
		# This must be done before the actual deletion, lest the object wont exist.
		logger.info("RuleSet "+str(ruleSet)+" has been deleted, along with all its rules.")
		# We delete the ruleset.
		ruleSet.delete()
	
	response.append({'response': 'ruleSetSuccessfulDeletion', 'text': 'Ruleset(s) was successfully deleted.'})
	return HttpResponse(json.dumps(response))












