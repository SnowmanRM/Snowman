"""
This script file serves to answer url requests for the /web/rules page.

"""

from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleSet, RuleRevision, Sensor
from update.models import Update
from web.utilities import UserSettings, rulesToTemplate
import logging, json

def index(request):

	"""This method is loaded when the /rules/ url is called.
	
	Which is a list of all RuleRevision objects, paginated by the limit set in pagelength.
	
	The method gets a count of the number of objects in the database and then gets all the objects. 
	If it doesnt find anything, it raises a 404 error.
	If it finds objects, it then sends everything to the template rules/rules.tpl through the render method. """
	
	logger = logging.getLogger(__name__)
	
	# Spool up context.
	context = {}
	
	# Get pagelength from the utility class.
	pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	# This is always page nr 1.
	context['pagenr'] = 1
	
	# We want pagelength with us in the template.
	context['pagelength'] = pagelength
	
	# The first page isnt hidden.
	context['ishidden'] = False
	
	try:
		# Get the current sensor count, but we want it in a negative value.
		#context['sensorcount'] =  Sensor.objects.count()
		#context['sensorcount'] = -context['sensorcount']
		
		# We need to know how many rules there are total.
		context['itemcount'] = Rule.objects.count()
		# Get all rules, but limited by the set pagelength.
		context['rule_list'] = Rule.objects.all()[:pagelength]

	except Rule.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['rule_list']=rulesToTemplate(context['rule_list'])
	#return HttpResponse(rulesToTemplate(context['rule_list']))
	return render(request, 'rules/rules.tpl', context)

def getRulePage(request, pagenr):
	"""This method is loaded when the /rules/page/<int>/ url is called.
	
	It is used to answer dynamic calls for more pages in the paginated list of RuleRevision objects in /rules/.
	
	The method takes an argument pagenr, which it uses to calculate the minrange and maxrange of objects it needs to get, with the pagelength factored in. 
	If it doesnt find anything, it raises a 404 error.
	If it finds objects, it then sends everything to the template rules/rulepage.tpl through the render method. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	# Get pagelength from the utility class.
	pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	# We want pagenr with us in the template.
	context['pagenr'] = pagenr
	
	# We want pagelength with us in the template.
	context['pagelength'] = pagelength
	
	# The first page isnt hidden.
	context['ishidden'] = True
	
	# We multiply the paglength with the requested pagenr, this should give us the minimum range.
	minrange = pagelength * (int(pagenr)-1)
	
	# We add pagelength to the minumum range, this gives us the maximum range.
	maxrange = int(minrange) + pagelength
	
	try:
		
		# We need to know how many rules there are total.
		context['itemcount'] = Rule.objects.count()
		# Get all rules, within the set range.
		context['rule_list'] = Rule.objects.all()[minrange:maxrange]
	except Rule.DoesNotExist:
		logger.warning("Page request /rules/page/"+str(pagenr)+" could not be resolved, objects in range "+str(minrange)+" - "+str(maxrange)+"not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['rule_list']=rulesToTemplate(context['rule_list'])
	return render(request, 'rules/rulePage.tpl', context)

def getRulesBySearch(request, pagenr):
	
	"""	This method is loaded when the /rules/search/<int>/ url is called. This url is called when a user has typed a string into 
		the search bar on the /rules page. 
		
		The method does a search in the database based on the searchfield and searchstring requested, and the item range based on the page requested.
		
		If it finds objects, it then sends everything to the template rules/rulepage.tpl through the render method.
	
	"""
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	# Get the two values from the HTTP POST request.
	searchstring = request.POST['searchs']
	searchfield = request.POST['searchf']
	
	# Get pagelength from the utility class.
	pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	# We set this value to true so that we can differentiate in the template.
	context['rulesearch'] = True
	
	# We want pagenr with us in the template, but we modify it.
	context['pagenr'] = "search"+pagenr
	
	# We want pagelength with us in the template.
	context['pagelength'] = pagelength
	
	# The first page isnt hidden.
	context['ishidden'] = True
	
	# We want the searchstring with us in the template.
	context['searchstring'] = searchstring
	
	# We multiply the paglength with the requested pagenr, this should give us the minimum range.
	minrange = pagelength * (int(pagenr)-1)
	
	# We add pagelength to the minumum range, this gives us the maximum range.
	maxrange = int(minrange) + pagelength
	
	try:
		
		# We do different queries based on the searchfield string.
		if searchfield=='sid':
			# We need to know how many rules the search will produce.
			context['itemcount'] = Rule.objects.filter(SID__istartswith=searchstring).count()
			# Get matching rules, within the set range.
			context['rule_list'] = Rule.objects.filter(SID__istartswith=searchstring)[minrange:maxrange]
		elif searchfield=='name':
			# We need to know how many rules the search will produce.
			context['itemcount'] = Rule.objects.filter(revisions__active=True, revisions__msg__icontains=searchstring).count()
			# Get matching rules, within the set range.
			context['rule_list'] = Rule.objects.filter(revisions__active=True, revisions__msg__icontains=searchstring)[minrange:maxrange]

	except Rule.DoesNotExist:
		logger.warning("Page request /rules/search for string: "+searchstring+" in field "+searchfield+" could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['rule_list']=rulesToTemplate(context['rule_list'])
	return render(request, 'rules/rulePage.tpl', context)

def getRulesByRuleSet(request, ruleSetID, pagenr):
	"""	This method is loaded when the /rules/getRulesByRuleSet/ url is called. 
		
		The method fetches rules based on a ruleSetID.
		
		If it finds objects, it then sends everything to the template rules/rulepage.tpl through the render method.
	
	"""
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	# Get the two values from the HTTP POST request.

	
	# Get pagelength from the utility class.
	pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	# We set this value to true so that we can differentiate in the template.
	context['rulesearch'] = False
	
	# We want pagenr with us in the template, but we modify it.
	context['pagenr'] = int(pagenr)
	
	# We want pagelength with us in the template.
	context['pagelength'] = int(pagelength)
	
	# The first page isnt hidden.
	if int(pagenr) == 1:
		context['ishidden'] = False
	else:
		context['ishidden'] = True
	
	
	# We multiply the paglength with the requested pagenr, this should give us the minimum range.
	minrange = pagelength * (int(pagenr)-1)
	
	# We add pagelength to the minumum range, this gives us the maximum range.
	maxrange = int(minrange) + pagelength
	
	try:
		
		# We need to know how many rules the search will produce.
		context['itemcount'] = Rule.objects.filter(ruleSet__id=ruleSetID).count()
		# Get matching rules, within the set range.
		context['rule_list'] = Rule.objects.filter(ruleSet__id=ruleSetID)[minrange:maxrange]
		

	except Rule.DoesNotExist:
		logger.warning("Page request /rules/getRulesByRuleSet could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['rule_list']=rulesToTemplate(context['rule_list'])
	return render(request, 'rules/rulePage.tpl', context)

def getRulesByRuleSetNewRules(request, ruleSetID, pagenr, updateID):
	"""	This method is loaded when the /rules/getRulesByRuleSetNewRules/ url is called. 
		
		The method fetches rules based on a ruleSetID and updateID and if the rule is new.
		
		If it finds objects, it then sends everything to the template rules/rulepage.tpl through the render method.
	
	"""
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	# Get the two values from the HTTP POST request.

	
	# Get pagelength from the utility class.
	pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	# We set this value to true so that we can differentiate in the template.
	context['rulesearch'] = False
	
	# We want pagenr with us in the template, but we modify it.
	context['pagenr'] = int(pagenr)
	
	# We want pagelength with us in the template.
	context['pagelength'] = int(pagelength)
	
	# The first page isnt hidden.
	if int(pagenr) == 1:
		context['ishidden'] = False
	else:
		context['ishidden'] = True
		
	# We multiply the paglength with the requested pagenr, this should give us the minimum range.
	minrange = pagelength * (int(pagenr)-1)
	
	# We add pagelength to the minumum range, this gives us the maximum range.
	maxrange = int(minrange) + pagelength
	
	try:
		
		# We need to know how many rules the search will produce.
		context['itemcount'] = Rule.objects.filter(ruleSet__id=ruleSetID, update__id=updateID).count()
		# Get matching rules, within the set range.
		context['rule_list'] = Rule.objects.filter(ruleSet__id=ruleSetID, update__id=updateID)[minrange:maxrange]
		

	except Rule.DoesNotExist:
		logger.warning("Page request /rules/getRulesByRuleSet could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['rule_list']=rulesToTemplate(context['rule_list'])
	return render(request, 'rules/rulePage.tpl', context)

def getRulesByRuleSetNewRuleRevisions(request, ruleSetID, pagenr, updateID):
	"""	This method is loaded when the /rules/getRulesByRuleSetNewRuleRevisions/ url is called. 
		
		The method fetches rules based on a ruleSetID, updateID and if it has a new revision.
		
		If it finds objects, it then sends everything to the template rules/rulepage.tpl through the render method.
	
	"""
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	# Get the two values from the HTTP POST request.

	
	# Get pagelength from the utility class.
	pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	# We set this value to true so that we can differentiate in the template.
	context['rulesearch'] = False
	
	# We want pagenr with us in the template, but we modify it.
	context['pagenr'] = int(pagenr)
	
	# We want pagelength with us in the template.
	context['pagelength'] = int(pagelength)
	
	# The first page isnt hidden.
	if int(pagenr) == 1:
		context['ishidden'] = False
	else:
		context['ishidden'] = True
	
	# We multiply the paglength with the requested pagenr, this should give us the minimum range.
	minrange = pagelength * (int(pagenr)-1)
	
	# We add pagelength to the minumum range, this gives us the maximum range.
	maxrange = int(minrange) + pagelength
	
	try:
		update = Update.objects.get(id=updateID)
	except Update.DoesNotExist:
		logger.warning("Page request /rules/getRulesByRuleSetNewRuleRevisions could not be resolved, objects not found.")
		raise Http404
	
	revList = update.ruleRevisions.values_list('rule__SID', flat=True)
	ruleList = update.rules.values_list('SID', flat=True)
	
	revList = list(set(revList)-set(ruleList))
	
	try:
		
		# We need to know how many rules the search will produce.
		context['itemcount'] = Rule.objects.filter(ruleSet__id=ruleSetID, SID__in=revList).count()
		# Get matching rules, within the set range.
		context['rule_list'] = Rule.objects.filter(ruleSet__id=ruleSetID, SID__in=revList)[minrange:maxrange]
		

	except Rule.DoesNotExist:
		logger.warning("Page request /rules/getRulesByRuleSet could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['rule_list']=rulesToTemplate(context['rule_list'])
	return render(request, 'rules/rulePage.tpl', context)


def getRulesByRuleClass(request, ruleClassID, pagenr):
	"""	This method is loaded when the /rules/getRulesByRuleClass/ url is called. 
		
		The method fetches rules based on a ruleClassID.
		
		If it finds objects, it then sends everything to the template rules/rulepage.tpl through the render method.
	
	"""
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	# Get the two values from the HTTP POST request.

	
	# Get pagelength from the utility class.
	pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	# We set this value to true so that we can differentiate in the template.
	context['rulesearch'] = False
	
	# We want pagenr with us in the template, but we modify it.
	context['pagenr'] = int(pagenr)
	
	# We want pagelength with us in the template.
	context['pagelength'] = int(pagelength)
	
	# The first page isnt hidden.
	if int(pagenr) == 1:
		context['ishidden'] = False
	else:
		context['ishidden'] = True
	
	# If this is the first page or there is only one page, minrange must be 0.
	minrange = pagelength * (int(pagenr)-1)
	
	# We add pagelength to the minumum range, this gives us the maximum range.
	maxrange = int(minrange) + pagelength
	
	try:
		
		# We need to know how many rules the search will produce.
		context['itemcount'] = Rule.objects.filter(ruleClass__id=ruleClassID).count()
		# Get matching rules, within the set range.
		context['rule_list'] = Rule.objects.filter(ruleClass__id=ruleClassID)[minrange:maxrange]
		

	except Rule.DoesNotExist:
		logger.warning("Page request /rules/getRulesByRuleSet could not be resolved, objects not found.")
		raise Http404
	
	# Process the objects before we give them to the template.
	context['rule_list']=rulesToTemplate(context['rule_list'])
	return render(request, 'rules/rulePage.tpl', context)

def reorganizeRules(request):
	"""This method is called when the url /rules/reorganizeRules/ is called.
	It takes a set of variables through POST and then moves the rules between RuleSets.
	It returns JSON objects of the results.
	"""
	
	# We set up the logger and a few lists.
	logger = logging.getLogger(__name__)
	response = []
	
	# We check to see if there are ruleset IDs given.
	if request.POST.getlist('id'):
		ruleIDs = request.POST.getlist('id')
	else:
		response.append({'response': 'noIDsGiven', 'text': 'No Rule ID was given.'})
		return HttpResponse(json.dumps(response))
	
	ruleList = []
	
	# We iterate over the given IDs and make sure the rule objects exist, then put them in the list.
	for ruleID in ruleIDs:
		try:
			ruleList.append(Rule.objects.get(id=ruleID))
		except Rule.DoesNotExist:
			response.append({'response': 'ruleDoesNotExist', 'text': 'Rule with DB ID '+str(ruleID)+' does not exist.'})
			logger.warning("Rule with DB ID "+str(ruleID)+" could not be found.")
			return HttpResponse(json.dumps(response))
	
	# We make sure a parent ruleset was provided.
	if request.POST.get('parent'):
		ruleSetID = request.POST['parent']
		# We make sure the ruleset exists.
		try:
			ruleSet = RuleSet.objects.get(id=ruleSetID)
		except RuleSet.DoesNotExist:
			response.append({'response': 'ruleSetDoesNotExists', 'text': 'RuleSet ID '+str(ruleSetID)+' could not be found.'})
			logger.warning("RuleSet ID "+str(ruleSet)+" could not be found.")
			return HttpResponse(json.dumps(response))
	else:
		response.append({'response': 'noParentGiven', 'text': 'No new parent RuleSet was given.'})
		return HttpResponse(json.dumps(response))
	
	# We iterate over the rules in the list and assign them to the new ruleset.
	for rule in ruleList:
		rule.ruleSet = ruleSet
		rule.save()
		logger.info("Rule "+str(rule)+" is now the child of RuleSet "+str(ruleSet)+".")
	
	response.append({'response': 'rulesSuccessfullyReorganized', 'text': 'The rules were successfully moved to the new ruleset.'})
	return HttpResponse(json.dumps(response))



