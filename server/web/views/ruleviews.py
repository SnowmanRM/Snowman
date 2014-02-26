"""
This script file serves to answer url requests for all the main pages in the page structure.

"""

from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision, Sensor
from web.utilities import UserSettings
import logging

def index(request):

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
		context['sensorcount'] =  Sensor.objects.count()
		context['sensorcount'] = -context['sensorcount']
		context['itemcount'] = Rule.objects.count()
		context['rule_list'] = Rule.objects.all()[:pagelength]
	except Rule.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	
	return render(request, 'rules/rules.tpl', context)

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
		context['sensorcount'] =  Sensor.objects.count()
		context['sensorcount'] = -context['sensorcount']
		context['itemcount'] = Rule.objects.count()
		context['rule_list'] = Rule.objects.all()[minrange:maxrange]
	except Rule.DoesNotExist:
		logger.warning("Page request /rules/page/"+str(pagenr)+" could not be resolved, objects in range "+str(minrange)+" - "+str(maxrange)+"not found.")
		raise Http404
	
	return render(request, 'rules/rulepage.tpl', context)

def getRulesBySearch(request, pagenr):
	
	"""This method is loaded when the /rules/search/<int> url is called.
	
	"""
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	searchstring = request.POST['searchs']
	searchfield = request.POST['searchf']
	
	pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	context['rulesearch'] = True
	context['pagenr'] = "search"+pagenr
	context['pagelength'] = pagelength
	context['ishidden'] = True
	
	if pagenr=='1':
		minrange=0
	else:
		minrange = pagelength * int(pagenr)
	
	maxrange = int(minrange) + pagelength
	
	try:
		context['sensorcount'] =  Sensor.objects.count()
		context['sensorcount'] = -context['sensorcount']
		
		if searchfield=='sid':
			context['itemcount'] = Rule.objects.filter(SID__istartswith=searchstring).count()
			context['rule_list'] = Rule.objects.filter(SID__istartswith=searchstring)[minrange:maxrange]
		elif searchfield=='name':
			context['itemcount'] = Rule.objects.filter(revisions__active=True, revisions__msg__icontains=searchstring).count()
			context['rule_list'] = Rule.objects.filter(revisions__active=True, revisions__msg__icontains=searchstring)[minrange:maxrange]
			
		
	except Rule.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	
	return render(request, 'rules/rulepage.tpl', context)

