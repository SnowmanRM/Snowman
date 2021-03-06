from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from core.models import Rule, RuleRevision, Sensor, Generator, RuleSet, Comment
from core.exceptions import MissingObjectError
from tuning.models import EventFilter, DetectionFilter, Suppress, SuppressAddress
from web.utilities import tuningToTemplate
from web.utilities import UserSettings
from web.exceptions import InvalidValueError
import logging, json, re
from itertools import chain
from util import patterns


@login_required
def index(request):
	"""This method is loaded when the /tuning/tuningByRule/ is called. 
	It delivers the first page of tuning objects. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	# Get pagelength from the utility class.
	pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	# We want pagenr with us in the template.
	context['pagenr'] = 1
	
	# We want pagelength with us in the template.
	context['pagelength'] = pagelength
	
	# The first page isnt hidden.
	context['ishidden'] = False

	
	# We multiply the paglength with the requested pagenr, this should give us the minimum range.
	minrange = 0
	
	# We add pagelength to the minumum range, this gives us the maximum range.
	maxrange = int(minrange) + (pagelength)
	
	try:
		# We get a total count of the number of objects.
		context['itemcount'] = EventFilter.objects.count()
		context['itemcount'] += DetectionFilter.objects.count()
		context['itemcount'] += Suppress.objects.count()
		# We get all the objects.
		eventFilterList = EventFilter.objects.all()
		detectionFilterList = DetectionFilter.objects.all()
		suppressList = Suppress.objects.all()
		# We combine all the objects into one big list.
		tuningList = list(chain(eventFilterList,detectionFilterList,suppressList))
	
	except:
		logger.warning("No sensors found.")
		raise Http404
	
	# We send a ranged set of the objects for processing.
	context['tuningList'] = tuningToTemplate(tuningList[minrange:maxrange])
	# Send to template.
	return render(request, 'tuning/tuning.tpl', context)

@login_required
def tuningPage(request, pagenr):
	"""This method is loaded when the /tuning/tuningByRulePage/ is called. 
	It delivers the page specified page of tuning objects. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	# Get pagelength from the utility class.
	pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	# We want pagenr with us in the template.
	context['pagenr'] = pagenr
	
	# We want pagelength with us in the template.
	context['pagelength'] = pagelength
	
	# The first page isnt hidden.
	if int(pagenr) == 1:
		context['ishidden'] = False
	else:
		context['ishidden'] = True
	
	# We multiply the paglength with the requested pagenr, this should give us the minimum range.
	minrange = (pagelength) * (int(pagenr)-1)
	
	# We add pagelength to the minumum range, this gives us the maximum range.
	maxrange = int(minrange) + (pagelength)
	
	try:
		# We get a total count of the number of objects.
		context['itemcount'] = EventFilter.objects.count()
		context['itemcount'] += DetectionFilter.objects.count()
		context['itemcount'] += Suppress.objects.count()
		# We get all the objects.
		eventFilterList = EventFilter.objects.all()
		detectionFilterList = DetectionFilter.objects.all()
		suppressList = Suppress.objects.all()
		# We combine all the objects into one big list.
		tuningList = list(chain(eventFilterList,detectionFilterList,suppressList))
	except:
		logger.warning("No sensors found.")
		raise Http404
	
	# We send a ranged set of the objects for processing.
	context['tuningList'] = tuningToTemplate(tuningList[minrange:maxrange])
	# Send to template.
	return render(request, 'tuning/tuningPage.tpl', context)

@login_required
def tuningSearch(request, pagenr):
	"""This method is loaded when the /tuning/tuningByRulePage/ is called. 
	It delivers the page specified page of tuning objects based on search parameters. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	# Get the two values from the HTTP POST request.
	searchstring = request.POST['searchs']
	searchfield = request.POST['searchf']
	
	
	# We set this value to true so that we can differentiate in the template.
	context['rulesearch'] = True
	
	# We want the searchstring with us in the template.
	context['searchstring'] = searchstring
	
	# Get pagelength from the utility class.
	pagelength = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	# We want pagenr with us in the template.
	context['pagenr'] = "search"+pagenr
	
	# We want pagelength with us in the template.
	context['pagelength'] = pagelength
	
	# The first page isnt hidden.
	if int(pagenr) == 1:
		context['ishidden'] = False
	else:
		context['ishidden'] = True
	
	# We multiply the paglength with the requested pagenr, this should give us the minimum range.
	minrange = (pagelength) * (int(pagenr)-1)
	
	# We add pagelength to the minumum range, this gives us the maximum range.
	maxrange = int(minrange) + (pagelength)
	
	try:
		
		# We do different queries based on the searchfield string.
		if searchfield=='sid':
			# We get a total count of the number of objects.
			context['itemcount'] = EventFilter.objects.filter(rule__SID__istartswith=searchstring).count()
			context['itemcount'] += DetectionFilter.objects.filter(rule__SID__istartswith=searchstring).count()
			context['itemcount'] += Suppress.objects.filter(rule__SID__istartswith=searchstring).count()
			# We get all the objects.
			eventFilterList = EventFilter.objects.filter(rule__SID__istartswith=searchstring)
			detectionFilterList = DetectionFilter.objects.filter(rule__SID__istartswith=searchstring)
			suppressList = Suppress.objects.filter(rule__SID__istartswith=searchstring)
		elif searchfield=='name':
			# We get a total count of the number of objects.
			context['itemcount'] = EventFilter.objects.filter(rule__revisions__msg__icontains=searchstring).distinct().count()
			context['itemcount'] += DetectionFilter.objects.filter(rule__revisions__msg__icontains=searchstring).distinct().count()
			context['itemcount'] += Suppress.objects.filter(rule__revisions__msg__icontains=searchstring).distinct().count()
			# We get all the objects.
			eventFilterList = EventFilter.objects.filter(rule__revisions__msg__icontains=searchstring).distinct()
			detectionFilterList = DetectionFilter.objects.filter(rule__revisions__msg__icontains=searchstring).distinct()
			suppressList = Suppress.objects.filter(rule__revisions__msg__icontains=searchstring).distinct()
		elif searchfield=='sensor':
			# We get a total count of the number of objects.
			context['itemcount'] = EventFilter.objects.filter(sensor__name__icontains=searchstring).count()
			context['itemcount'] += DetectionFilter.objects.filter(sensor__name__icontains=searchstring).count()
			context['itemcount'] += Suppress.objects.filter(sensor__name__icontains=searchstring).count()
			# We get all the objects.
			eventFilterList = EventFilter.objects.filter(sensor__name__icontains=searchstring)
			detectionFilterList = DetectionFilter.objects.filter(sensor__name__icontains=searchstring)
			suppressList = Suppress.objects.filter(sensor__name__icontains=searchstring)
			
		# We combine all the objects into one big list.
		tuningList = list(chain(eventFilterList,detectionFilterList,suppressList))
	except:
		logger.warning("No sensors found.")
		raise Http404
	
	# We send a ranged set of the objects for processing.
	context['tuningList'] = tuningToTemplate(tuningList[minrange:maxrange])
	# Send to template.
	return render(request, 'tuning/tuningPage.tpl', context)

@login_required
def getFilterForm(request):
	"""This method is loaded when the /tuning/getFilterForm is called. 
	It delivers a form for EventFilters and DetectionFilters. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	try:
		# Get a complete list of sensors.
		context['allsensors'] = Sensor.objects.all()
	
	except Sensor.DoesNotExist:
		logger.warning("No sensors found.")
		raise Http404
	
	# Send to template.
	return render(request, 'tuning/filterForm.tpl', context)

@login_required
def getEventFilterFormByID(request, tuningID):
	"""This method is loaded when the /tuning/getThresholdForm is called. 
	It delivers a form for thresholding. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	context['edit'] = True
	
	try:
		# Get a complete list of sensors.
		context['allsensors'] = Sensor.objects.all()
	
	except Sensor.DoesNotExist:
		logger.warning("No sensors found.")
		raise Http404
	
	try:
		# Get an EventFilter object based on ID.
		context['eventFilter'] = EventFilter.objects.get(id=tuningID)
	except EventFilter.DoesNotExist:
		logger.warning("No EventFilter found.")
		raise Http404
	
	# Send to template.
	return render(request, 'tuning/filterForm.tpl', context)

@login_required
def getDetectionFilterFormByID(request, tuningID):
	"""This method is loaded when the /tuning/getThresholdForm is called. 
	It delivers a form for thresholding. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	context['edit'] = True
	
	try:
		# Get a complete list of sensors.
		context['allsensors'] = Sensor.objects.all()
	
	except Sensor.DoesNotExist:
		logger.warning("No sensors found.")
		raise Http404
	
	try:
		# Get an DetectionFilter object based on ID.
		context['detectionFilter'] = DetectionFilter.objects.get(id=tuningID)
	except EventFilter.DoesNotExist:
		logger.warning("No DetectionFilter found.")
		raise Http404
	
	# Send to template.
	return render(request, 'tuning/filterForm.tpl', context)

@login_required
def getSuppressForm(request):
	"""This method is loaded when the /tuning/getSuppressForm is called. 
	It delivers a form for suppression. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	try:
		# Get a complete list of sensors.
		context['allsensors'] = Sensor.objects.all()
	
	except Sensor.DoesNotExist:
		logger.warning("No sensors found.")
		raise Http404
	
	# Send to template.
	return render(request, 'tuning/suppressForm.tpl', context)

@login_required
def getSuppressFormByID(request, tuningID):
	"""This method is loaded when the /tuning/getSuppressForm is called. 
	It delivers a form for suppression. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	context['edit'] = True
	
	try:
		# Get a complete list of sensors.
		context['allsensors'] = Sensor.objects.all()
	
	except Sensor.DoesNotExist:
		logger.warning("No sensors found.")
		raise Http404
	
	try:
		# Get a Suppress object based on ID.
		context['suppress'] = Suppress.objects.get(id=tuningID)
	except Suppress.DoesNotExist:
		logger.warning("No Suppression found.")
		raise Http404
	
	# Send to template.
	return render(request, 'tuning/suppressForm.tpl', context)

@login_required
def getModifyForm(request):
	"""This method is loaded when the /tuning/getModifyForm is called. 
	It delivers a form for enabling and disabling rulesets. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	try:
		# Get a complete list of sensors.
		context['allsensors'] = Sensor.objects.all()
	
	except Sensor.DoesNotExist:
		logger.warning("No sensors found.")
		raise Http404
	
	# Send to template.
	return render(request, 'tuning/modifyForm.tpl', context)

@login_required
def modifyRule(request):
	"""
	This method processes requests directed at the /tuning/modifyRule/ url. It is used to enable and disable rules and rulesets.
	The request should contain a POST with all required fields.
	It returns JSON objects containing the results.
	"""
	# We set up the logger and a few lists.
	logger = logging.getLogger(__name__)
	response = []
	sids = []
	ruleSets = []
	
	# If the POST contains sids, we're processing rules.
	if request.POST.get('sids'):
		sids = json.loads(request.POST.get('sids'))
	# If the POST contains ruleset, we're processing rulesets.
	if request.POST.get('ruleset'):
		ruleSets = request.POST.getlist('ruleset')
	# Get the mode as well.
	mode = request.POST.get('mode')
	
	# We translate the mode into true or false.
	if mode == "enable":
		active = True
	elif mode == "disable":
		active = False
	else:
		logger.error("Invalid mode '"+str(mode)+"'. Rule(s) not modified.")
		response.append({'response': 'invalidMode', 'text': 'Rule modification failed, invalid mode. \nContact administrator.\n\n'})
		return HttpResponse(json.dumps(response))
	
	# We only need to process rules if there are some in the list.
	if len(sids) == 0:
		response.append({'response': 'noSids'})
	else: 
		# We use this list to return which rules got changed successfully.
		goodsids = []
		# We iterate over the sids provided.
		for sid in sids:
			# If we find the rule, we update its active flag to reflect the new status.
			try:
				r = Rule.objects.filter(SID=sid).update(active=active)
				goodsids.append({'sid': sid, 'mode': mode})
				logger.info("Rule "+str(r)+" is now "+str(mode)+"d.")
			except Rule.DoesNotExist:
				response.append({'response': 'ruleDoesNotExist', 'text': 'Rule '+sid+' could not be found. \nIt has not been modified.\n\n'})
				logger.warning("Rule "+str(sid)+" could not be found.")
				
		response.append({'response': 'ruleModificationSuccess', 'sids': goodsids})
		
	# We only need to process rulesets if there are some in the list.
	if len(ruleSets) == 0:
		response.append({'response': 'noSets'})
	else: 
		# We use this list to return which rulesets got changed successfully.
		goodRuleSets = []
		
		# Global is used to determine if the rulset is to be modified globally or per sensor.
		if request.POST.get('global'):
			globalmodify = request.POST['global']
		else:
			globalmodify = ""
			
		# If its global, we just change the active flag of the ruleset.
		if globalmodify == "on":
			for ruleSet in ruleSets:
				try:
					r = RuleSet.objects.filter(id=ruleSet).update(active=active)
					goodRuleSets.append({'set': ruleSet, 'mode': mode})
					logger.info("RuleSet "+str(r)+" is now "+str(mode)+"d.")
				except RuleSet.DoesNotExist:
					response.append({'response': 'ruleSetDoesNotExist', 'text': 'RuleSet '+ruleSet+' could not be found. \nIt has not been modified.\n\n'})
					logger.warning("RuleSet "+str(ruleSet)+" could not be found.")
					
			response.append({'response': 'ruleSetModificationSuccess', 'sets': goodRuleSets})
			
		# If its not global, we have to iterate over all the sensors provided and add/remove the rulesets.
		else:
			sensors = request.POST.getlist('sensors')
			# If we didnt pick all sensors, we gotta iterate over all the ones we selected. 
			sensorList = []
			allSensor = False
			for sensor in sensors:
				try:
					s = Sensor.objects.get(id=sensor)
					
					if s.name == "All":
						sensorList = [s]
						allSensor = True
						break
					sensorList.append(s)
				except Sensor.DoesNotExist:
					response.append({'response': 'sensorDoesNotExist', 'text': 'Sensor with DB ID '+sensor+' does not exist.'})
					logger.warning("Sensor "+str(sensor)+" could not be found.")
				
			for ruleSet in ruleSets:
				try:
					r = RuleSet.objects.get(id=ruleSet)
					
					if "All" in r.sensors.values_list('name', flat=True):
						allInSet = True
					else:
						allInSet = False
						
					if r.sensors.count():
						setHasSensors = True
					else:
						setHasSensors = False
						
					if active:
						if allSensor and setHasSensors and not allInSet:
							r.sensors.clear
							r.sensors.add(*sensorList) # This is where the ruleset is tied to the sensor.
						elif allSensor and allInSet:
							pass
						else:
							r.sensors.add(*sensorList) # This is where the ruleset is tied to the sensor.
					else:
						if allSensor and setHasSensors:
							r.sensors.clear()
						elif not allSensor and allInSet:
							r.sensors.clear()
							s = Sensor.objects.exclude(name="All").all()
							r.sensors.add(*s)
							r.sensors.remove(*sensorList) # This is where the ruleset is removed from the sensor.
						elif (allSensor and allInSet) or not setHasSensors:
							pass
						else:
							r.sensors.remove(*sensorList) # This is where the ruleset is removed from the sensor.
						
					goodRuleSets.append({'set': ruleSet, 'mode': mode, 'sensor': sensor})
					logger.info("RuleSet "+str(r)+" is now "+str(mode)+"d on sensor "+str(s)+".")
				except RuleSet.DoesNotExist:
					response.append({'response': 'ruleSetDoesNotExist', 'text': 'RuleSet '+ruleSet+' could not be found. \nIt has not been modified.\n\n'})
					logger.warning("RuleSet "+str(ruleSet)+" could not be found.")
				
					
			response.append({'response': 'ruleSetModificationSuccess', 'sets': goodRuleSets})
	
	return HttpResponse(json.dumps(response))

@login_required
def setFilterOnRule(request):
	"""This method is loaded when /tuning/setFilterOnRule is called.
	The request should contain a POST of a form with all required fields. 
	
	The function will check all values for errors and return a warning if something isnt right.
	
	If everything is ok or the force flag is set, it will either update or create the EventFilter objects requested.
	
	It returns JSON objects containing the results.
	
	This method will raise a MultiValueDictKeyError (django.utils.datastructures) when element in request.POST[element] does not exist.
	"""
	
	logger = logging.getLogger(__name__)
	
	# Get some initial post values for processing.
	ruleIds = request.POST.getlist('id')
	sensors = request.POST.getlist('sensors')
	commentString = request.POST['comment']
	force = request.POST['force']
	response = []
	
	# If the ruleIds list is empty, it means a SID has been entered manually.
	if len(ruleIds) == 0:
		# Grab the value from the POST.
		ruleSID = request.POST['sid']
		
		# Match the GID:SID pattern, if its not there, throw exception.
		try:
			matchPattern = r"(\d+):(\d+)"
			pattern = re.compile(matchPattern)
			result = pattern.match(ruleSID)
			
			ruleGID = result.group(1)
			ruleSID = result.group(2)
		except:
			response.append({'response': 'invalidGIDSIDFormat', 'text': 'Please format in the GID:SID syntax.'})
			logger.warning("Invalid GID:SID syntax provided: "+str(ruleSID)+".")
			return HttpResponse(json.dumps(response))
		
		# Try to find a generator object with the GID supplied, if it doesnt exist, throw exception.
		try:
			g = Generator.objects.filter(GID=ruleGID).count() # There might be more than one.
			if g == 0:
				response.append({'response': 'gidDoesNotExist', 'text': 'GID '+ruleGID+' does not exist.'})
				logger.warning("'GID "+str(ruleGID)+" could not be found.")
				return HttpResponse(json.dumps(response))
		except Generator.DoesNotExist:
			response.append({'response': 'gidDoesNotExist', 'text': 'GID '+ruleGID+' does not exist.'})
			logger.warning("'GID "+str(ruleGID)+" could not be found.")
			return HttpResponse(json.dumps(response))
		
		# Try to find a rule object with the SID supplied, if it doesnt exist, throw exception.
		try:
			ruleIds.append(Rule.objects.get(SID=ruleSID).id)
		except Rule.DoesNotExist:
			response.append({'response': 'sidDoesNotExist', 'text': 'SID '+ruleSID+' does not exist.'})
			logger.warning("'SID "+str(ruleSID)+" could not be found.")
			return HttpResponse(json.dumps(response))
		
	# If force is false, it means we have to check everything.				
	if force == "False":
		
		for sensor in sensors:
			try:
				Sensor.objects.get(id=int(sensor))
			except Sensor.DoesNotExist:
				response.append({'response': 'sensorDoesNotExist', 'text': 'Sensor with DB ID '+sensor+' does not exist.'})
				logger.warning("Sensor with DB ID "+str(sensor)+" could not be found.")
				return HttpResponse(json.dumps(response))			
		
		# We iterate through all selected sensors and rules to see if a threshold already exists.
		# We warn the user if there are thresholds. We also check to see if the rule objects selected exist. 	
		for sensor in sensors:
			s = Sensor.objects.get(id=sensor)

			for ruleId in ruleIds:
				try:
					r = Rule.objects.get(id=ruleId)
					if r.eventFilters.filter(sensor=s).count() > 0:
						if len(response) == 0:
							response.append({'response': 'thresholdExists', 'text': 'Thresholds already exists, do you want to overwrite?.', 'sids': []})
						response[0]['sids'].append(r.SID)
						response[0]['sids']=list(set(response[0]['sids']))
				except Rule.DoesNotExist:
					response.append({'response': 'ruleDoesNotExist', 'text': 'Rule with DB ID '+ruleId+' does not exist.'})
					logger.warning("Rule with DB ID "+str(ruleId)+" could not be found.")
					return HttpResponse(json.dumps(response))
			
		# Warn the user if the comment string is empty.
		if commentString == "":
			response.append({'response': 'noComment', 'text': 'You have not set any comments on this action, are you sure you want to proceed?.'})
		
		# Warn the user since all sensors is default.
		if "1" in sensors:
			response.append({'response': 'allSensors', 'text': 'You are setting this threshold on all sensors, are you sure you want to do that?.'})
		
		# If any responses were triggered, return them. Else, we set force to true and implement the threshold.
		if len(response) > 0:
			return HttpResponse(json.dumps(response))
		else:
			force="True"
	
	# The user either wants us to continue or there were no warnings.
	if force == "True":
		filterType = request.POST['filterType']
		tcount = int(request.POST['count'])
		tseconds = int(request.POST['seconds'])
		
		if filterType == 'eventFilter':
			ttype = int(request.POST['type'])
		
			# We make sure type is in the correct range.
			if ttype not in range(1,4):
				response.append({'response': 'typeOutOfRange', 'text': 'Type value out of range.'})
				logger.warning("Type value out of range: "+str(ttype)+".")
				return HttpResponse(json.dumps(response))
	
		ttrack = int(request.POST['track'])
		
		# We make sure track is in the correct range.
		if ttrack not in range(1,3):
			response.append({'response': 'trackOutOfRange', 'text': 'Track value out of range.'})
			logger.warning("Track value out of range: "+str(ttrack)+".")
			return HttpResponse(json.dumps(response))
		
		# If this is an edit, we have to do some things with the comment object.
		if request.POST.get('edit'):
			editid = int(request.POST['edit'])
			if filterType == 'eventFilter':
				try:
					# Grab the object and delete its comment object.
					eFilter = EventFilter.objects.get(id=editid)
					if eFilter.comment is not None:
						comment = Comment.objects.get(id=eFilter.comment.id)
						comment.delete()
					
				except Comment.DoesNotExist:
					logger.warning("Could not find Comment with id "+str(eFilter.comment.id)+".")
				except EventFilter.DoesNotExist:
					logger.warning("Could not find EventFilter with id "+str(editid)+".")
					
			elif filterType == 'detectionFilter':
				try:
					# Grab the object and delete its comment object.
					dFilter = DetectionFilter.objects.get(id=editid)
					if dFilter.comment is not None:
						comment = Comment.objects.get(id=dFilter.comment.id)
						comment.delete()
						
				except Comment.DoesNotExist:
					logger.warning("Could not find Comment with id "+str(dFilter.comment.id)+".")
				except DetectionFilter.DoesNotExist:
					logger.warning("Could not find DetecionFilter with id "+str(editid)+".")
		
		# We iterate over all the rules and sensors to implement the threshold.
		try:
			for ruleId in ruleIds:
				for sensorId in sensors:
					trule = Rule.objects.get(id=ruleId)
					tsensor = Sensor.objects.get(id=int(sensorId))
					
					try:
						if filterType == 'eventFilter':
							comment = Comment.objects.create(user=request.user,comment=commentString, type="newEventFilter")
							arguments = {'rule':trule, 'sensor':tsensor, 'comment':comment, 'eventFilterType':ttype, 'track':ttrack, 'count':tcount, 'seconds':tseconds}
							filterObject = EventFilter.objects.get(rule=trule, sensor=tsensor)
							filterObject.eventFilterType = ttype
						elif filterType == 'detectionFilter':
							comment = Comment.objects.create(user=request.user,comment=commentString, type="newDetectionFilter")
							arguments = {'rule':trule, 'sensor':tsensor, 'comment':comment, 'track':ttrack, 'count':tcount, 'seconds':tseconds}
							filterObject = DetectionFilter.objects.get(rule=trule, sensor=tsensor)
						else:
							raise InvalidValueError(filterType+" is not a valid filter type!")
						
						filterObject.track = ttrack
						filterObject.count = tcount
						filterObject.seconds = tseconds
						filterObject.comment = comment
						filterObject.save()
						logger.info("EventFilter successfully updated on rule: "+str(trule)+".")
													
					except EventFilter.DoesNotExist:
						filterObject = EventFilter.objects.create(**arguments)
						filterObject.save()
						logger.info("event_filter successfully added to rule: "+str(trule)+".")
					except DetectionFilter.DoesNotExist:
						filterObject = DetectionFilter.objects.create(**arguments)
						filterObject.save()
						logger.info("detection_filter successfully added to rule: "+str(trule)+".")
			
			response.append({'response': 'filterAdded', 'text': filterType+' successfully added.'})
		
			return HttpResponse(json.dumps(response))
		except Exception as e: # Something went wrong.
			response.append({'response': 'addFilterFailure', 'text': 'Failed when trying to add filter.'})
			logger.error("Failed when trying to add filter: "+e.message)
			return HttpResponse(json.dumps(response))

@login_required		
def setSuppressOnRule(request):
	"""This method is loaded when the /tuning/setSuppressOnRule is called.
	The request should contain a POST of a form with all required fields. 
	
	The function will check all values for errors and return a warning if something isnt right.
	
	If everything is ok or the force flag is set, it will either update or create the Suppress objects requested.
	
	It returns JSON objects containing the results.
	"""
	
	logger = logging.getLogger(__name__)
	
	# Get some initial post values for processing.
	ruleIds = request.POST.getlist('id')
	sensors = request.POST.getlist('sensors')
	commentString = request.POST['comment']
	force = request.POST['force']
	response = []
	
	# If the ruleIds list is empty, it means a SID has been entered manually.
	if len(ruleIds) == 0:
		# Grab the value from the POST.
		ruleSID = request.POST['sid']
		
		# Match the GID:SID pattern, if its not there, throw exception.
		try:
			matchPattern = r"(\d+):(\d+)"
			pattern = re.compile(matchPattern)
			result = pattern.match(ruleSID)
			
			ruleGID = result.group(1)
			ruleSID = result.group(2)
		except:
			response.append({'response': 'invalidGIDSIDFormat', 'text': 'Please format in the GID:SID syntax.'})
			logger.warning("Invalid GID:SID syntax provided: "+str(ruleSID)+".")
			return HttpResponse(json.dumps(response))
		
		# Try to find a generator object with the GID supplied, if it doesnt exist, throw exception.
		try:
			g = Generator.objects.filter(GID=ruleGID).count() # There might be more than one.
			if g == 0:
				response.append({'response': 'gidDoesNotExist', 'text': 'GID '+ruleGID+' does not exist.'})
				logger.warning("'GID "+str(ruleGID)+" could not be found.")
				return HttpResponse(json.dumps(response))
		except Generator.DoesNotExist:
			response.append({'response': 'gidDoesNotExist', 'text': 'GID '+ruleGID+' does not exist.'})
			logger.warning("'GID "+str(ruleGID)+" could not be found.")
			return HttpResponse(json.dumps(response))
		
		# Try to find a rule object with the SID supplied, if it doesnt exist, throw exception.
		try:
			ruleIds.append(Rule.objects.get(SID=ruleSID).id)
		except Rule.DoesNotExist:
			response.append({'response': 'sidDoesNotExist', 'text': 'SID '+ruleSID+' does not exist.'})
			logger.warning("'SID "+str(ruleSID)+" could not be found.")
			return HttpResponse(json.dumps(response))
	
	# If force is false, it means we have to check everything.	
	if force == "False":
		
		sensorList = []
		
		# If we didnt pick all sensors, we gotta check to see if the selected ones exist. 
		# We also populate a list for later use.

			
		# If we selected all sensors, generate a list of all of their ids.
		
		for sensor in sensors:
			try:
				Sensor.objects.get(id=int(sensor))
				sensorList.append(sensor)
			except Sensor.DoesNotExist:
				response.append({'response': 'sensorDoesNotExist', 'text': 'Sensor with DB ID '+str(sensor)+' does not exist.'})
				logger.warning("Sensor with DB ID "+str(sensor)+" could not be found.")
				return HttpResponse(json.dumps(response))	
		
		# We iterate through all selected sensors and rules to see if a threshold already exists.
		# We warn the user if there are thresholds. We also check to see if the rule objects selected exist. 	
		for sensor in sensorList:
			s = Sensor.objects.get(id=sensor)
			for ruleId in ruleIds:
				try:
					r = Rule.objects.get(id=ruleId)
					if r.suppress.filter(sensor=s).count() > 0:
						if len(response) == 0:
							response.append({'response': 'suppressExists', 'text': 'Suppressions already exists, do you want to overwrite?.', 'sids': []})
						response[0]['sids'].append(r.SID)
						response[0]['sids']=list(set(response[0]['sids']))
				except Rule.DoesNotExist:
					response.append({'response': 'ruleDoesNotExist', 'text': 'Rule with DB ID '+ruleId+' does not exist.'})
					logger.warning("Rule with DB ID "+str(ruleId)+" could not be found.")
					return HttpResponse(json.dumps(response))
		
		# Since this form lets the user input one or more IPv4 addresses, we have to check them.
		ipString = request.POST['ip']
		
		# The string cant be empty.
		if ipString == "":
			response.append({'response': 'noIPGiven', 'text': 'You need to supply one or more IP addresses.'})
			return HttpResponse(json.dumps(response))
		
		badIps = []
		badIpTest = False
		
		# This pattern matches for valid IPv4 with subnet notation (0.0.0.0/0 - 255.255.255.255/32).
		ipPattern = re.compile(patterns.ConfigPatterns.VALIDIPMASK)
		
		# Iterate over each IP given and check it for validity.
		for ip in re.finditer("[^,;\s]+", ipString):
			test = ipPattern.match(ip.group(0))
			if not test:
				badIps.append(ip.group(0))
				badIpTest = True
		
		# Express error if one of the IPs is invalid as IPv4.
		if badIpTest:
			response.append({'response': 'badIP', 'text': 'is not valid IPv4.', 'ips': badIps})
			logger.warning("User provided bad IP format.")
			
		# Warn the user if the comment string is empty.
		if commentString == "":
			response.append({'response': 'noComment', 'text': 'You have not set any comments on this action, are you sure you want to proceed?.'})
		
		# Warn the user since all sensors is default.
		if "1" in sensors:
			response.append({'response': 'allSensors', 'text': 'You are setting this suppression on all sensors, are you sure you want to do that?.'})
		
		# If any responses were triggered, return them. Else, we set force to true and implement the threshold.
		if len(response) > 0:
			return HttpResponse(json.dumps(response))
		else:
			force="True"
	
	# The user either wants us to continue or there were no warnings.
	if force == "True":
		strack = int(request.POST['track'])
		
		# We make sure track is in the correct range.
		if strack not in range(1,3):
			response.append({'response': 'trackOutOfRange', 'text': 'Track value out of range.'})
			logger.warning("Track value out of range: "+str(strack)+".")
			return HttpResponse(json.dumps(response))
		
		# We do the IP matching again since we could have submitted them again since last check.
		# Since this form lets the user input one or more IPv4 addresses, we have to check them.
		ipString = request.POST['ip']
		
		# The string cant be empty.
		if ipString == "":
			response.append({'response': 'noIPGiven', 'text': 'You need to supply one or more IP addresses.'})
			logger.warning("User provided bad IP format.")
			return HttpResponse(json.dumps(response))
		
		goodIps = []
		
		# This pattern matches for valid IPv4 with subnet notation (0.0.0.0/0 - 255.255.255.255/32).
		ipPattern = re.compile(patterns.ConfigPatterns.VALIDIPMASK)
		
		# Iterate over each IP given and check it for validity.
		# We put it in the list we use for making SuppressAddresses later.
		for ip in re.finditer("[^,;\s]+", ipString):
			test = ipPattern.match(ip.group(0))
			if test:
				goodIps.append(ip.group(0))
				
		suppressAddressList = []
		
		# We iterate over all IPs that were good and create SuppressAddress objects and put them in the 
		# suppressAddressList we use for creating Suppress objects later.
		# We also check if the IP already has a SuppressAddress object and just put that in the suppressAddressList.
		try:
			for ip in goodIps:
				sa = SuppressAddress.objects.filter(ipAddress=ip).count()
				if sa > 0:
					suppressAddressList.append(SuppressAddress.objects.get(ipAddress=ip))
				else:
					sa = SuppressAddress.objects.create(ipAddress=ip)
					logger.info("SuppressAddress successfully created for IP: "+str(ip)+".")
					suppressAddressList.append(sa)
				
		except:
			response.append({'response': 'addSuppressAddressFailure', 'text': 'Failed when trying to add suppression addresses.'})
			logger.error("Failed when trying to add suppression addresses.")
			return HttpResponse(json.dumps(response))
		
		# If this is an edit, we have to do some things with the comment object.
		if request.POST.get('edit'):
			editid = int(request.POST['edit'])
			try:
				# Grab the object and delete its comment object.
				suppress = Suppress.objects.get(id=editid)
				if suppress.comment is not None:
					comment = Comment.objects.get(id=suppress.comment.id)
					comment.delete()
					
			except Comment.DoesNotExist:
				logger.warning("Could not find Comment with id "+str(suppress.comment.id)+".")
			except Suppress.DoesNotExist:
				logger.warning("Could not find Suppress with id "+str(editid)+".")
		
		
		

		# We iterate over all the rules and sensors to implement the suppression.
		try:
			for ruleId in ruleIds:
				for sensorId in sensors:
					srule = Rule.objects.get(id=ruleId)
					ssensor = Sensor.objects.get(id=int(sensorId))
					try:
						comment = Comment.objects.create(user=request.user,comment=commentString, type="newSuppression")
					except:
						logger.warning("Could not create Comment.")
					# We check to see if a suppression already exists, in that case we just update it. If not, we create one.
					try:
						s = Suppress.objects.get(rule=srule, sensor=ssensor)

						s.comment = comment
						s.track = strack
						for address in suppressAddressList:
							s.addresses.add(address)
						s.save()
						logger.info("Suppression successfully updated on rule: "+str(srule)+".")
					except Suppress.DoesNotExist:
						s = Suppress.objects.create(rule=srule, sensor=ssensor, comment=comment, track=strack)

						for address in suppressAddressList:
							s.addresses.add(address)
						s.save()
						logger.info("Suppression successfully created on rule: "+str(srule)+".")
			
			response.append({'response': 'suppressAdded', 'text': 'Suppression successfully added.'})
			return HttpResponse(json.dumps(response))
		except: # Something went wrong.
			response.append({'response': 'addSuppressFailure', 'text': 'Failed when trying to add suppressions.'})
			logger.error("Failed when trying to add suppressions.")
			return HttpResponse(json.dumps(response))

@login_required
def deleteTuning(request):
	"""This method is loaded when the /tuning/deleteTuning is called.
	The request should contain a POST of a form with all required fields. 
	
	It will delete the tuning objects specified, if everything checks out.
	
	It returns JSON objects containing the results.
	"""
	
	logger = logging.getLogger(__name__)
	
	response = []
	
	# We check to see if there are ruleset IDs given.
	if request.POST.getlist('id'):
		tuningIDs = request.POST.getlist('id')
	else:
		response.append({'response': 'noIDsGiven', 'text': 'No Tuning ID was given, deletion cancelled.'})
		return HttpResponse(json.dumps(response))
	
	# We iterate over the IDs given and delete them.
	for tuningID in tuningIDs:
		
		# The ID is given in a tuningID-tuningType pattern, so we have to match it.
		matchPattern = r"(\d+)-(\w+)"
		pattern = re.compile(matchPattern)
		result = pattern.match(tuningID)
		
		tuning = result.group(1)
		tuningType = result.group(2)
		
		# Based on the tuningType, we get the object if it exists and delete it and its comment object. 
		if tuningType == "EventFilter":
			try:
				eFilter = EventFilter.objects.get(id=tuning)
				if eFilter.comment is not None:
					eFilter.comment.delete()
				eFilter.delete()
			except EventFilter.DoesNotExist:
				logger.warning("Could not find EventFilter with id "+str(tuningID)+".")
				response.append({'response': 'tuningDoesNotExists', 'text': 'Could not find EventFilter with id '+str(tuningID)+'.'})
				return HttpResponse(json.dumps(response))
				
		elif tuningType == "DetectionFilter":
			try:
				dFilter = DetectionFilter.objects.get(id=tuning)
				if dFilter.comment is not None:
					dFilter.comment.delete()
				dFilter.delete()
			except DetectionFilter.DoesNotExist:
				logger.warning("Could not find DetectionFilter with id "+str(tuningID)+".")
				response.append({'response': 'tuningDoesNotExists', 'text': 'Could not find DetectionFilter with id '+str(tuningID)+'.'})
				return HttpResponse(json.dumps(response))
		elif tuningType == "Suppression":
			try:
				suppress = Suppress.objects.get(id=tuning)
				if suppress.comment is not None:
					suppress.comment.delete()
				suppress.delete()
			except Suppress.DoesNotExist:
				logger.warning("Could not find Suppress with id "+str(tuningID)+".")
				response.append({'response': 'tuningDoesNotExists', 'text': 'Could not find Suppress with id '+str(tuningID)+'.'})
				return HttpResponse(json.dumps(response))
		else:
			logger.warning("Invalid tuningType: "+str(tuningType)+".")
			response.append({'response': 'invalidTuningType', 'text': 'Invalid tuningType: '+str(tuningType)+'.'})
			return HttpResponse(json.dumps(response))
			
	response.append({'response': 'tuningSuccessfulDeletion', 'text': 'Tuning was successfully deleted.'})
	return HttpResponse(json.dumps(response))



















