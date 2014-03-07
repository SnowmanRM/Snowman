from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision, Sensor, Generator
from tuning.models import Threshold
from web.utilities import UserSettings
import logging, json, re


def getThresholdForm(request):
	"""This method is loaded when the /tuning/getSuppressForm is called. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	try:
	# Get the current sensor count, but we want it in a negative value.
	
		context['allsensors'] = Sensor.objects.all()
	
	except Sensor.DoesNotExist:
		logger.warning("No sensors found.")
		raise Http404
	
	return render(request, 'tuning/thresholdForm.tpl', context)

def getSuppressForm(request):
	"""This method is loaded when the /tuning/getSuppressForm is called. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	try:
	# Get the current sensor count, but we want it in a negative value.
	
		context['allsensors'] = Sensor.objects.all()
	
	except Sensor.DoesNotExist:
		logger.warning("No sensors found.")
		raise Http404
	
	return render(request, 'tuning/suppressForm.tpl', context)

def setThresholdOnRule(request):
	
	ruleIds = request.POST.getlist('id')
	sensors = request.POST.getlist('sensors')
	commentString = request.POST['comment']
	force = request.POST['force']
	response = []
	
	if len(ruleIds) == 0:
		ruleSID = request.POST['sid']
		
		try:
			matchPattern = r"(\d+):(\d+)"
			pattern = re.compile(matchPattern)
			result = pattern.match(ruleSID)
			
			ruleGID = result.group(1)
			ruleSID = result.group(2)
		except:
			response.append({'response': 'invalidGIDSIDFormat', 'text': 'Please format in the GID:SID syntax.'})

			return HttpResponse(json.dumps(response))
		
		try:
			Generator.objects.get(GID=ruleGID)
		except Generator.DoesNotExist:
			response.append({'response': 'gidDoesNotExist', 'text': 'GID '+ruleGID+' does not exist.'})
			return HttpResponse(json.dumps(response))
		try:
			ruleIds.append(Rule.objects.get(SID=ruleSID).id)
		except Rule.DoesNotExist:
			response.append({'response': 'sidDoesNotExist', 'text': 'SID '+ruleSID+' does not exist.'})
			return HttpResponse(json.dumps(response))
		
					
	if force == "False":
		
		if sensors[0] != "all":
			for sensor in sensors:
				try:
					Sensor.objects.get(id=sensor)
				except Sensor.DoesNotExist:
					response.append({'response': 'SensorDoesNotExist', 'text': 'Sensor with DB ID '+sensor+' does not exist.'})
					return HttpResponse(json.dumps(response))	
		
		for ruleId in ruleIds:
			try:
				r = Rule.objects.get(id=ruleId)
				if r.thresholds.count() > 0:
					if len(response) == 0:
						response.append({'response': 'thresholdExists', 'text': 'Thresholds already exists, do you want to overwrite?.', 'sids': []})
					response[0]['sids'].append(r.SID)
			except Rule.DoesNotExist:
				response.append({'response': 'ruleDoesNotExist', 'text': 'Rule with DB ID '+ruleId+' does not exist.'})
				return HttpResponse(json.dumps(response))
			
		if commentString == "":
			response.append({'response': 'noComment', 'text': 'You have not set any comments on this action, are you sure you want to proceed?.'})
		
		if sensors[0] == "all":
			response.append({'response': 'allSensors', 'text': 'You are setting this threshold on all sensors, are you sure you want to do that?.'})
			return HttpResponse(json.dumps(response))
		
		if len(response) > 0:
			return HttpResponse(json.dumps(response))
		else:
			force="True"
			
	if force == "True":
		tcount = int(request.POST['count'])
		tseconds = int(request.POST['seconds'])
		
		ttype = int(request.POST['type'])
		
		if ttype not in range(1,4):
			response.append({'response': 'typeOutOfRange', 'text': 'Type value out of range.'})
			return HttpResponse(json.dumps(response))
	
		ttrack = int(request.POST['track'])
		
		if ttrack not in range(1,3):
			response.append({'response': 'trackOutOfRange', 'text': 'Track value out of range.'})
			return HttpResponse(json.dumps(response))
		
		if sensors[0] == "all":
			sensors = Sensor.objects.values_list('id', flat=True)
		
		try:
			for ruleId in ruleIds:
				for sensorId in sensors:
					trule = Rule.objects.get(id=ruleId)
					tsensor = Sensor.objects.get(id=sensorId)
					t = Threshold.objects.filter(rule=trule, sensor=tsensor).count();
					if t > 0:
						Threshold.objects.filter(rule=trule, sensor=tsensor).update(comment=commentString, thresholdType=ttype, track=ttrack, count=tcount, seconds=tseconds)
					elif t == 0:
						t = Threshold(rule=trule, sensor=tsensor, comment=commentString, thresholdType=ttype, track=ttrack, count=tcount, seconds=tseconds)
						t.save()
			
			response.append({'response': 'thresholdAdded', 'text': 'Threshold successfully added.'})
			return HttpResponse(json.dumps(response))
		except:
			response.append({'response': 'addThresholdFailure', 'text': 'Failed when trying to add thresholds.'})
			return HttpResponse(json.dumps(response))
		
	
	
