import json
import logging
import os
import re
import subprocess

from django.contrib.auth.models import User
from django.http import Http404, HttpResponse
from django.shortcuts import render

from core.models import Sensor
from util.config import Config
from util import patterns
from web.utilities import sensorsToTemplate, sensorsToFormTemplate


def index(request):
	data = {}
	data['sensors'] = Sensor.objects.exclude(name="All").order_by('name').filter(parent=None)
	data['isMain'] = True
	#data['sensors'] = sensorsToTemplate(data['sensors'])
	return render(request, "sensor/index.tpl", data)

def getSensorChildren(request, sensorID):
	data = {}
	parent = Sensor.objects.get(id=sensorID)
	data['sensors'] = Sensor.objects.exclude(name="All").order_by('name').filter(parent=parent)
	data['isMain'] = False
	#data['sensors'] = sensorsToTemplate(data['sensors'])
	return render(request, "sensor/sensorList.tpl", data)

def getCreateSensorForm(request):
	data = {}
	data['sensors'] = Sensor.objects.exclude(name="All").order_by('name').filter(parent=None)
	
	data['sensors'] = sensorsToFormTemplate(data['sensors'], 0)
	return render(request, "sensor/createSensorForm.tpl", data)

def createSensor(request):
	logger = logging.getLogger(__name__)
	response = []
	if(request.POST):
		
		if request.POST.get('ip'):
			sensorIP = request.POST.get('ip')
			ipPattern = re.compile(patterns.ConfigPatterns.VALIDIP)
			test = ipPattern.match(sensorIP)
			if not test:
				response.append({'response': 'badIP', 'text': 'IP given is not valid IPv4.'})
				logger.warning("User provided bad IP format.")
				return HttpResponse(json.dumps(response))
		else:
			sensorIP = None
		
		if request.POST.get('name'):
			sensorName = request.POST.get('name')
			try:
				user = User.objects.get(username=sensorName)
				
			except User.DoesNotExist:
				user = User.objects.create(username=sensorName, first_name=sensorName, last_name="SENSOR")
				password = User.objects.make_random_password()
				user.set_password(password)
				user.save()
				logger.info("Created user "+str(user)+"")
				try:
					sensor = Sensor.objects.get(name=sensorName)
				except Sensor.DoesNotExist:
					
					if request.POST.get('auto'):
						autonomous = True
					else:
						autonomous = False	
					
					sensor = Sensor.objects.create(name=sensorName, ipAddress=sensorIP, autonomous=autonomous, user=user, active=True)
					logger.info("Created sensor "+str(sensor)+"")
					response.append({'response': 'sensorCreationSuccess', 'text': 'The sensor was successfully created.', 'password': password})
				else:
					response.append({'response': 'sensorNameExists', 'text': 'Sensor name already exists, please select another.'})
					return HttpResponse(json.dumps(response))
			else:
				response.append({'response': 'sensorNameExists', 'text': 'Sensor name already exists, please select another.'})
				return HttpResponse(json.dumps(response))
		else:
			logger.warning("No sensor name was given.")
			response.append({'response': 'noName', 'text': 'No sensor name was given.'})
			return HttpResponse(json.dumps(response))
	else:
		logger.warning("No data was given in POST.")
		response.append({'response': 'noPOST', 'text': 'No data was given in POST.'})

	return HttpResponse(json.dumps(response))

def regenerateSecret(request):
	data = {}
	data['status'] = False
	if(request.POST and "sid" in request.POST):
		try:
			sensor = Sensor.objects.get(pk=int(request.POST['sid']))
			data['password'] = User.objects.make_random_password()
			sensor.user.set_password(data['password'])
			sensor.user.save()
			data['message'] = "Secret is regenerated"
			data['sid'] = sensor.id
			data['status'] = True
		except Sensor.DoesNotExist:
			data['message'] = "Invalid request"
	else:
		data['message'] = "Invalid request"

	return HttpResponse(json.dumps(data), content_type="application/json")

def requestUpdate(request):
	data = {}
	data['status'] = False

	if(request.POST and "sid" in request.POST):
		try:
			sensor = Sensor.objects.get(pk=int(request.POST['sid']))
			data.update(sensor.requestUpdate())
		except Sensor.DoesNotExist:
			data['message'] = "Invalid request"
	else:
		data['message'] = "Invalid request"
	
	return HttpResponse(json.dumps(data), content_type="application/json")
