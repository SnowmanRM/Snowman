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
from web.views.sensorforms import NewSensorForm

def index(request):
	data = {}
	data['sensors'] = Sensor.objects.exclude(name="All").order_by('name').all()
	data['newSensorForm'] = NewSensorForm()
	return render(request, "sensor/index.tpl", data)

def new(request):
	data = {}
	data['status'] = False
	
	if(request.POST):
		form = NewSensorForm(request.POST)
		if(form.is_valid()):
			try:
				user = User.objects.get(username=form.cleaned_data['name'])
			except User.DoesNotExist:
				user = User.objects.create(username=form.cleaned_data['name'], first_name=form.cleaned_data['name'], last_name="SENSOR")
				data['password'] = User.objects.make_random_password()
				user.set_password(data['password'])
				user.save()
				
				sensor = Sensor.objects.create(name=form.cleaned_data['name'], ipAddress=form.cleaned_data['ipAddress'], autonomous=form.cleaned_data['autonomous'], user=user, active=True)
				data['message'] = "Sensor is created"
				data['status'] = True
				data['id'] = sensor.id
			else:
				data['message'] = "Sensor with the name %s already exists." % form.cleaned_data['name']
		else:
			data['message'] = "Invalid data supplied"
	else:
		data['message'] = "ERROR: No data posted"

	return HttpResponse(json.dumps(data), content_type="application/json")

def getSensorList(request):
	data = {}
	data['sensors'] = Sensor.objects.exclude(name='All').order_by('name').all()
	return render(request, "sensor/sensorList.tpl", data)

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
