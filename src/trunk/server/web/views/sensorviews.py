import json
import logging
import os
import re
import subprocess

from django.contrib.auth.models import User, Group
from django.http import Http404, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from core.models import Sensor
from util.config import Config
from util.configgenerator import ConfigGenerator
from util import patterns
from web.utilities import sensorsToFormTemplate

@login_required
def index(request):
	parent = Sensor.objects.get(name="All")
	data = {}
	data['sensors'] = Sensor.objects.filter(parent=parent).order_by('name')
	data['isMain'] = True
	#data['sensors'] = sensorsToTemplate(data['sensors'])
	return render(request, "sensor/index.tpl", data)

@login_required
def getSensorChildren(request, sensorID):
	data = {}
	parent = Sensor.objects.get(id=sensorID)
	data['sensors'] = Sensor.objects.exclude(name="All").order_by('name').filter(parent=parent)
	data['isMain'] = False
	#data['sensors'] = sensorsToTemplate(data['sensors'])
	return render(request, "sensor/sensorList.tpl", data)

@login_required
def getCreateSensorForm(request):
	parent = Sensor.objects.get(name="All")
	data = {}
	data['sensors'] = Sensor.objects.exclude(name="All").order_by('name').filter(parent=parent)
	
	data['sensors'] = sensorsToFormTemplate(data['sensors'], 0)
	return render(request, "sensor/createSensorForm.tpl", data)

@login_required
def getEditSensorForm(request, sensorID):
	data = {}
	data['sensor'] = Sensor.objects.get(id=sensorID)
	if data['sensor'].parent:
		data['sensorParent'] = data['sensor'].parent.id
	else:
		data['sensorParent'] = None
	
	if data['sensor'].childSensors.count() > 0:
		data['sensorChildren'] =  data['sensor'].childSensors.values_list('id', flat=True)
	else:
		data['sensorChildren'] = None
	data['sensors'] = Sensor.objects.exclude(name="All").order_by('name').filter(parent=None)
	data['sensors'] = sensorsToFormTemplate(data['sensors'], 0)
	return render(request, "sensor/editSensorForm.tpl", data)

@login_required
def downloadRuleSet(request, sensorID):
	sensor = get_object_or_404(Sensor, pk=sensorID)
	cg = ConfigGenerator(sensor)
	ruleArchive = cg.generateConfig()
	
	fsock = open(ruleArchive, 'r')
	os.unlink(ruleArchive)

	response = HttpResponse(fsock, mimetype='application/x-tgz')
	response['Content-Disposition'] = "attachment; filename=%s" % (os.path.basename(ruleArchive))
	
	return response

@login_required
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
				
				group = Group.objects.get(name="Sensors")
				group.user_set.add(user)
				
				try:
					sensor = Sensor.objects.get(name=sensorName)
				except Sensor.DoesNotExist:
					if request.POST['children'] == "None":
						children = False
					elif request.POST.getlist('children'):
						children = request.POST.getlist('children')
						if "None" in children:
							children.remove("None")
					else:
						children = False
						
					if request.POST.get('auto'):
						autonomous = True
					else:
						autonomous = False	
					
					sensorAll = Sensor.objects.get(name="All")
					sensor = Sensor.objects.create(name=sensorName, parent=sensorAll, ipAddress=sensorIP, autonomous=autonomous, 
														user=user, active=True)
					
					if children:
						for child in children:
							try:
								c = Sensor.objects.get(id=child)
								sensor.childSensors.add(c)
								logger.info("Sensor "+str(c)+" is now child of Sensor "+str(sensor)+".")
							except:
								logger.debug("Could not find Sensor with DB ID: "+child+".")
					
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

@login_required
def editSensor(request):
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
		sensorID = request.POST.get('id')
	else:
		response.append({'response': 'noSensorID', 'text': 'The POST did not deliver a Sensor ID.'})
		return HttpResponse(json.dumps(response))
	
	try:
		sensor = Sensor.objects.get(id=sensorID)
	except Sensor.DoesNotExist:
		response.append({'response': 'sensorDoesNotExists', 'text': 'Sensor ID '+sensorID+' could not be found.'})
		logger.warning("Sensor ID "+sensorID+" could not be found.")
		return HttpResponse(json.dumps(response))
	
	if request.POST.get('name'):
		sensorName = request.POST.get('name')
	else:
		logger.warning("No sensor name was given.")
		response.append({'response': 'noName', 'text': 'No sensor name was given.'})
		return HttpResponse(json.dumps(response))
	
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
	
	if request.POST.get('auto'):
		autonomous = True
	else:
		autonomous = False
	
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
	
	if sensor.name != sensorName: 
		user = sensor.user
		try: 
			User.objects.get(username=sensorName)
			response.append({'response': 'userNameExists', 'text': 'That Sensor name already exists, try another.'})
			return HttpResponse(json.dumps(response))
		except User.DoesNotExist:
			user.name = sensorName
			sensor.name = sensorName
		logger.info("Sensor "+str(sensor)+" has been renamed.")
		edited = True
	
	if sensor.ipAddress != sensorIP:
		sensor.ipAddress = sensorIP
		logger.info("RuleSet "+str(sensor)+" has changed IP.")
		edited = True
		
	if sensor.autonomous != autonomous:
		sensor.autonomous = autonomous
		logger.info("Sensor "+str(sensor)+" has changed autonomous.")
		edited = True
		
	# If the sensor is not to have a parent, we set the parent to be None.
	if not parent:
		sensor.parent = Sensor.objects.get(name="All")
		logger.info("Sensor "+str(sensor)+" no longer has a parent.")
		edited = True
	
	# If the sensor is assigned a new parent, we assign the parent to the sensor.
	elif (sensor.parent == None and parent) or (sensor.parent and int(sensor.parent.id) != int(parent)):
		# We check to see if the parent exists.
		try:
			sensorParent = Sensor.objects.get(id=parent)
		except Sensor.DoesNotExist:
			response.append({'response': 'sensorDoesNotExists', 'text': 'Sensor ID '+sensorParent+' could not be found.'})
			logger.warning("Sensor ID "+str(sensorParent)+" could not be found.")
			return HttpResponse(json.dumps(response))
		
		# We make sure the sensor isnt setting itself as a parent.
		if sensorParent != sensor:
			sensor.parent = sensorParent
			logger.info("RuleSet "+str(sensorParent)+" is now the parent of "+str(sensor)+".")
			edited = True
		elif sensorParent == sensor:
			response.append({'response': 'sensorParentInbreeding', 'text': 'Inbreeding problem:\nA Sensor cannot become its own parent.'})
			return HttpResponse(json.dumps(response))
		
	# We get the sensors current list of children.	
	sensorChildren = sensor.childSensors.values_list('id', flat=True)
	
	# If the sensor is given children but doesnt have any atm.
	if children and not len(sensorChildren):
		sensorChildren = []
		# We iterate over the children to make sure they all exist and put them in the list.
		try:
			for child in children:
				sensorChildren.append(Sensor.objects.get(id=child))
		except Sensor.DoesNotExist:
			response.append({'response': 'sensorDoesNotExists', 'text': 'Sensor list of IDs '+children+' could not be found.'})
			logger.warning("Sensor list of IDs "+str(children)+" could not be found.")
			return HttpResponse(json.dumps(response))
		
		# We get the parent of the sensor.
		sensorParent = sensor.parent
		
		# We iterate over the children again to add them to the sensor.
		for child in sensorChildren:
			inbreeding = False
			
			# We make sure the new child isnt one of the current sensors parents. Grandfather-paradox.
			while sensorParent != None:
				if sensorParent == child:
					inbreeding = True
				sensorParent = sensorParent.parent
			
			# If there was no inbreeding and the child isnt the sensor itself, we add it to the list of children.
			if not inbreeding and child != sensor:
				sensor.childSensors.add(child)
				edited = True
				
			
			# If there was some form of inbreeding.
			elif inbreeding or child == sensor:
				response.append({'response': 'sensorChildInbreeding', 'text': 'Inbreeding problem:\nA Sensor cannot become its own child. \nA Sensors parent cannot become its child.'})
				return HttpResponse(json.dumps(response))
	
	
	# If the sensor is given children and they are different from the current children.	
	elif children and set(children) != set(sensorChildren):
		
		oldSensorChildren = []
		newSensorChildren = []
		
		# We verify that all children exist and make two lists of both the new children and the current children of the sensor.
		try:
			for child in sensorChildren:
				oldSensorChildren.append(Sensor.objects.get(id=child))
			for child in children:
				newSensorChildren.append(Sensor.objects.get(id=child))
		except Sensor.DoesNotExist:
			response.append({'response': 'sensorDoesNotExists', 'text': 'Sensor list of IDs '+children+' could not be found.'})
			logger.warning("Sensor list of IDs "+children+" could not be found.")
			return HttpResponse(json.dumps(response))
		
		# If there are old children that are not in the new children list, we remove them from the sensors current children.
		for child in oldSensorChildren:
			if child not in newSensorChildren:
				sensor.childSensors.remove(child)
				edited = True
				
				logger.info("Sensor "+str(sensor)+" is no longer the parent of "+str(child)+".")
		
		# We get the parent of the sensor.
		setParent = sensor.parent
		
		# We iterate over the children again to add them to the sensor.
		for child in newSensorChildren:
			# We only add a new child if it isnt in the old child list.
			if child not in oldSensorChildren:
				inbreeding = False
				
				# We make sure the new child isnt one of the current sensors parents. Grandfather-paradox.
				while setParent != None:
					if setParent == child:
						inbreeding = True
					setParent = setParent.parent
				
				# If there was no inbreeding and the child isnt the sensor itself, we add it to the list of children.	
				if not inbreeding and child != sensor:
					sensor.childSensors.add(child)
					edited = True
					logger.info("Sensor "+str(sensor)+" is now the parent of "+str(child)+".")
				# If there was some form of inbreeding.
				elif inbreeding or child == sensor:
					response.append({'response': 'ruleSetChildInbreeding', 'text': 'Inbreeding problem:\nA Sensor cannot become its own child. \nA Sensors parent cannot become its child.'})
					return HttpResponse(json.dumps(response))
			
	# If the sensor is to not have any children and has children, we clear any current relations.
	elif (not children and len(sensorChildren) > 0 ):
		sensor.childSensors.clear()
		logger.info("Sensor "+str(sensor)+" no longer has children.")
		edited = True
		
	if edited:
		sensor.save()
		response.append({'response': 'successfulSensorEdit', 'text': 'The Sensor was edited successfully.'})
	else:
		response.append({'response': 'sensorNoChanges', 'text': 'Edit complete, no changes.'})
		
	
	return HttpResponse(json.dumps(response))

@login_required
def deleteSensor(request):
	
	"""This method is called when the url /ruleset/editRuleSet/ is called.
	It takes a set of variables through POST and then deletes RuleSet objects based on them.
	It returns JSON objects of the results.
	"""
	
	# We set up the logger and a few lists.
	logger = logging.getLogger(__name__)
	response = []
	
	# We check to see if there are sensor IDs given.
	if request.POST.getlist('id'):
		sensorIDs = request.POST.getlist('id')
	else:
		response.append({'response': 'noIDsGiven', 'text': 'No Sensor ID was given, deletion cancelled.'})
		return HttpResponse(json.dumps(response))
	
	# We iterate over the sensor IDs given.
	for sensorID in sensorIDs:
		# We check to see if the sensor exists first.
		try:
			sensor = Sensor.objects.get(id=sensorID)

		except Sensor.DoesNotExist:
			response.append({'response': 'sensorDoesNotExists', 'text': 'Sensor ID '+sensorID+' could not be found.'})
			logger.warning("Sensor ID "+str(sensorID)+" could not be found.")
			return HttpResponse(json.dumps(response))
	
		# If the sensor has children, we have to deal with their relations.
		if sensor.childSensors.count() > 0:
				for child in sensor.childSensors.all():
					# We give set all the childrens parent to be the deleted sensors parent.
					child.parent = sensor.parent
					child.save()
					logger.info("Sensor "+str(child)+" is now child of Sensor "+str(sensor.parent)+".")
		
		# We remove the parent relation.	
		sensor.parent = None
		sensor.save()
		
		# This must be done before the actual deletion, lest the object wont exist.
		logger.info("Sensor "+str(sensor)+" has been deleted.")
		user = User.objects.get(username=sensor.name)
		logger.info("User "+str(user)+" has been deleted.")
		# We delete the sensor.
		user.delete()
		sensor.delete()
	
	response.append({'response': 'sensorSuccessfulDeletion', 'text': 'Sensors was successfully deleted.'})
	return HttpResponse(json.dumps(response))

@login_required
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

@login_required
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


@login_required
def syncAllSensors(request):
	
	allOK =[]
	
	for sensor in Sensor.objects.exclude(name="All").filter(active=True,autonomous=False):
		try:
			allOK.append(sensor.requestUpdate())
		except:
			allOK.append(False)
		
	if False in allOK:
		return HttpResponse(False)
	else:
		return HttpResponse(True)
