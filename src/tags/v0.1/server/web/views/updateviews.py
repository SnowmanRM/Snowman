"""
The views related to the update-pages.
"""
import logging
import os
import subprocess
import time

from django.http import Http404
from django.shortcuts import render

from srm.settings import BASE_DIR
from update.models import Source
from update.tasks import UpdateTasks
from util.config import Config
from web.views.updateforms import ManualUpdateForm, DailySelector, WeeklySelector, MonthlySelector, NewSourceForm

def index(request):
	"""The default view for the update section."""
	data = {}
	
	# Create a list over sources, and their last 5 updates.
	data['sources'] = []
	for source in Source.objects.all():
		d = {}
		d['source'] = source
		
		try:
			d['updatable'] = (len(source.url) > 0)
		except TypeError:
			d['updatable'] = False

		try:
			d['lastUpdate'] = source.updates.last().time.strftime("%d.%m.%Y %H:%M")
		except AttributeError:
			d['lastUpdate'] = "Never"

		d['updates'] = source.updates.order_by('-id').all()[:5]
		
		# Create a form for editing the sources:
		formData = {'name': source.name, 'url': source.url, 'md5url': source.md5url, 'schedule': "n"}
		d['form'] = NewSourceForm(formData)
		
		data['sources'].append(d)
	
	# If something is posted:
	if(request.POST):
		# Create the form based on the posted data
		data['manualUpdateForm'] = ManualUpdateForm(request.POST, request.FILES)
		
		# If the form is considered valid:
		if(data['manualUpdateForm'].is_valid()):
			# Construct some path where we can work.
			workarea = Config.get("storage", "inputFiles")
			create = Config.get("storage", "createIfNotExists")
			filename = os.path.join(workarea, request.FILES['file'].name)
			
			# Create the working-directories, if needed and wanted. 
			if(os.path.isdir(workarea) == False and create == "true"):
				os.makedirs(workarea)
			
			# Store the uploaded file.
			upload = open(filename, "wb+")
			for chunk in request.FILES['file'].chunks():
				upload.write(chunk)
			upload.close()
			
			# Generate a message for the user
			# TODO: LIVE statusupdates instead of this message.
			data['uploadMessage'] = "The ruleset is now uploaded, and the processing of the file is started. This might take a while however, depending on the size of the file."
			
			# Call the background-update script.
			source = Source.objects.get(pk=request.POST['source'])
			subprocess.call([os.path.join(BASE_DIR, 'scripts/runManualBackgroundUpdate.py'), filename, source.name])
	
	# If nothing is posted, create an empty form
	else:
		data['manualUpdateForm'] = ManualUpdateForm()
				
	return render(request, "update/index.tpl", data)

def newSource(request):
	data = {}
	
	if(request.POST):
		data['newSourceForm'] = NewSourceForm(request.POST)
		if(data['newSourceForm'].is_valid()):
			if(data['newSourceForm'].cleaned_data['schedule'] == 'd'):
				data['timeSelector'] = DailySelector(request.POST)
			elif(data['newSourceForm'].cleaned_data['schedule'] == 'w'):
				data['timeSelector'] = WeeklySelector(request.POST)
			elif(data['newSourceForm'].cleaned_data['schedule'] == 'm'):
				data['timeSelector'] = MonthlySelector(request.POST)
			
			if('timeSelector' in data and data['timeSelector'].is_valid() == False):
				pass			
			else:
				source, created = Source.objects.get_or_create(name=data['newSourceForm'].cleaned_data['name'])
				
				if not created:
					data['warningmessage'] = "The source '%s' already exists" % data['newSourceForm'].cleaned_data['name']
				else:
					source.url = data['newSourceForm'].cleaned_data['url']
					source.md5url = data['newSourceForm'].cleaned_data['md5url']
					
					if(data['newSourceForm'].cleaned_data['schedule'] == 'n'):
						schedule = "No automatic updates"
					else:
						schedule = str(request.POST['minute']) + " "
						schedule += str(request.POST['hour']) + " "

						if(data['newSourceForm'].cleaned_data['schedule'] == 'm'):
							schedule += str(request.POST['day']) + " * "
						else:
							schedule += "* * "
						
						if(data['newSourceForm'].cleaned_data['schedule'] == 'w'):
							schedule += str(int(request.POST['day']) % 7)
						else:
							schedule += "*"
						 
					source.schedule = schedule 
					source.save()
					data['warningmessage'] = "The source '%s' is created." % data['newSourceForm'].cleaned_data['name']
					data.pop('newSourceForm')
	else:
		data['newSourceForm'] = NewSourceForm()
	
	return render(request, "update/newSourceForm.tpl", data)

def getManualUpdateForm(request):
	return render(request, "update/manualUpdateForm.tpl", {'manualUpdateForm':ManualUpdateForm()})

def getSourceList(request):
	data = {}
	
	# Create a list over sources, and their last 5 updates.
	data['sources'] = []
	for source in Source.objects.all():
		d = {}
		d['source'] = source
		d['updates'] = source.updates.order_by('-id').all()[:5]
		data['sources'].append(d)

	return render(request, "update/sourceList.tpl", data)

def getTimeSelector(request, interval):
	if(interval not in ['d', 'w', 'm', 'n']):
		raise Http404
	
	data = {}
	
	if(interval == 'd'):
		data['form'] = DailySelector()
	elif(interval == 'w'):
		data['form'] = WeeklySelector()
	elif(interval == 'm'):
		data['form'] = MonthlySelector()

	return render(request, "update/formElement.tpl", data)

def runUpdate(request, id):
	data = {}
	source = Source.objects.get(pk=id)
	
	data['message'] = "Started en update from %s.\nThis might take a while, and currently no feedback is given if things are happening or not. Be patient :)" % source.name
	
	# Call the background-update script.
	subprocess.call([os.path.join(BASE_DIR, 'scripts/runBackgroundUpdate.py'), str(source.id)])
	
	return render(request, "message.tpl", data)
