"""
The views related to the update-pages.
"""
import logging
from multiprocessing import Process
import os
import subprocess
import time
import urllib2

from django import forms
from django.forms import ModelChoiceField
from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision
from srm.settings import BASE_DIR
from update.models import Source
from update.tasks import UpdateTasks
from util.config import Config
from web.utilities import UserSettings

class NameModelChoiceField(ModelChoiceField):
	"""A drop-down-list, based on django's "ModelChoiseField", which can be populated
	by a django queryset, and uses the objects name as visual representation."""

	def label_from_instance(self, obj):
		"""Overrides the default label, to rather use the name of the object."""
		return "%s" % obj.name

class ManualUpdateForm(forms.Form):
	"""The form used for file-uploads."""
	file = forms.FileField()
	source = NameModelChoiceField(queryset=Source.objects.all(), empty_label=None)

class DailySelector(forms.Form):
	hourChoises = (('', '<select one>'),) + tuple((x, str(x)) for x in range(0,24))
	minuteChoises = (('', '<select one>'),) + tuple((x, str(x)) for x in range(0,60,15))
	
	hour = forms.ChoiceField(hourChoises)
	minute = forms.ChoiceField(minuteChoises)

class WeeklySelector(DailySelector):
	dayChoises = (
		(0, '<select one>'),
		(1, "Monday"),
		(2, "Tuesday"),
		(3, "Wednesday"),
		(4, "Thursday"),
		(5, "Friday"),
		(6, "Saturday"),
		(7, "Sunday"),
	)
	
	day = forms.ChoiceField(dayChoises)

class MonthlySelector(DailySelector):
	dayChoises = (('', '<select one>'),) + tuple((x, str(x)) for x in range(1,32))
	day = forms.ChoiceField(dayChoises)

class NewSourceForm(forms.Form):
	"""The form used to create new sources"""
	scheduleChoises = (
		('', '<Select one>'),
		('n', 'No automatic update'),
		('d', 'Daily'),
		('w', 'Weekly'),
		('m', 'Monthly'),
	)
	
	name = forms.CharField(max_length=40)
	url = forms.CharField(max_length=160, required=False)
	md5url = forms.CharField(max_length=160, required=False)
	schedule = forms.ChoiceField(scheduleChoises)

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
	
	try:
		test = urllib2.urlopen(source.url)
		test.close()
	except:
		data['message'] = "Could not find the file %s. Download therfore not started." % source.url
	else:
		data['message'] = "Started en update from %s.\nThis might take a while, and currently no feedback is given if things are happening or not. Be patient :)" % source.name

	# Call the background-update script.
	subprocess.call([os.path.join(BASE_DIR, 'scripts/runBackgroundUpdate.py'), str(source.id)])
	
	return render(request, "message.tpl", data)
