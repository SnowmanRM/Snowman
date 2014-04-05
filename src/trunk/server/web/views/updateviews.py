"""
The views related to the update-pages.
"""

import json
import logging
import os
import re
import subprocess

from django.http import Http404, HttpResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count

from srm.settings import BASE_DIR
from update.models import Source, Update, UpdateLog, RuleChanges
from util.config import Config
from web.views.updateforms import ManualUpdateForm, DailySelector, WeeklySelector, MonthlySelector, NewSourceForm
from web.views.updateutils import createForm, createSourceList

def index(request):
	"""The default view for the update section."""
	data = {}
	
	# Create a list over sources.
	data['sources'] = createSourceList()
	
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
			source = Source.objects.get(pk=request.POST['source'])
			if(source.locked):
				data['uploadMessage'] = "There are already an update going for this source"
			else:
				data['uploadMessage'] = "The ruleset is now uploaded, and the processing of the file is started. This might take a while however, depending on the size of the file."
				# Call the background-update script.
				subprocess.call([os.path.join(BASE_DIR, 'scripts/runManualBackgroundUpdate.py'), filename, source.name])
	
	# If nothing is posted, create an empty form
	else:
		data['manualUpdateForm'] = ManualUpdateForm()
				
	return render(request, "update/index.tpl", data)

def changes(request):
	CHANGE = 1
	KEEP = 2

	logger = logging.getLogger(__name__)
	if request.POST:
		checkBox = re.compile(r"change-(\d+)")
		button = re.compile(r"btn-(.+)")
		
		changes = []
		action = None
		
		for element in request.POST:
			btn = button.match(element)
			cb = checkBox.match(element)
			
			if btn:
				if(btn.group(1) == "change"):
					action = CHANGE
				elif(btn.group(1) == "keep"):
					action = KEEP
			elif cb:
				changes.append(int(cb.group(1)))
		
		if(action):		
			for change in changes:
				try:
					c = RuleChanges.objects.get(pk=change)
				except RuleChanges.DoesNotExist:
					logger.error("Could not get change with ID %d" % change)
				else:
					if(action == CHANGE):
						if(c.moved):
							c.rule.ruleSet = c.originalSet
						else:
							c.rule.ruleSet = c.newSet
						c.rule.save()
					c.delete()
			
	data = {}
	data['updates'] = []
	
	for update in Update.objects.order_by('time').reverse().filter(isNew=True):
		updateID = update.id
		updateName = update.source.name
		updateTime = update.time
		updateRevisionsCount = update.ruleRevisions.count()

		updateNewRulesCount = update.rules.count()
		
		updateNewRevisionsCount = updateRevisionsCount - updateNewRulesCount
		
		updateNewRuleSetCount = update.ruleSets.count()
		
		updateChangeCount = updateRevisionsCount + updateNewRuleSetCount
		
		updatePendingChangeCount = update.pendingChanges.count()
		pendingRuleSets = []
		
		for change in update.pendingChanges.all():
				
			pendingRuleSets.append(change)
		
		data['updates'].append({'updateID':updateID,'updateName':updateName,'updateTime':updateTime,'updateChangeCount':updateChangeCount,
							'updatePendingChangeCount':updatePendingChangeCount,'pendingRuleSets':pendingRuleSets, 'updateNewRuleSetCount': updateNewRuleSetCount,
							'updateNewRulesCount':updateNewRulesCount,'updateNewRevisionsCount':updateNewRevisionsCount})
	
	#return HttpResponse(data['updates'])
	return render(request, "update/changes.tpl", data)

def removeUpdate(request, updateID):
	
	logger = logging.getLogger(__name__)
	
	try:
		update = Update.objects.get(id=updateID)
	except Update.DoesNotExist:
		logger.warning("Page request /rules/ could not be resolved, objects not found.")
		raise Http404
	
	update.isNew = False
	update.save()
	
	return HttpResponse('Success')

def newSource(request):
	"""This view recieves data from the "newSource" form. If the data recieved is valid, a new source is created.
	Otherwise, the form is returned, with information on why the form is not valid.
	
	This view is not a complete website, as it is supposed to be called via AJAX"""
	data = {}
	
	# If we recieved some data:
	if(request.POST):
		# Create a form based on these data.
		data.update(createForm(post = request.POST))

		# If the form now is valid:
		if(data['newSourceForm'].is_valid()):
			# And eventually, the timeSelector data is valid, if a schedule other than none is selected
			if('timeSelector' in data and data['timeSelector'].is_valid() == False):
				pass			
			else:
				# Try to create a new source
				source, created = Source.objects.get_or_create(name=data['newSourceForm'].cleaned_data['name'])
				
				# If it already exists, return an error message.
				if not created:
					data['warningmessage'] = "The source '%s' already exists" % data['newSourceForm'].cleaned_data['name']

				# Otherwise, update the freshly created source with the correct data, and save it.
				else:
					source.url = data['newSourceForm'].cleaned_data['url']
					source.md5url = data['newSourceForm'].cleaned_data['md5url']
					source.setSchedule(data, save = False)
					source.save()

					# Add an error-message, and remove the form from the view-data, so that it is not displayed.
					data['warningmessage'] = "The source '%s' is created." % data['newSourceForm'].cleaned_data['name']
					data.pop('newSourceForm')
	
	# If no data was recieved, create an emty form.
	else:
		data['newSourceForm'] = NewSourceForm()
	
	return render(request, "update/newSourceForm.tpl", data)

def editSource(request, id):
	"""This view is responsible to recieve and process requests for changing sources. If the form is valid, the source gets
	updated. Otherwise, a form with a description of what is wrong gets returned.
	
	This view is not a complete website, as it is supposed to be called via AJAX"""
	
	logger = logging.getLogger(__name__)

	# If we cannot find a source with the requested ID, raise an 404 error.
	try:
		source = Source.objects.get(pk=id)
	except Source.DoesNotExist:
		raise Http404
	
	# Return the ID to the requesting client, so that the javascript knows which edit-form
	#   needs to be updated when the response is recieved.
	data = {}
	data['id'] = id
	data['success'] = "false"
	
	# If this view is supplied with some data:
	if(request.POST):
		# Create a form based on these data
		data.update(createForm(post = request.POST))
		
		# It that form is valid, update the source-object, and display a friendly message telling that things have beed updated.
		if(data['newSourceForm'].is_valid() and ("timeSelector" not in data or data['timeSelector'].is_valid())):
			source.name = data['newSourceForm'].cleaned_data['name']
			source.url = data['newSourceForm'].cleaned_data['url']
			source.md5url = data['newSourceForm'].cleaned_data['md5url']
			source.url = data['newSourceForm'].cleaned_data['url']
			source.setSchedule(data, save=False)
			source.save()
			logger.debug("Saved %s", source)

			data['message'] = "The source is updated."	
			data['success'] = "true"

		# If the supplied data was invalid, return an error-message.
		else:
			data['message'] = "The schema was not correct."	
	
	# If this view was invoked without data, return a form with the data of the source-object.			
	else:
		data.update(createForm(source = source))
	
	return render(request, "update/response.tpl", data)

def getManualUpdateForm(request):
	"""A very simple view, only returning the form for manual-updates.
	This view is not a complete website, as it is supposed to be called via AJAX"""

	return render(request, "update/manualUpdateForm.tpl", {'manualUpdateForm':ManualUpdateForm()})

def getSourceList(request):
	"""This view returns the list of sources, used in the index-view of update.
	This view is not a complete website, as it is supposed to be called via AJAX"""
	data = {}
	
	# Create a list over sources
	data['sources'] = createSourceList()

	return render(request, "update/sourceList.tpl", data)

def getTimeSelector(request, interval):
	""" This view returns a time-select form, which matches the selected update-interval.
	This view is not a complete website, as it is supposed to be called via AJAX"""
	
	# If the requested interval is invalid, raise an 404 error
	if(interval not in ['d', 'w', 'm', 'n']):
		raise Http404
	
	data = {}
	
	# Create the correct form (or, in the case of no automatic updates, skip creating the form
	# alltogether.
	if(interval == 'd'):
		data['form'] = DailySelector()
	elif(interval == 'w'):
		data['form'] = WeeklySelector()
	elif(interval == 'm'):
		data['form'] = MonthlySelector()

	return render(request, "update/formElement.tpl", data)

def runUpdate(request, id):
	"""This view is responsible to start an automatic update of a source. The update is spawned in its own process, so
	the user is only informed that the update is started.
	The status-message is returnes as JSON."""
	data = {}

	# If we cannot find a source with the requested ID, raise an 404 error.
	try:
		source = Source.objects.get(pk=id)
	except Source.DoesNotExist:
		raise Http404
	
	if source.locked:
		data['message'] = "There are already an update running for %s" % source.name
	else:
		data['message'] = "Started the update from %s." % source.name
	
		# Call the background-update script.
		subprocess.call([os.path.join(BASE_DIR, 'scripts/runBackgroundUpdate.py'), str(source.id)])
	
	return HttpResponse(json.dumps(data), content_type="application/json")

def getStatus(request, id):
	"""This view returns the update-status for a given source as JSON.
	
	The data returned is:
	 - status: true/false if an update is running now
	 - progress: How far (in percents) the current update have come.
	 - message: A message telling what the update-process is doing right now.
	 - time: The time corresponding to the last message.
	 - updates: A list over the 5 last updates. Each of which contains:
		- time: The time the update was started
		- changes: The nuber of rules that have been changed in this update."""

	data = {}

	# If we cannot find a source with the requested ID, raise an 404 error.
	try:
		source = Source.objects.get(pk=id)
	except Source.DoesNotExist:
		raise Http404
	
	data['status'] = source.locked 
	if source.locked:
		lastUpdate = source.updates.last()
		lastLogLine = lastUpdate.logEntries.filter(logType=UpdateLog.PROGRESS).last()
		match = re.match(r"(\d+)\ (.*)", lastLogLine.text)
		data['progress'] = match.group(1)
		data['message'] = match.group(2)
		data['time'] = str(lastLogLine.time)
	
	data['updates'] = []
	for update in source.updates.order_by('-time').all()[:5]:
		d = {}
		d['time'] = update.time.strftime("%d.%m.%Y %H:%M")
		d['changes'] = update.ruleRevisions.count()
		data['updates'].append(d)
		
	return HttpResponse(json.dumps(data), content_type="application/json")
