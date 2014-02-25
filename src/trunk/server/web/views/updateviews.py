"""
The views related to the update-pages.
"""
import logging
from multiprocessing import Process
import os
import subprocess
import time

from django import forms
from django.forms import ModelChoiceField
from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision
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

def index(request):
	"""The default view for the update section."""
	data = {}
	
	# Create a list over sources, and their last 5 updates.
	data['sources'] = []
	for source in Source.objects.all():
		d = {}
		d['source'] = source
		d['updates'] = source.updates.order_by('-id').all()[:5]
		data['sources'].append(d)
	
	# If something is posted:
	if(request.POST):
		# Create the form based on the posted data
		data['manualUpdateForm'] = ManualUpdateForm(request.POST, request.FILES)
		
		# If the form is considered valid:
		if(data['manualUpdateForm'].is_valid()):
			# Construct some path where we can work.
			workarea = Config.get("updates", "workarea")
			filename = os.path.join(workarea, request.FILES['file'].name)
			
			# Store the uploaded file.
			upload = open(filename, "wb+")
			for chunk in request.FILES['file'].chunks():
				upload.write(chunk)
			upload.close()
			
			# Generate a message for the user
			# TODO: LIVE statusupdates instead of this message.
			data['uploadMessage'] = "The ruleset is now uploaded, and the processing of the file is started. This might take a while however, depending on the size of the file."
			
			# Do the first fork to make the update happen in the background.
			source = Source.objects.get(pk=request.POST['source'])
			p = Process(target=UpdateTasks.update, args=(filename, source.name))
			p.start()
	
	# If nothing is posted, create an empty form
	else:
		data['manualUpdateForm'] = ManualUpdateForm()
				
	return render(request, "update/index.tpl", data)
