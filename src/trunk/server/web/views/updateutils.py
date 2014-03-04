"""
A couple of common utilities used by the update-views.
"""

import time

from update.models import Source
from web.views.updateforms import DailySelector, WeeklySelector, MonthlySelector, NewSourceForm

def createForm(source = None, post = None):
	"""Creates a form for changing a source, based on a source-object, or posted data.
	It returns a dict, with one or two items:
		'newSourceForm': A Django-form for the source name/url/md5url/update-interval
		'timeSelector': A Django-form for selecting the update-time, if update-interval is not "No automatic updates".
	"""

	d = {}
	
	# If we are missing some data, just return the empty dict. 
	if not source and not post:
		logger.error("createForm needs either a source-object or a post-dict supplied to work.")
		return d
	
	# If a dict with post-data is supplied, use that to fill data into the forms.
	if(post):
		formData = post
	
	# Otherwise, extract the data from the source-object.
	elif(source):
		formData = {'name': source.name, 'url': source.url, 'md5url': source.md5url}
		formData.update(source.getSchedule())
	
	# Create the NewSourceForm
	d['newSourceForm'] = NewSourceForm(formData)
	
	# If needded, create the correct time-selector form.
	if(formData['schedule'] == 'd'):
		d['timeSelector'] = DailySelector(formData)
	elif(formData['schedule'] == 'w'):
		d['timeSelector'] = WeeklySelector(formData)
	elif(formData['schedule'] == 'm'):
		d['timeSelector'] = MonthlySelector(formData)
	
	return d
	
def createSourceList():
	"""This method creates a list of all our sources, with their 5 last updates, last-updated
	date, an edit-form and if it is updateable. This information is used by the template-system
	to generate the source-list."""

	sources = []
	# For every source in the system
	for source in Source.objects.all():
		# Create a dict, and add the raw source there
		d = {}
		d['source'] = source
		
		# Add a bool saying if this source can be auto-updated. (IE: Do we have an URL for rules?)
		try:
			d['updatable'] = (len(source.url) > 0)
		except TypeError:
			d['updatable'] = False

		# Add the date for the last update
		try:
			d['lastUpdate'] = source.updates.last().time.strftime("%d.%m.%Y %H:%M")
		except AttributeError:
			d['lastUpdate'] = "Never"

		# Add the five last updates related to this source.
		d['updates'] = source.updates.order_by('-id').all()[:5]
		
		# Add the forms needed to edit this source.
		d.update(createForm(source))
		
		# Append the dict we created to the list of all the sources.
		sources.append(d)

	return sources
