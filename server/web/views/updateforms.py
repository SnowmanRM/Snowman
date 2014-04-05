"""
The forms used by the update-views.
"""
from django import forms
from django.forms import ModelChoiceField
from django.contrib.auth.decorators import login_required
from update.models import Source

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
