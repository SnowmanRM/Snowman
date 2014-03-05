from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision, Sensor
from tuning.models import Threshold
from web.utilities import UserSettings
import logging, json


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
	ruleId = request.POST.getlist('id')
	response = []
	for rule in ruleId:
		r = Rule.objects.get(id=rule)
		if r.thresholds.count() == 0:
			response.append({'response': 'thresholdExists', 'ruleSID': r.SID})
	
	return HttpResponse(json.dumps(response))