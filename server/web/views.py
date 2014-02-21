from django.http import Http404, HttpResponse
from django.shortcuts import render

from core.models import *

from django.core import serializers

from web.utilities import UserSettings

import json

from django.shortcuts import redirect


def index(request):
	return redirect('web.views.ruleview')


def ruleview(request):
	
	context = {}
	
	context['pagecount'] =RuleRevision.objects.count()

	# Slik foreslår jeg at vi henter sidelengde :) - Eigil
	context['pagelength'] = UserSettings.getPageLength(request, pagetype=UserSettings.RULELIST)
	
	try:
		context['rule_list'] = RuleRevision.objects.all()[:10]
	except Rule.DoesNotExist:
		raise Http404
	
	
	return render(request, 'general/ruleview.tpl', context)

def ruleview2(request, minrange, maxrange):
	ruleviewlistmax = 10
	context = {}
	
	context['pagecount'] = RuleRevision.objects.count() / ruleviewlistmax
	
	try:
		rule_list = Rule.objects.all()[minrange:maxrange]
	except Rule.DoesNotExist:
		raise Http404
	
	revisions = []
	for r in rule_list:
		revisions.append(r.revisions.last())
	
	context['rules'] = [{'rule': t[0], 'rev': t[1]} for t in zip(rule_list, revisions)]
	
	return render(request, 'general/ruleview2.tpl', context)

def getRuleList(request, pagenr):
	
	pagedivisor = 10
	
	#pagecount = RuleRevision.objects.count()
	
	minrange = pagedivisor * int(pagenr)
	
	maxrange = int(minrange) + pagedivisor
	
	try:
		rule_list = RuleRevision.objects.all()[minrange:maxrange]
	except RuleRevision.DoesNotExist:
		raise Http404
	
	#context = []
	
	#for r in rule_list: 
		#context.append({'rev':r.json(),'rule':r.rule.json()})
	
	return render(request, 'general/ruleviewlist.tpl', {'rule_list':rule_list})
	
	
	
	
	
