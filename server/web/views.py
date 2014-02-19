from django.http import Http404, HttpResponse
from django.shortcuts import render

from core.models import *

from django.core import serializers

import json


def index(request):
	ruleviewlistmax = 10
	context = {}
	
	context['pagecount'] =RuleRevision.objects.count() / ruleviewlistmax
	
	try:
		rule_list = Rule.objects.all()[:10]
	except Rule.DoesNotExist:
		raise Http404
	
	revisions = []
	for r in rule_list:
		revisions.append(r.revisions.last())
	
	context['rules'] = [{'rule': t[0], 'rev': t[1]} for t in zip(rule_list, revisions)]
	
	return render(request, 'general/ruleview.tpl', context)

def ruleview2(request, minrange, maxrange):
	ruleviewlistmax = 10
	context = {}
	
	context['pagecount'] =RuleRevision.objects.count() / ruleviewlistmax
	
	try:
		rule_list = Rule.objects.all()[minrange:maxrange]
	except Rule.DoesNotExist:
		raise Http404
	
	revisions = []
	for r in rule_list:
		revisions.append(r.revisions.last())
	
	context['rules'] = [{'rule': t[0], 'rev': t[1]} for t in zip(rule_list, revisions)]
	
	return render(request, 'general/ruleview2.tpl', context)

def getRuleListRange(request, minrange, maxrange):
	
	
	try:
		rule_list = RuleRevision.objects.all()[minrange:maxrange]
		
	except RuleRevision.DoesNotExist:
		raise Http404
	
	context = []
	
	for r in rule_list: 
		context.append({'rev':r.getJson(),'rule':r.rule.getJson()})
	
	return HttpResponse(json.dumps(context), content_type="application/json")
	
	
	
	
	