from django.http import Http404
from django.shortcuts import render

from core.models import Rule, RuleRevision


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
