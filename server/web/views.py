from django.http import Http404
from django.shortcuts import render

from core.models import Rule, RuleRevision


def index(request):
	try:
		rule_list = RuleRevision.objects.all()[:5]
	except Rule.DoesNotExist:
		raise Http404
	context = {'rule_list': rule_list}
	return render(request, 'general/ruleview.tpl', context)
