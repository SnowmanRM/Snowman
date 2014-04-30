#!/usr/bin/python

from core.models import Sensor, Rule
from tuning.models import DetectionFilter, EventFilter, Suppress, SuppressAddress

def getEventFilter(sensor, rule):
	s = sensor
	while s != None:
		try:
			ef = s.eventFilters.get(rule=rule)
			return ef
		except EventFilter.DoesNotExist:
			s = s.parent
	return False

def getDetectionFilter(sensor, rule):
	s = sensor
	while s != None:
		try:
			df = s.detectionFilters.get(rule=rule)
			return df
		except DetectionFilter.DoesNotExist:
			s = s.parent
	return False

def getSuppress(sensor, rule):
	s = sensor
	while s != None:
		try:
			sup = s.suppress.get(rule=rule)
			return sup
		except Suppress.DoesNotExist:
			s = s.parent
	return False

def generateFilterConfig(rules, sensor, filters, suppresses):
	"""Generates filter-configurations for the list of rules supplied"""
	for sid in rules:
		rule = rules[sid][0]

		# If filters exist, add them to the appropiate files
		eventFilter = getEventFilter(sensor, rule)
		detectionFilter = getDetectionFilter(sensor, rule)
		suppress = getSuppress(sensor, rule)
		
		if eventFilter:
			filters.addLine(eventFilter.getConfigLine())
		#if detectioFilter:
		#	filters.addLine(detectionFilter.getConfigLine())
		if suppress:
			suppresses.addLine(suppress.getConfigLine())
