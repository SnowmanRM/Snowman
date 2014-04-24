#!/usr/bin/python

from core.models import Sensor
from tuning.models import EventFilter, DetectionFilter, Suppress

class UserSettings():
	DEFAULT = 0
	RULELIST = 1
	
	@staticmethod
	def getPageLength(request, pagetype = DEFAULT):
		return 50

def rulesToTemplate(ruleList):
	"""
	This method takes Django Query objects containing a list of rules. 
	
	It returns a list of objects that can be put directly into the template without any additional processing.
	"""
	
	# We get the count of all sensors in the system.
	sensorCount = Sensor.objects.exclude(name="All").count()
	
	# This list will be whats returned.
	chewedRules = []
	
	# We iterate over all the rules.
	for rule in ruleList:
		
		# We go get a number of variables.
		ruleID = rule.id
		ruleGID = rule.generator.GID
		ruleSID = rule.SID
		ruleEventFilterCount = rule.eventFilters.count()
		ruleDetectionFilterCount = rule.detectionFilters.count()
		ruleSuppressCount = rule.suppress.count()
		ruleCurrentRevision = rule.getCurrentRevision()
		ruleRev = ruleCurrentRevision.rev
		ruleMsg = ruleCurrentRevision.msg
		ruleRaw = ruleCurrentRevision.raw
		ruleUpdateTime = ruleCurrentRevision.update.first().time
		ruleRuleSet = rule.ruleSet
		ruleRuleSetName = ruleRuleSet.name
		ruleSource = rule.update.first().source
		ruleSourceName = ruleSource.name
		ruleClass = rule.ruleClass
		ruleClassName = ruleClass.classtype
		ruleClassPriority = ruleClass.priority
		ruleActive = rule.active
		
		# To save time in the template, we go get the reference fields here.
		chewedRuleReferences = []
		for reference in ruleCurrentRevision.references.all():
			chewedRuleReferences.append({'urlPrefix':reference.referenceType.urlPrefix, 'reference': reference.reference})
		
		# Based on the priority, a certain color is to be picked.
		if ruleClassPriority == 1:
			ruleClassPriorityColor = "btn-danger"
		elif ruleClassPriority == 2:
			ruleClassPriorityColor = "btn-warning"
		elif ruleClassPriority == 3:
			ruleClassPriorityColor = "btn-success"
		else:
			ruleClassPriorityColor = "btn-primary"
		
		# If the rule is active, we calculate how many sensors its active on.
		if (ruleActive):
			ruleActiveOnSensors = ruleRuleSet.sensors.values_list('name', flat=True)
			
			if "All" in ruleActiveOnSensors:
				ruleActiveOnSensors = Sensor.objects.exclude(name="All").all()
				ruleActiveOnSensors = ruleActiveOnSensors.values_list('name', flat=True)
				ruleActiveOnSensorsCount = sensorCount
			else:
				ruleActiveOnSensorsCount = ruleRuleSet.sensors.count()
				
			ruleSetParent = ruleRuleSet.parent
			
			while ruleSetParent is not None:
				parentActiveOnSensors = ruleSetParent.sensors.values_list('name', flat=True)
				if "All" in parentActiveOnSensors:
					ruleActiveOnSensors = Sensor.objects.exclude(name="All").all()
					ruleActiveOnSensors = ruleActiveOnSensors.values_list('name', flat=True)
					ruleActiveOnSensorsCount = sensorCount
					ruleSetParent = None
				else:
					ruleActiveOnSensors = parentActiveOnSensors
					ruleActiveOnSensorsCount = ruleSetParent.sensors.count()
					ruleSetParent = ruleSetParent.parent
			
			ruleInActiveOnSensorsCount = sensorCount - ruleActiveOnSensorsCount
		else: # If the rule isnt active, it wont be active on any sensors
			ruleActiveOnSensors = []
			ruleActiveOnSensorsCount = 0
			ruleInActiveOnSensorsCount = sensorCount
		
		# Finally we feed all the variables into an object and append it to the return list.
		chewedRules.append({'ruleID':ruleID,'ruleGID':ruleGID,'ruleSID':ruleSID,'ruleEventFilterCount':ruleEventFilterCount,
						'ruleSuppressCount':ruleSuppressCount,'ruleRev':ruleRev,'ruleMsg':ruleMsg,
						'ruleReferences':chewedRuleReferences,'ruleRaw':ruleRaw,
						'ruleUpdateTime':ruleUpdateTime,'ruleRuleSetName':ruleRuleSetName,'ruleClassName':ruleClassName,
						'ruleClassPriority':ruleClassPriority,'ruleActiveOnSensors':ruleActiveOnSensors,'ruleActiveOnSensorsCount':ruleActiveOnSensorsCount, 
						'ruleInActiveOnSensorsCount':ruleInActiveOnSensorsCount, 'ruleActive':ruleActive, 'ruleClassPriorityColor': ruleClassPriorityColor, 
						'ruleDetectionFilterCount':ruleDetectionFilterCount, 'ruleSourceName':ruleSourceName})
	
	
	# Once all rules are iterated over, we send the clean objects back.
	return chewedRules

def ruleSetsToTemplate(ruleSetList):
	"""
	This method takes Django Query objects containing a list of rulesets. 
	
	It returns a list of objects that can be put directly into the template without any additional processing.
	"""
	
	# We get the count of all sensors in the system.
	sensorCount = Sensor.objects.exclude(name="All").count()
	
	# This list will be whats returned.
	chewedRuleSets = []
	
	# We iterate over all the rulesets.
	for ruleSet in ruleSetList:
		
		# We go get a number of variables.
		ruleSetID = ruleSet.id
		ruleSetName = ruleSet.name
		ruleSetActive = ruleSet.active
		
		#TODO: comment this
		if ruleSet.childSets.count() > 0:
			ruleSetHasChildren = True
			
			ruleSetRulesCount = ruleSet.rules.count()
			if ruleSetRulesCount:
				ruleSetHasRules = True
			else:
				ruleSetHasRules = False
				
			
			ruleSetRulesCount = len(ruleSet)
			ruleSetActiveRulesCount = ruleSet.getActiveRuleCount()
			
			ruleSetInActiveRulesCount = ruleSetRulesCount - ruleSetActiveRulesCount
		else:
			# We calculate the number of rules the ruleset has.
			ruleSetHasChildren = False
			ruleSetRulesCount = ruleSet.rules.count()
			if ruleSetRulesCount:
				ruleSetHasRules = True
			else:
				ruleSetHasRules = False
			ruleSetActiveRulesCount = ruleSet.rules.filter(active=True).count()
			ruleSetInActiveRulesCount = ruleSetRulesCount - ruleSetActiveRulesCount
		
		
		# If the ruleset is active, we calculate how many sensors its active on.
		if (ruleSetActive):
			ruleSetActiveOnSensors = ruleSet.sensors.values_list('name', flat=True)
			if "All" in ruleSetActiveOnSensors:
				ruleSetActiveOnSensors = Sensor.objects.exclude(name="All").all()
				ruleSetActiveOnSensors = ruleSetActiveOnSensors.values_list('name', flat=True)
				ruleSetActiveOnSensorsCount = sensorCount
			else:
				ruleSetActiveOnSensorsCount = ruleSet.sensors.count()
				
			ruleSetParent = ruleSet.parent
			
			while ruleSetParent is not None:
				parentActiveOnSensors = ruleSetParent.sensors.values_list('name', flat=True)
				if "All" in parentActiveOnSensors:
					ruleSetActiveOnSensors = Sensor.objects.exclude(name="All").all()
					ruleSetActiveOnSensors = ruleSetActiveOnSensors.values_list('name', flat=True)
					ruleSetActiveOnSensorsCount = sensorCount
					ruleSetParent = None
				else:
					ruleSetActiveOnSensors = parentActiveOnSensors
					ruleSetActiveOnSensorsCount = ruleSetParent.sensors.count()
					ruleSetParent = ruleSetParent.parent
					
			ruleSetInActiveOnSensorsCount = sensorCount - ruleSetActiveOnSensorsCount
		else: # If the ruleset isnt active, it wont be active on any sensors
			ruleSetActiveOnSensors = []
			ruleSetActiveOnSensorsCount = 0
			ruleSetInActiveOnSensorsCount = sensorCount

		# Finally we feed all the variables into an object and append it to the return list.
		chewedRuleSets.append({'ruleSetID':ruleSetID,'ruleSetName':ruleSetName,'ruleSetRulesCount':ruleSetRulesCount,'ruleSetActiveRulesCount':ruleSetActiveRulesCount,
							'ruleSetInActiveRulesCount':ruleSetInActiveRulesCount,'ruleSetActiveOnSensors':ruleSetActiveOnSensors,'ruleSetActiveOnSensorsCount':ruleSetActiveOnSensorsCount,
							'ruleSetInActiveOnSensorsCount':ruleSetInActiveOnSensorsCount,'ruleSetActive':ruleSetActive, 'ruleSetHasChildren':ruleSetHasChildren,
							'ruleSetHasRules':ruleSetHasRules})
	
	
	# Once all rulesets are iterated over, we send the clean objects back.
	return chewedRuleSets

def ruleSetsWithNewRulesToTemplate(ruleSetList, update):
	""""
	This method takes Django Query objects containing a list of rulesets. 
	
	It returns a list of objects that can be put directly into the template without any additional processing.
	"""
	
	ruleIDs = update.rules.values_list('id', flat=True)
	
	# We get the count of all sensors in the system.
	sensorCount = Sensor.objects.exclude(name="All").count()
	
	# This list will be whats returned.
	chewedRuleSets = []
	
	# We iterate over all the rulesets.
	for ruleSet in ruleSetList:
		ruleSetRuleIDs = ruleSet.rules.values_list('id', flat=True)
		
		if(len(set(ruleSetRuleIDs).intersection(ruleIDs))):
			
			# We go get a number of variables.
			ruleSetID = ruleSet.id
			ruleSetName = ruleSet.name
			ruleSetActive = ruleSet.active
			
			#TODO: comment this
			if ruleSet.childSets.count() > 0:
				ruleSetHasChildren = True
				
				ruleSetRulesCount = ruleSet.rules.filter(id__in=ruleIDs).count()
				if ruleSetRulesCount:
					ruleSetHasRules = True
					ruleSetActiveRulesCount = ruleSet.rules.filter(active=True, id__in=ruleIDs).count()
				else:
					ruleSetHasRules = False
					ruleSetActiveRulesCount = 0
				
				ruleSetInActiveRulesCount = ruleSetRulesCount - ruleSetActiveRulesCount
			else:
				# We calculate the number of rules the ruleset has.
				ruleSetHasChildren = False
				ruleSetRulesCount = ruleSet.rules.filter(id__in=ruleIDs).count()
				if ruleSetRulesCount:
					ruleSetHasRules = True
				else:
					ruleSetHasRules = False
				ruleSetActiveRulesCount = ruleSet.rules.filter(active=True, id__in=ruleIDs).count()
				ruleSetInActiveRulesCount = ruleSetRulesCount - ruleSetActiveRulesCount
			
			
			# If the ruleset is active, we calculate how many sensors its active on.
			if (ruleSetActive):
				ruleSetActiveOnSensors = ruleSet.sensors.values_list('name', flat=True)
				if "All" in ruleSetActiveOnSensors:
					ruleSetActiveOnSensors = Sensor.objects.exclude(name="All").all()
					ruleSetActiveOnSensors = ruleSetActiveOnSensors.values_list('name', flat=True)
					ruleSetActiveOnSensorsCount = sensorCount
				else:
					ruleSetActiveOnSensorsCount = ruleSet.sensors.count()
					
				ruleSetParent = ruleSet.parent
				
				while ruleSetParent is not None:
					parentActiveOnSensors = ruleSetParent.sensors.values_list('name', flat=True)
					if "All" in parentActiveOnSensors:
						ruleSetActiveOnSensors = Sensor.objects.exclude(name="All").all()
						ruleSetActiveOnSensors = ruleSetActiveOnSensors.values_list('name', flat=True)
						ruleSetActiveOnSensorsCount = sensorCount
						ruleSetParent = None
					else:
						ruleSetActiveOnSensors = parentActiveOnSensors
						ruleSetActiveOnSensorsCount = ruleSetParent.sensors.count()
						ruleSetParent = ruleSetParent.parent
						
				ruleSetInActiveOnSensorsCount = sensorCount - ruleSetActiveOnSensorsCount
			else: # If the ruleset isnt active, it wont be active on any sensors
				ruleSetActiveOnSensors = []
				ruleSetActiveOnSensorsCount = 0
				ruleSetInActiveOnSensorsCount = sensorCount
	
			# Finally we feed all the variables into an object and append it to the return list.
			chewedRuleSets.append({'ruleSetID':ruleSetID,'ruleSetName':ruleSetName,'ruleSetRulesCount':ruleSetRulesCount,'ruleSetActiveRulesCount':ruleSetActiveRulesCount,
								'ruleSetInActiveRulesCount':ruleSetInActiveRulesCount,'ruleSetActiveOnSensors':ruleSetActiveOnSensors,'ruleSetActiveOnSensorsCount':ruleSetActiveOnSensorsCount,
								'ruleSetInActiveOnSensorsCount':ruleSetInActiveOnSensorsCount,'ruleSetActive':ruleSetActive, 'ruleSetHasChildren':ruleSetHasChildren,
								'ruleSetHasRules':ruleSetHasRules})
		
	
	# Once all rulesets are iterated over, we send the clean objects back.
	return chewedRuleSets
	
	
def ruleSetsWithNewRuleRevisionsToTemplate(ruleSetList, update):
	""""
	This method takes Django Query objects containing a list of rulesets. 
	
	It returns a list of objects that can be put directly into the template without any additional processing.
	"""
	
	revSIDs = update.ruleRevisions.values_list('rule__SID', flat=True)
	newRuleSIDs = update.rules.values_list('SID', flat=True)
	
	ruleSIDs = list(set(revSIDs) - set(newRuleSIDs))
	
	# We get the count of all sensors in the system.
	sensorCount = Sensor.objects.exclude(name="All").count()
	
	# This list will be whats returned.
	chewedRuleSets = []
	
	# We iterate over all the rulesets.
	for ruleSet in ruleSetList:
		ruleSetRuleSIDs = ruleSet.rules.values_list('SID', flat=True)
		
		if(len(set(ruleSetRuleSIDs).intersection(ruleSIDs))):
			
			# We go get a number of variables.
			ruleSetID = ruleSet.id
			ruleSetName = ruleSet.name
			ruleSetActive = ruleSet.active
			
			#TODO: comment this
			if ruleSet.childSets.count() > 0:
				ruleSetHasChildren = True
				
				ruleSetRulesCount = ruleSet.rules.filter(SID__in=ruleSIDs).count()
				if ruleSetRulesCount:
					ruleSetHasRules = True
					ruleSetActiveRulesCount = ruleSet.rules.filter(active=True, SID__in=ruleSIDs).count()
				else:
					ruleSetHasRules = False
					ruleSetActiveRulesCount = 0
				
				ruleSetInActiveRulesCount = ruleSetRulesCount - ruleSetActiveRulesCount
			else:
				# We calculate the number of rules the ruleset has.
				ruleSetHasChildren = False
				ruleSetRulesCount = ruleSet.rules.filter(SID__in=ruleSIDs).count()
				if ruleSetRulesCount:
					ruleSetHasRules = True
				else:
					ruleSetHasRules = False
				ruleSetActiveRulesCount = ruleSet.rules.filter(active=True, SID__in=ruleSIDs).count()
				ruleSetInActiveRulesCount = ruleSetRulesCount - ruleSetActiveRulesCount
			
			
			# If the ruleset is active, we calculate how many sensors its active on.
			if (ruleSetActive):
				ruleSetActiveOnSensors = ruleSet.sensors.values_list('name', flat=True)
				if "All" in ruleSetActiveOnSensors:
					ruleSetActiveOnSensors = Sensor.objects.exclude(name="All").all()
					ruleSetActiveOnSensors = ruleSetActiveOnSensors.values_list('name', flat=True)
					ruleSetActiveOnSensorsCount = sensorCount
				else:
					ruleSetActiveOnSensorsCount = ruleSet.sensors.count()
					
				ruleSetParent = ruleSet.parent
				
				while ruleSetParent is not None:
					parentActiveOnSensors = ruleSetParent.sensors.values_list('name', flat=True)
					if "All" in parentActiveOnSensors:
						ruleSetActiveOnSensors = Sensor.objects.exclude(name="All").all()
						ruleSetActiveOnSensors = ruleSetActiveOnSensors.values_list('name', flat=True)
						ruleSetActiveOnSensorsCount = sensorCount
						ruleSetParent = None
					else:
						ruleSetActiveOnSensors = parentActiveOnSensors
						ruleSetActiveOnSensorsCount = ruleSetParent.sensors.count()
						ruleSetParent = ruleSetParent.parent
						
				ruleSetInActiveOnSensorsCount = sensorCount - ruleSetActiveOnSensorsCount
			else: # If the ruleset isnt active, it wont be active on any sensors
				ruleSetActiveOnSensors = []
				ruleSetActiveOnSensorsCount = 0
				ruleSetInActiveOnSensorsCount = sensorCount
	
			# Finally we feed all the variables into an object and append it to the return list.
			chewedRuleSets.append({'ruleSetID':ruleSetID,'ruleSetName':ruleSetName,'ruleSetRulesCount':ruleSetRulesCount,'ruleSetActiveRulesCount':ruleSetActiveRulesCount,
								'ruleSetInActiveRulesCount':ruleSetInActiveRulesCount,'ruleSetActiveOnSensors':ruleSetActiveOnSensors,'ruleSetActiveOnSensorsCount':ruleSetActiveOnSensorsCount,
								'ruleSetInActiveOnSensorsCount':ruleSetInActiveOnSensorsCount,'ruleSetActive':ruleSetActive, 'ruleSetHasChildren':ruleSetHasChildren,
								'ruleSetHasRules':ruleSetHasRules})
		
	
	# Once all rulesets are iterated over, we send the clean objects back.
	return chewedRuleSets
	
	
def ruleSetHierarchyListToTemplate(ruleSetList, level):
	
	# This list will be whats returned.
	chewedRuleSets = []
	
	# We iterate over all the rulesets.
	for ruleSet in ruleSetList:
		
		# We go get a number of variables.
		ruleSetID = ruleSet.id
		ruleSetName = ruleSet.name
		
		chewedRuleSets.append({'ruleSetID':ruleSetID,'ruleSetName':(" - "*level)+ruleSetName})
		
		if ruleSet.childSets.count() > 0:

			for item in ruleSetHierarchyListToTemplate(ruleSet.childSets.all(), level+1):
				chewedRuleSets.append(item)
	
	return chewedRuleSets

def ruleClassesToTemplate(ruleClassList):
	"""
	This method takes Django Query objects containing a list of rulesets. 
	
	It returns a list of objects that can be put directly into the template without any additional processing.
	"""
	
	# This list will be whats returned.
	chewedRuleClasses = []
	
	# We iterate over all the ruleclasses.
	for ruleClass in ruleClassList:
		
		# We go get a number of variables.
		ruleClassID = ruleClass.id
		ruleClassName = ruleClass.classtype
		ruleClassDescription = ruleClass.description
		
		# We calculate the number of rules the ruleclass has.
		ruleClassRulesCount = ruleClass.rules.count()
		ruleClassActiveRulesCount = ruleClass.rules.filter(active=True).count()
		ruleClassInActiveRulesCount = ruleClassRulesCount - ruleClassActiveRulesCount
		
		ruleClassPriority = ruleClass.priority
		
		# Based on the priority, a certain color is to be picked.
		if ruleClassPriority == 1:
			ruleClassPriorityColor = "btn-danger"
		elif ruleClassPriority == 2:
			ruleClassPriorityColor = "btn-warning"
		elif ruleClassPriority == 3:
			ruleClassPriorityColor = "btn-success"
		else:
			ruleClassPriorityColor = "btn-primary"


		# Finally we feed all the variables into an object and append it to the return list.
		chewedRuleClasses.append({'ruleClassID':ruleClassID,'ruleClassName':ruleClassName,'ruleClassRulesCount':ruleClassRulesCount,'ruleClassActiveRulesCount':ruleClassActiveRulesCount,
							'ruleClassInActiveRulesCount':ruleClassInActiveRulesCount,'ruleClassPriorityColor':ruleClassPriorityColor,'ruleClassDescription':ruleClassDescription,
							'ruleClassPriority':ruleClassPriority})

	# Once all ruleclasses are iterated over, we send the clean objects back.
	return chewedRuleClasses


#TODO: comment this
def tuningToTemplate(tuningList):
	
	chewedTuningList = []
	for tuning in tuningList:
		if type(tuning) is EventFilter:
			tuningID = tuning.id
			tuningComment = tuning.comment
			if tuningComment is not None:
				tuningAdded = tuningComment.time
				tuningUser = tuningComment.user
				tuningComment = tuningComment.comment
			else:
				tuningAdded = ""
				tuningUser = ""
				tuningComment = ""
			tuningType = "EventFilter"
			tuningRuleSID = tuning.rule.SID
			tuningRuleName = tuning.rule.getCurrentRevision().msg
			tuningSensorName = tuning.sensor.name
			tuningContent = "type "+str(tuning.TYPE[tuning.eventFilterType])+", track "+str(tuning.TRACK[tuning.track])+",  count "+str(tuning.count)+",\
							seconds "+str(tuning.seconds)+" "
			
			
			chewedTuningList.append({ 'tuningID':tuningID, 'tuningAdded':tuningAdded,'tuningUser':tuningUser,'tuningType':tuningType,'tuningRuleSID':tuningRuleSID,
									'tuningRuleName':tuningRuleName,'tuningSensorName':tuningSensorName,'tuningContent':tuningContent,'tuningComment':tuningComment })
		
		elif type(tuning) is DetectionFilter:
			tuningID = tuning.id
			tuningComment = tuning.comment
			if tuningComment is not None:
				tuningAdded = tuningComment.time
				tuningUser = tuningComment.user
				tuningComment = tuningComment.comment
			else:
				tuningAdded = ""
				tuningUser = ""
				tuningComment = ""
			tuningType = "DetectionFilter"
			tuningRuleSID = tuning.rule.SID
			tuningRuleName = tuning.rule.getCurrentRevision().msg
			tuningSensorName = tuning.sensor.name
			tuningContent = "count "+str(tuning.count)+", seconds "+str(tuning.seconds)+" "
			
			
			chewedTuningList.append({ 'tuningID':tuningID, 'tuningAdded':tuningAdded,'tuningUser':tuningUser,'tuningType':tuningType,'tuningRuleSID':tuningRuleSID,
									'tuningRuleName':tuningRuleName,'tuningSensorName':tuningSensorName,'tuningContent':tuningContent,'tuningComment':tuningComment })
		
		elif type(tuning) is Suppress:
			tuningID = tuning.id
			tuningComment = tuning.comment
			if tuningComment is not None:
				tuningAdded = tuningComment.time
				tuningUser = tuningComment.user
				tuningComment = tuningComment.comment
			else:
				tuningAdded = ""
				tuningUser = ""
				tuningComment = ""
			tuningType = "Suppression"
			tuningRuleSID = tuning.rule.SID
			tuningRuleName = tuning.rule.getCurrentRevision().msg
			tuningSensorName = tuning.sensor.name
			suppressAddresses = tuning.addresses.values_list('ipAddress', flat=True)
			tuningContent = "track "+str(tuning.TRACK[tuning.track])+", IP Addresses ["+', '.join(suppressAddresses)+"] "
			
			
			chewedTuningList.append({ 'tuningID':tuningID, 'tuningAdded':tuningAdded,'tuningUser':tuningUser,'tuningType':tuningType,'tuningRuleSID':tuningRuleSID,
									'tuningRuleName':tuningRuleName,'tuningSensorName':tuningSensorName,'tuningContent':tuningContent,'tuningComment':tuningComment })

	
	return chewedTuningList


def sensorsToFormTemplate(sensorList, level):
	chewedSensorList = []
	# We iterate over all the rulesets.
	for sensor in sensorList:
		
		# We go get a number of variables.
		sensorID = sensor.id
		sensorName = sensor.name
		
		chewedSensorList.append({ 'sensorID':sensorID,'sensorName':(" - "*level)+sensorName})
		
		if sensor.childSensors.count() > 0:
			for item in sensorsToFormTemplate(sensor.childSensors.all(), level+1):
				chewedSensorList.append(item)

	return chewedSensorList

