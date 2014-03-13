#!/usr/bin/python

from core.models import Sensor

class UserSettings():
	DEFAULT = 0
	RULELIST = 1
	
	@staticmethod
	def getPageLength(request, pagetype = DEFAULT):
		return 20

def rulesToTemplate(ruleList):
	
	sensorCount = Sensor.objects.count()
	
	chewedRules = []
	
	for rule in ruleList:
		
		ruleID = rule.id
		ruleGID = rule.generator.GID
		ruleSID = rule.SID
		
		ruleThresholdCount = rule.thresholds.count()
		ruleSuppressCount = rule.suppress.count()
		
		ruleCurrentRevision = rule.getCurrentRevision()
		ruleRev = ruleCurrentRevision.rev
		ruleMsg = ruleCurrentRevision.msg
		ruleRaw = ruleCurrentRevision.raw
		ruleUpdateTime = ruleCurrentRevision.update.first().time
		
		chewedRuleReferences = []
		for reference in ruleCurrentRevision.references.all():
			chewedRuleReferences.append({'urlPrefix':reference.referenceType.urlPrefix, 'reference': reference.reference})
		
		ruleRuleSet = rule.ruleSet
		ruleRuleSetName = ruleRuleSet.name
		
		ruleClass = rule.ruleClass
		ruleClassName = ruleClass.classtype
		ruleClassPriority = ruleClass.priority
		
		if ruleClassPriority == 1:
			ruleClassPriorityColor = "btn-danger"
		elif ruleClassPriority == 2:
			ruleClassPriorityColor = "btn-warning"
		elif ruleClassPriority == 3:
			ruleClassPriorityColor = "btn-success"
		else:
			ruleClassPriorityColor = "btn-primary"
		
		ruleActive = rule.active
		
		if (ruleActive):
			ruleActiveOnSensors = ruleRuleSet.sensors.values_list('name', flat=True)
			ruleActiveOnSensorsCount = ruleRuleSet.sensors.count()
			ruleInActiveOnSensorsCount = sensorCount - ruleActiveOnSensorsCount
		else:
			ruleActiveOnSensors = []
			ruleActiveOnSensorsCount = 0
			ruleInActiveOnSensorsCount = sensorCount
		
		chewedRules.append({'ruleID':ruleID,'ruleGID':ruleGID,'ruleSID':ruleSID,'ruleThresholdCount':ruleThresholdCount,
						'ruleSuppressCount':ruleSuppressCount,'ruleRev':ruleRev,'ruleMsg':ruleMsg,
						'ruleReferences':chewedRuleReferences,'ruleRaw':ruleRaw,
						'ruleUpdateTime':ruleUpdateTime,'ruleRuleSetName':ruleRuleSetName,'ruleClassName':ruleClassName,
						'ruleClassPriority':ruleClassPriority,'ruleActiveOnSensors':ruleActiveOnSensors,'ruleActiveOnSensorsCount':ruleActiveOnSensorsCount, 
						'ruleInActiveOnSensorsCount':ruleInActiveOnSensorsCount, 'ruleActive':ruleActive, 'ruleClassPriorityColor': ruleClassPriorityColor})
	
	
	
	return chewedRules

def ruleSetsToTemplate(ruleSetList):
	sensorCount = Sensor.objects.count()
	
	chewedRuleSets = []
	
	for ruleSet in ruleSetList:
		ruleSetID = ruleSet.id
		ruleSetName = ruleSet.name
		
		ruleSetRulesCount = ruleSet.rules.count()
		ruleSetActiveRulesCount = ruleSet.rules.filter(active=True).count()
		ruleSetInActiveRulesCount = ruleSetRulesCount - ruleSetActiveRulesCount
		
		ruleSetActive = ruleSet.active
		if (ruleSetActive):
			ruleSetActiveOnSensors = ruleSet.sensors.values_list('name', flat=True)
			ruleSetActiveOnSensorsCount = ruleSet.sensors.count()
			ruleSetInActiveOnSensorsCount = sensorCount - ruleSetActiveOnSensorsCount
		else:
			ruleSetActiveOnSensors = []
			ruleSetActiveOnSensorsCount = 0
			ruleSetInActiveOnSensorsCount = sensorCount

		
		chewedRuleSets.append({'ruleSetID':ruleSetID,'ruleSetName':ruleSetName,'ruleSetRulesCount':ruleSetRulesCount,'ruleSetActiveRulesCount':ruleSetActiveRulesCount,
							'ruleSetInActiveRulesCount':ruleSetInActiveRulesCount,'ruleSetActiveOnSensors':ruleSetActiveOnSensors,'ruleSetActiveOnSensorsCount':ruleSetActiveOnSensorsCount,
							'ruleSetInActiveOnSensorsCount':ruleSetInActiveOnSensorsCount,'ruleSetActive':ruleSetActive})
	
	
	
	return chewedRuleSets

def ruleClassesToTemplate(ruleClassList):
	
	chewedRuleClasses = []
	
	for ruleClass in ruleClassList:
		ruleClassID = ruleClass.id
		ruleClassName = ruleClass.classtype
		ruleClassDescription = ruleClass.description
		
		ruleClassPriority = ruleClass.priority
		
		if ruleClassPriority == 1:
			ruleClassPriorityColor = "btn-danger"
		elif ruleClassPriority == 2:
			ruleClassPriorityColor = "btn-warning"
		elif ruleClassPriority == 3:
			ruleClassPriorityColor = "btn-success"
		else:
			ruleClassPriorityColor = "btn-primary"
		
		ruleClassRulesCount = ruleClass.rules.count()
		ruleClassActiveRulesCount = ruleClass.rules.filter(active=True).count()
		ruleClassInActiveRulesCount = ruleClassRulesCount - ruleClassActiveRulesCount
		
		

		
		chewedRuleClasses.append({'ruleClassID':ruleClassID,'ruleClassName':ruleClassName,'ruleClassRulesCount':ruleClassRulesCount,'ruleClassActiveRulesCount':ruleClassActiveRulesCount,
							'ruleClassInActiveRulesCount':ruleClassInActiveRulesCount,'ruleClassPriorityColor':ruleClassPriorityColor,'ruleClassDescription':ruleClassDescription,
							'ruleClassPriority':ruleClassPriority})
	
	
	
	return chewedRuleClasses