class HTTPResponses:
	INVALIDGIDSID = {'response': 'invalidGIDSIDFormat', 'text': 'Please format in the GID:SID syntax.'}
	NOCOMMENT = {'response': 'noComment', 'text': 'You have not set any comments on this action, are you sure you want to proceed?'}
	ALLSENSORS = {'response': 'allSensors', 'text': 'Are you sure you want to set this filter on all sensors?'}
	TYPEOUTOFRANGE = {'response': 'typeOutOfRange', 'text': 'Type value out of range.'}
	TRACKOUTOFRANGE = {'response': 'trackOutOfRange', 'text': 'Track value out of range.'}
	ADDFILTERFAILURE = {'response': 'addFilterFailure', 'text': 'Failed when trying to add filter.'}
	
	@staticmethod
	def SIDDOESNOTEXIST(sid):
		return {'response': 'sidDoesNotExist', 'text': 'SID '+sid+' does not exist.'}
	
	@staticmethod
	def GIDDOESNOTEXIST(gid):
		return {'response': 'gidDoesNotExist', 'text': 'GID '+gid+' does not exist.'}
	
	@staticmethod
	def SENSORDOESNOTEXIST(sensor):
		return {'response': 'sensorDoesNotExist', 'text': 'Sensor with DB ID '+sensor+' does not exist.'}
	
	@staticmethod
	def FILTEREXISTS(filterType, sid, sensorName):
		return {'response': 'filterExists', 'text': 'A filter of type '+filterType+' already exists for rule id '+str(sid)+' on sensor \''+sensorName+'\', do you want to overwrite?.', 'sids': []}
	
	@staticmethod
	def RULEDOESNOTEXIST(ruleId):
		return {'response': 'ruleDoesNotExist', 'text': 'Rule with DB ID '+ruleId+' does not exist.'}
	
	@staticmethod
	def FILTERADDED(filterType):
		return {'response': 'filterAdded', 'text': filterType+' successfully added.'}
	
	