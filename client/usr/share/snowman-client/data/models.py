#!/usr/bin/python
from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, backref

from util.config import Config

Base = declarative_base()

class Session():
	"""The databse-class is responsible for the sqlalchemy sessions which is connecting
	to the database. To get a session-object for your database-work, you can use 
	Session.session()."""
	engine = None
	session = None
	
	@staticmethod
	def _initialize():
		"""This method reads the database-configuration from the configuration-files, and
		initializes the connection to the databse. It also makes sure that the db-schema
		is created and present."""

		# Read the configuration from file:
		dbType = Config.get("localdb", "type")
		dbName = Config.get("localdb", "name")
		dbHost = Config.get("localdb", "hostname")
		dbUser = Config.get("localdb", "username")
		dbPass = Config.get("localdb", "password")
		
		# Construct the dbPath string, or rais an exception if the dbtype is unknown.
		if(dbType == "sqlite"):
			dbpath = 'sqlite:///' + dbName
		elif(dbType == "mysql"):
			dbpath = dbType + "://" + dbUser + ":" + dbPass + "@" + dbHost + "/" + dbName
		else:
			raise Exception("DatabaseConfiguration is not correct")
		
		# Create a dbengine, and depending on the configfile maybe turn on the debug.
		if(Config.get("localdb", "debug") == "0"):
			Session.engine = create_engine(dbpath)
		else:
			Session.engine = create_engine(dbpath, echo=True)
		
		# Create a session, and bind it to the engine.
		Session.session = sessionmaker(bind=Session.engine)
		
		# Making sure that the dbSchema is created.
		Base.metadata.create_all(Session.engine)

class Rule(Base):
	"""This class represents a single revision of a rule. As it i intended to be used
	on the srm-client, a single revision is enough, and we do not need to add functionality
	to turn it on or off (If a rule is off, it is not sent to the client)"""
	__tablename__ = 'rule'

	# Assign datamembers
	id = Column(Integer, primary_key=True)
	ruleset_id = Column(Integer, ForeignKey('ruleset.id'))
	ruleclass_id = Column(Integer, ForeignKey('ruleclass.id'))
	SID = Column(Integer)
	rev = Column(Integer)
	raw = Column(Text)
	msg = Column(Text)

	# Assign foreign-key referrers
	ruleset = relationship("RuleSet", backref=backref('rules', order_by=id))
	ruleclass = relationship("RuleClass", backref=backref('rules', order_by=id))

	def __init__(self, sid, rev, raw, msg):
		self.SID = sid
		self.rev = rev
		self.raw = raw
		self.msg = msg

	def __repr__(self):
		return "<Rule ('%d','%d', '%s', '%s')>" % (self.SID, self.rev, self.raw, self.msg)
	
	def __str__(self):
		return "<Rule ('%d','%d')>" % (self.SID, self.rev)

class RuleSet(Base):
	"""Represents a single ruleset on a sensor."""
	__tablename__ = 'ruleset'

	id = Column(Integer, primary_key=True)
	name = Column(String(40))
	description = Column(Text)
	
	def __init__(self, name, description):
		self.name = name
		self.description = description
	
	def __repr__(self):
		return "<RuleSet ('%s', '%s')>" % (self.name, self.description)
	
	def __str__(self):
		return "<RuleSet ('%s', '%s')>" % (self.name, self.description)

class Suppress(Base):
	"""Suppression of a single rule on certain addresses."""
	__tablename__ = 'suppress'

	TRACK = {1: "by_src", 2: "by_dst"}

	id = Column(Integer, primary_key=True)
	rule_id = Column(Integer, ForeignKey('rule.id'))
	track = Column(Integer)
	
	# Assign foreign-key referrers
	rule = relationship("Rule", backref=backref('suppress', order_by=id))
	
	def __init__(self, track):
		self.track = track
	
	def __repr__(self):
		return "<Suppress ('%s', '%s', '%s')>" % (self.rule, self.comment, self.addresses)

	def __str__(self):
		return "<Suppress ('%s', '%s')>" % (self.rule, self.comment)
	
	def getConfigString(self):
		addresses = ""
		for a in self.addresses:
			if(len(addresses) > 0):
				addresses += " "
			addresses += str(a.address)
		return "suppress gen_id 1, sig_id %d, track %s, ip %s" % (self.rule.SID, Suppress.TRACK[self.track], addresses)

class SuppressAddress(Base):
	"""An IP-Address used by a suppression."""
	__tablename__ = 'suppressaddress'

	id = Column(Integer, primary_key=True)
	suppress_id = Column(Integer, ForeignKey('suppress.id'))
	address = Column(String(40))
	
	# Assign foreign-key referrers
	suppress = relationship("Suppress", backref=backref('addresses', order_by=id))
	
	def __init__(self, address):
		self.address = address

	def __repr__(self):
		return "<SuppressAddress ('%s')>" % (self.address)

	def __str__(self):
		return "<SuppressAddress ('%s')>" % (self.address)

class DetectionFilter(Base):
	__tablename__ = 'detectionfilter'

	id = Column(Integer, primary_key=True)
	rule_id = Column(Integer, ForeignKey('rule.id'))
	track = Column(Integer)
	count = Column(Integer)
	seconds = Column(Integer)
	
	# Assign foreign-key referrers
	rule = relationship("Rule", backref=backref('detectionfilter', order_by=id))

	def __init__(self, track, count, seconds):
		self.track = track
		self.count = count
		self.seconds = seconds

	def __repr__(self):
		return "<DetectionFilter ('%d','%d','%d')>" % (self.track, self.count, self.seconds)

	def __str__(self):
		return "<DetectionFilter ('%d','%d','%d')>" % (self.track, self.count, self.seconds)

class EventFilter(Base):
	__tablename__ = 'eventfilter'
	
	TYPE = {1: "limit", 2: "threshold", 3:"both"}
	TRACK = {1: "by_src", 2: "by_dst"}
	REVTRACK = {'by_src': 1, 'by_dst': 2}

	id = Column(Integer, primary_key=True)
	rule_id = Column(Integer, ForeignKey('rule.id'))
	filtertype = Column(Integer)
	track = Column(Integer)
	count = Column(Integer)
	seconds = Column(Integer)
	
	# Assign foreign-key referrers
	rule = relationship("Rule", backref=backref('eventfilter', order_by=id))

	def __init__(self, ttype, track, count, seconds):
		self.filtertype = ttype
		self.track = track
		self.count = count
		self.seconds = seconds

	def __repr__(self):
		return "<EventFilter ('%d', '%d','%d','%d')>" % (self.filtertype, self.track, self.count, self.seconds)

	def __str__(self):
		return "<EventFilter ('%d', '%d','%d','%d')>" % (self.filtertype, self.track, self.count, self.seconds)


class StaticFile(Base):
	"""A static file, which is supposed to be delivered to the sensor, without further processing."""
	__tablename__ = 'staticfile'
	
	id = Column(Integer, primary_key=True)
	name = Column(String(80))
	path = Column(String(80))
	checksum = Column(String(80))

	def __init__(self, name, path, checksum):
		self.name = name
		self.path = path
		self.checksum = checksum

	def __repr__(self):
		return "<StaticFile ('%s','%s','%s')>" % (self.name, self.path, self.checksum)

	def __str__(self):
		return "<StaticFile ('%s')>" % (self.name)

class RuleClass(Base):
	"""A ruleclass. All rules should be a part of a class. The client also uses these classes to
	generate the classifications.conf file for SNORT"""
	__tablename__ = 'ruleclass'
	
	id = Column(Integer, primary_key=True)
	classtype = Column(String(80))
	description = Column(String(160))
	priority = Column(Integer)
	
	def __init__(self, classtype, description, priority):
		self.classtype = classtype
		self.description = description
		self.priority = priority
	
	def __repr__(self):
		return "<RuleClass ('%s','%s','%d')>" % (self.classtype, self.description, self.priority)
	
	def __str__(self):
		return "<RuleClass ('%s','%s','%d')>" % (self.classtype, self.description, self.priority)

class RuleReference(Base):
	"""Rules contains references, which make snort able to create links explaining the rules. This
	class is to represent a reference, and is of a certain type, belonging to a certain Rule"""
	__tablename__ = 'rulereference'
	
	id = Column(Integer, primary_key=True)
	reference = Column(String(240))
	rule_id = Column(Integer, ForeignKey('rule.id'))
	referencetype_id = Column(Integer, ForeignKey('rulereferencetype.id'))
	
	# Assign foreign-key referrers
	rule = relationship("Rule", backref=backref('references', order_by=id))
	referenceType = relationship("RuleReferenceType", backref=backref('references', order_by=id))
	
	def __init__(self, reference):
		self.reference = reference
	
	def __repr__(self):
		return "<RuleReference ('%s')>" % (self.reference)

	def __str__(self):
		return "<RuleReference ('%s')>" % (self.reference)

class RuleReferenceType(Base):
	"""A RuleReference needs to be of a specific type. This class defines these types. A type have
	a name, and an urlPrefix. When a prefixlink is generated, Snort takes the urlprefix, and just
	simply append the reference to this prefix."""
	__tablename__ = 'rulereferencetype'

	id = Column(Integer, primary_key=True)
	name = Column(String(80))
	prefix = Column(String(200))
	
	def __init__(self, name, prefix):
		self.name = name
		self.prefix = prefix
	
	def __repr__(self):
		return "<RuleReferenceType ('%s','%s')>" % (self.name, self.prefix)
		
	def __str__(self):
		return "<RuleReferenceType ('%s')>" % (self.name)

class Generator(Base):
	"""The spesifications for a generator.
	
	Currently only used for gen-msg.map"""
	__tablename__ = 'generator'
		
	id = Column(Integer, primary_key=True)
	gid = Column(Integer)
	alertId = Column(Integer)
	message = Column(String(160))
	
	def __init__(self, gid, alertId, message):
		self.gid = gid
		self.alertId = alertId
		self.message = message
	
	def __repr__(self):
		return "<Generator ('%d', '%d', '%s')>" % (self.gid, self.alertID, self.message)
		
	def __str__(self):
		return "<Generator ('%s')>" % (self.message)

Session._initialize()
