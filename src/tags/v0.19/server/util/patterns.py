""" This module is to hava a central place to store all our regex patterns. """

class ConfigPatterns:
	"""Patterns used to parse the configuration-files"""
	RULE = r"(.*)alert(?=.*sid:(\d+))(?=.*rev:(\d+))(?=.*msg:\"(.*?)\";)(?=.*classtype:(.*?);)"
	RULESET = r".*ruleset (.*?)[,;]"
	RULEREFERENCE = r"reference:(.*?),(.*?);"
	REFERENCE = r"config reference: (.*) (http(s)?://.*)"
	CLASS = r"config classification: (.*)"
	GENMSG = r"(\d+ \|\| )+.*"
	SIDMSG = r"(\d+) \|\| ((.*\|\|)* .*)"
	
	#GENMSG = r"(\d+)\s*\|\|\s*(\d+)\s*\|\|\s+(.*)"
	#SIDMSG = r"(\d+)\s*\|\|\s*(.*)"
