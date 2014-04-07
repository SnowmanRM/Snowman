""" This module is to hava a central place to store all our regex patterns. """

class ConfigPatterns:
	"""Patterns used to parse the configuration-files"""
	RULE = r"(.*)alert(?=.*sid:\s*(\d+))(?=.*rev:\s*(\d+))(?=.*msg:\s*\"(.*?)\";)(?=.*classtype:\s*(.*?)\s*;)"
	RULESET = r".*ruleset\s*(.*?)\s*[,;]"
	RULEREFERENCE = r"reference:\s*(.*?)\s*,\s*(.*?)\s*;"
	REFERENCE = r"config reference:\s*(.*)\s*(http(s)?://.*)"
	CLASS = r"config classification:\s*(.*)"
	GENMSG = r"(\d+)\s*\|\|\s*(\d+)\s*\|\|\s+(.*)"
	SIDMSG = r"(\d+)\s*\|\|\s*(.*)"
	GID = r"(?=.*gid:\s*(.*?)\s*;)"
	THRESHOLD = r".*threshold:\s*type\s*(.*?)\s*,\s*track\s*(.*?)\s*,\s*count\s*(\d*)\s*,\s*seconds\s*(\d*)\s*;"
	EVENT_FILTER = r"(?:threshold|event_filter)\s*gen_id\s*1\s*,\s*sig_id\s*(\d+)\s*,\s*type\s*(.*?)\s*,\s*track\s*(.*?)\s*,\s*count\s*(\d*)\s*,\s*seconds\s*(\d*)"
	DETECTION_FILTER = r".*detection_filter:\s*track\s*(.*?)\s*,\s*count\s*(\d*)\s*,\s*seconds\s*(\d*)\s*;"
	PRIORITY = r".*priority:\s*(\d+)"
	VALIDIP = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
	VALIDIPMASK = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/([0-9]|[12]?[0-9]|3[0-2])|)$"

