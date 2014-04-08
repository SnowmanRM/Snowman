#!/usr/bin/python
import os
import shutil
import sys

def createRefConf(path):
	f = open(os.path.join(path, "reference.config"), "w")
	f.write("config reference: url       http://\n")
	f.close()

def createRuleFile(SID, path, name, noRules):
	f = open(os.path.join(path, name), "w")
	for i in range(noRules):
		SID = SID + 1
		f.write("""alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"INDICATOR-COMPROMISE c99shell.php command request - security"; flow:to_server,established; urilen:<50; content:"act=security"; fast_pattern:only; http_uri; metadata:service http; reference:url,vil.nai.com/vil/content/v_136948.htm; classtype:policy-violation; sid:%d; rev:2;)\n""" % SID)
	f.close()

if __name__ == "__main__":
	path = "/tmp/ruleset/"
	SID = 40000000
	rulesPerFile = 10
	
	if(len(sys.argv) > 1):
		noRules = int(sys.argv[1])
	else:
		noRules = 10

	if os.path.exists(path):
		shutil.rmtree(path)
	os.makedirs(path)
	
	createRefConf(path)
	
	done = 0
	while done < noRules:
		if(noRules - done < rulesPerFile):
			r = noRules - done
		else:
			r = rulesPerFile
			
		createRuleFile(SID, path, "test%d.rules" % done, r)
		SID = SID + r
		done += r
