from core.models import *
from tuning.models import *
from update.models import *

# Data for core
sensor = Sensor.objects.create(name="MySensorName", active=True, ipAddress="127.0.0.1", secret="abcd")
generator = Generator.objects.create(GID=1, alertID=1, message="Generic SNORT rule")
ruleset = RuleSet.objects.create(name="MyRuleSet", description="My first ruleset.", active=True)
rulereferencetype = RuleReferenceType.objects.create(name="url", urlPrefix="http://")
ruleclass = RuleClass.objects.create(classtype="default", description="The default Rule-class", priority=4)
rule = Rule.objects.create(SID=1, generator=generator, active=True, ruleSet=ruleset, ruleClass=ruleclass)
rulerevision = RuleRevision.objects.create(rule=rule, rev=1, active=True, msg="Message", raw="The raw snort-rule")
rulereference = RuleReference.objects.create(reference="foo.bar/123", referenceType=rulereferencetype, rulerevision=rulerevision)

# Data for tuning
modifier = RuleModifier.objects.create(rule=rule, sensor=sensor, active=None)
supress = Supress.objects.create(rule=rule, sensor=sensor, comment="My first Supress", track=Supress.SOURCE)
supressaddress = SupressAddress.objects.create(supress=supress, ipAddress="127.0.0.2")
threshold = Threshold.objects.create(rule=rule, sensor=sensor, comment="My first Threshold", thresholdType=Threshold.LIMIT, track=Threshold.SOURCE, count=42, seconds=60)

# Data for update
source = Source.objects.create(name="Manual", schedule="00:00", url="", lastMd5="")
update = Update.objects.create(time="2014-01-01", source=source)
updatefile = UpdateFile.objects.create(name="a.txt", update=update, checksum="abc")
staticFile = StaticFile.objects.create(name="a.txt", update=update, checksum="abc", path="/test/av/path/")
rc = RuleChanges.objects.create(rule=rule, originalSet=ruleset, newSet=ruleset, update=update, moved=False)
