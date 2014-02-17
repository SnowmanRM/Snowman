from core.models import *
from tuning.models import *
from update.models import *


# Tests for core
sensor = Sensor.objects.first()
ruleset = RuleSet.objects.first()
rulereferencetype = RuleReferenceType.objects.first()
ruleclass = RuleClass.objects.first()
rule = Rule.objects.first()
rulerevision = RuleRevision.objects.first()
rulereference = RuleReference.objects.first()

print sensor
print repr(sensor)
print ruleset
print repr(ruleset)
print rulereferencetype
print repr(rulereferencetype)
print ruleclass
print repr(ruleclass)
print rule
print repr(rule)
print rulerevision
print repr(rulerevision)
print rulereference
print repr(rulereference)

# Tests for tuning
modifier = RuleModifier.objects.first()
supress = Supress.objects.first()
supressaddress = SupressAddress.objects.first()
threshold = Threshold.objects.first()

print modifier
print repr(modifier)
print supress
print repr(supress)
print supressaddress
print repr(supressaddress)
print threshold
print repr(threshold)

# Tests for update
source = Source.objects.first()
update = Update.objects.first()
updatefile = UpdateFile.objects.first()
staticfile = StaticFile.objects.first()
rc = RuleChanges.objects.first()

print source
print repr(source)
print update
print repr(update)
print updatefile
print repr(updatefile)
print staticfile
print repr(staticfile)
print rc
print repr(rc)
