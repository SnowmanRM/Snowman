#!/usr/bin/python
import os
import sys

# To let a standalone-script use Django, you need to add the path for the root-directory
# of our project to the sys-path. For this script, that is the parent folder, of the folder
# this script is in.
scriptpath = os.path.realpath(__file__)
scriptdir = os.path.dirname(scriptpath)
parentdir = os.path.dirname(scriptdir)
sys.path.append(parentdir)

# Tell where to find the DJANGO settings.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "srm.settings")

from update.updater import Updater

u = Updater()

u.addGenerator(1)
u.addGenerator(3, 3, "Hallo")
u.addGenerator(4, 4, "Hallo")
u.addGenerator(5, 5, "Hallo")
u.addGenerator(6, 5, "Hallo")

u.addClass("Test1", "Endret 1", 1)
u.addClass("Test2", "Endret 2", 2)
u.addClass("Test3", "Testklasse 3", 3)

u.addReferenceType("url", "http://")
u.addReferenceType("hei", "http://hei.com/")

u.addRuleSet("Sett1")
u.addRuleSet("Sett2")

u.addRule(1337, 1, "RAW", "MSG", True, "Sett1", "Test1")
u.addRule(1, 1, "RAW", "MSG", True, "Sett1", "Test1")

u.addReference("url", "Referanse", 1337)
u.addReference("url", "ReferanseNummer2", 1337)
u.addReference("hei", "Referanse2", 1)

u.addSuppress(1337, "by_src", ["1.2.3.4", "1.2.3.5"])

u.saveAll()
u.debug()
