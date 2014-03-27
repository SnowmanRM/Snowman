from django.conf.urls import patterns, include, url


# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()
urlpatterns = patterns('',
    #Main URLs
    url(r'^$', 'web.views.views.index'),

    #TODO:
    
    url(r'^ruleset/bysensor/active/$', 'web.views.views.ruleSetBySensorActive'),
    url(r'^ruleset/bysensor/new/$', 'web.views.views.ruleSetBySensorNew'),
    url(r'^tuning/bysensor/$', 'web.views.views.tuningBySensor'),
    
    url(r'^tuning/bysensor/(?P<sensorname>\w+)/$', 'web.views.views.tuningBySensorName'),
    
    
    # URLs used for AJAX requests
    #TODO:
    url(r'^rules/byClass/(?P<classname>\w+)/(?P<pagenr>\d+)/$', 'web.views.requests.getRulePageByClass'),
    url(r'^ruleset/set/(?P<rulesetname>\w+)/$', 'web.views.requests.getRuleSet'),
    url(r'^sensors/parent/(?P<sensorname>\w+)/$', 'web.views.requests.getSensor'),
    #url(r'^update/(?P<sensorname>\w+)/$', 'web.views.requests.postSensorUpdate'),
    #url(r'^update/(?P<sensorname>\w+)/updates$', 'web.views.requests.getSensorUpdatesBySensorName'),
)

urlpatterns += patterns('web.views.sensorviews',
    url(r'^sensors/$', 'index'),

	# AJAX-Calls
    url(r'^sensors/new/$', 'new'),
    url(r'^sensors/getSensorList/$', 'getSensorList'),
    url(r'^sensors/regenerateSecret/$', 'regenerateSecret'),
)
urlpatterns += patterns('web.views.updateviews',
    url(r'^update/$', 'index'),
    url(r'^update/changes/$', 'changes'),
    url(r'^update/changes/removeUpdate/(?P<updateID>\d+)/$', 'removeUpdate'),
    url(r'^update/editSource/(?P<id>\d+)/$', 'editSource'),
    url(r'^update/getManualUpdateForm/$', 'getManualUpdateForm'),
    url(r'^update/getSourceList/$', 'getSourceList'),
	url(r'^update/getStatus/(?P<id>\d+)/$', 'getStatus'),
	url(r'^update/getTimeSelector/(?P<interval>[wdmn])/$', 'getTimeSelector'),
    url(r'^update/newSource/$', 'newSource'),
	url(r'^update/runUpdate/(?P<id>\d+)/$', 'runUpdate'),
)
urlpatterns += patterns('web.views.ruleviews',
    url(r'^rules/$', 'index'),
    url(r'^rules/page/search/(?P<pagenr>\d+)/$', 'getRulesBySearch'),
    url(r'^rules/ruleSet/(?P<ruleSetID>\d+)/(?P<pagenr>\d+)/$', 'getRulesByRuleSet'),
    url(r'^rules/ruleClass/(?P<ruleClassID>\d+)/(?P<pagenr>\d+)/$', 'getRulesByRuleClass'),
    url(r'^rules/page/(?P<pagenr>\d+)/$', 'getRulePage'),
    url(r'^rules/reorganizeRules/$', 'reorganizeRules'),
    url(r'^rules/ruleSetNewRules/(?P<ruleSetID>\d+)/(?P<pagenr>\d+)/(?P<updateID>\d+)/$', 'getRulesByRuleSetNewRules'),
    url(r'^rules/ruleSetNewRuleRevisions/(?P<ruleSetID>\d+)/(?P<pagenr>\d+)/(?P<updateID>\d+)/$', 'getRulesByRuleSetNewRuleRevisions'),
    
)
urlpatterns += patterns('web.views.rulesetviews',
    url(r'^ruleSet/$', 'index'),
	url(r'^ruleset/children/(?P<ruleSetID>\d+)/$', 'getRuleSetChildren'),
	url(r'^ruleset/getCreateRuleSetForm/$', 'getCreateRuleSetForm'),
	url(r'^ruleset/createRuleSet/$', 'createRuleSet'),
	url(r'^ruleset/getEditRuleSetForm/(?P<ruleSetID>\d+)/$', 'getEditRuleSetForm'),
	url(r'^ruleset/editRuleSet/$', 'editRuleSet'),
	url(r'^ruleset/deleteRuleSet/$', 'deleteRuleSet'),
	url(r'^ruleset/getReorganizeRulesForm/$', 'getReorganizeRulesForm'),
	url(r'^ruleset/updateSets/(?P<updateID>\d+)/$', 'getRuleSetByUpdate'),
	url(r'^ruleset/updateRules/(?P<updateID>\d+)/$', 'getRuleSetByUpdateNewRules'),
	url(r'^ruleset/updateRuleRevisions/(?P<updateID>\d+)/$', 'getRuleSetByUpdateNewRuleRevisions'),

)
urlpatterns += patterns('web.views.ruleclassviews',
    url(r'^ruleClass/$', 'index'),
   # url(r'^ruleset/children/(?P<ruleSetID>\d+)/$', 'getRuleSetChildren'),

)

urlpatterns += patterns('web.views.tuningviews',
    url(r'^tuning/getSuppressForm/$', 'getSuppressForm'),
    url(r'^tuning/getThresholdForm/$', 'getThresholdForm'), 
    url(r'^tuning/getModifyForm/$', 'getModifyForm'),
    url(r'^tuning/modifyRule/$', 'modifyRule'),
    url(r'^tuning/setSuppressOnRule/$', 'setSuppressOnRule'), 
    url(r'^tuning/setFilterOnRule/$', 'setFilterOnRule'),
    url(r'^tuning/byRule/$', 'tuningByRule'),
    url(r'^tuning/byRule/page/(?P<pagenr>\d+)/$', 'tuningByRulePage'),
)
