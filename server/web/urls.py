from django.conf.urls import patterns, include, url


# Uncomment the next two lines to enable the admin:
# from django.contrib import admin, auth
# admin.autodiscover()
urlpatterns = patterns('',
    #Main URLs
    url(r'^$', 'web.views.views.index'),

)

urlpatterns += patterns('web.views.sensorviews',
    url(r'^sensors/$', 'index'),

	# AJAX-Calls
    url(r'^sensors/createSensor/$', 'createSensor'),
    url(r'^sensors/editSensor/$', 'editSensor'),
    url(r'^sensors/deleteSensor/$', 'deleteSensor'),
    url(r'^sensors/getCreateSensorForm/$', 'getCreateSensorForm'),
    url(r'^sensors/getEditSensorForm/(?P<sensorID>\d+)/$', 'getEditSensorForm'),
    url(r'^sensors/getSensorChildren/(?P<sensorID>\d+)/$', 'getSensorChildren'),
    url(r'^sensors/regenerateSecret/$', 'regenerateSecret'),
    url(r'^sensors/requestUpdate/$', 'requestUpdate'),
    url(r'^sensors/syncAllSensors/$', 'syncAllSensors'),
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

)

urlpatterns += patterns('web.views.tuningviews',
	url(r'^tuning/$', 'index'),
    url(r'^tuning/getSuppressForm/$', 'getSuppressForm'),
    url(r'^tuning/getSuppressForm/(?P<tuningID>\d+)/$', 'getSuppressFormByID'),
    url(r'^tuning/getFilterForm/$', 'getFilterForm'), 
    url(r'^tuning/getEventFilterForm/(?P<tuningID>\d+)/$', 'getEventFilterFormByID'), 
    url(r'^tuning/getDetectionFilterForm/(?P<tuningID>\d+)/$', 'getDetectionFilterFormByID'), 
    url(r'^tuning/getModifyForm/$', 'getModifyForm'),
    url(r'^tuning/modifyRule/$', 'modifyRule'),
    url(r'^tuning/setSuppressOnRule/$', 'setSuppressOnRule'), 
    url(r'^tuning/setFilterOnRule/$', 'setFilterOnRule'),
    url(r'^tuning/page/(?P<pagenr>\d+)/$', 'tuningPage'),
    url(r'^tuning/search/(?P<pagenr>\d+)/$', 'tuningSearch'),
    url(r'^tuning/deleteTuning/$', 'deleteTuning'),
)

urlpatterns += patterns('web.views.userviews',
	url(r'^users/$', 'index'),
	url(r'^users/getCreateUserForm/$', 'getCreateUserForm'),
	url(r'^users/createUser/$', 'createUser'),
	url(r'^users/deleteUser/$', 'deleteUser'),
	url(r'^users/resetPassword/$', 'resetPassword'),
	url(r'^users/setPageLength/(?P<length>\d+)/$', 'setPageLength'),
	url(r'^users/getResetPasswordForm/$', 'getResetPasswordForm'),
	url(r'^login/$', 'getLoginForm'),
	url(r'^login/authenticate/$', 'authenticateLogin'),
	url(r'^logout/$', 'logoutUser'),
	
)
