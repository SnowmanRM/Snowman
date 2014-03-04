from django.conf.urls import patterns, include, url


# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()
urlpatterns = patterns('',
    #Main URLs
    url(r'^$', 'web.views.views.index'),

    #TODO:
    url(r'^ruleset/$', 'web.views.views.ruleSet'),
    url(r'^ruleset/bysensor/active/$', 'web.views.views.ruleSetBySensorActive'),
    url(r'^ruleset/bysensor/new/$', 'web.views.views.ruleSetBySensorNew'),
    url(r'^ruleclass/$', 'web.views.views.ruleclass'),
    url(r'^sensors/$', 'web.views.views.sensors'),
    url(r'^tuning/bysensor/$', 'web.views.views.tuningBySensor'),
    url(r'^tuning/byrule/$', 'web.views.views.tuningByRule'),
    url(r'^tuning/bysensor/(?P<sensorname>\w+)/$', 'web.views.views.tuningBySensorName'),
    
    
    # URLs used for AJAX requests
    #TODO:
    url(r'^rules/byClass/(?P<classname>\w+)/(?P<pagenr>\d+)/$', 'web.views.requests.getRulePageByClass'),
    url(r'^ruleset/set/(?P<rulesetname>\w+)/$', 'web.views.requests.getRuleSet'),
    url(r'^sensors/parent/(?P<sensorname>\w+)/$', 'web.views.requests.getSensor'),
    #url(r'^update/(?P<sensorname>\w+)/$', 'web.views.requests.postSensorUpdate'),
    #url(r'^update/(?P<sensorname>\w+)/updates$', 'web.views.requests.getSensorUpdatesBySensorName'),
)

urlpatterns += patterns('web.views.updateviews',
    url(r'^update/$', 'index'),
    url(r'^update/newSource/$', 'newSource'),
    url(r'^update/editSource/(?P<id>\d+)/$', 'editSource'),
    url(r'^update/getSourceList/$', 'getSourceList'),
    url(r'^update/getManualUpdateForm/$', 'getManualUpdateForm'),
	url(r'^update/getTimeSelector/(?P<interval>[wdmn])/$', 'getTimeSelector'),
	url(r'^update/runUpdate/(?P<id>\d+)/$', 'runUpdate'),
)
urlpatterns += patterns('web.views.ruleviews',
    url(r'^rules/$', 'index'),
    url(r'^rules/page/search/(?P<pagenr>\d+)/$', 'getRulesBySearch'),
    url(r'^rules/page/(?P<pagenr>\d+)/$', 'getRulePage'),
)

