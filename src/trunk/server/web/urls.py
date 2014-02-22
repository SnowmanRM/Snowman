from django.conf.urls import patterns, include, url


# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()
urlpatterns = patterns('',
    # Examples:
    #Main URLs
    url(r'^$', 'web.views.index'),
    url(r'^rules/$', 'web.views.rules'),
    #TODO:
    url(r'^ruleset/$', 'web.views.ruleSet'),
    url(r'^ruleset/bysensor/active/$', 'web.views.ruleSetBySensorActive'),
    url(r'^ruleset/bysensor/new/$', 'web.views.ruleSetBySensorNew'),
    url(r'^ruleclass/$', 'web.views.ruleclass'),
    url(r'^update/$', 'web.views.update'),
    url(r'^updates/$', 'web.views.updates'),
    url(r'^sensors/$', 'web.views.sensors'),
    url(r'^tuning/bysensor/$', 'web.views.tuningBySensor'),
    url(r'^tuning/byrule/$', 'web.views.tuningByRule'),
    url(r'^tuning/bysensor/(?P<sensorname>\w+)/$', 'web.views.tuningBySensorName'),
    
    
    # URLs used for AJAX requests
    url(r'^rules/page/(?P<pagenr>\d+)/$', 'web.requests.getRulePage'),
    #TODO:
    url(r'^rules/byClass/(?P<classname>\w+)/(?P<pagenr>\d+)/$', 'web.requests.getRulePageByClass'),
    url(r'^ruleset/set/(?P<rulesetname>\w+)/$', 'web.requests.getRuleSet'),
    url(r'^sensors/parent/(?P<sensorname>\w+)/$', 'web.requests.getSensor'),
    url(r'^update/(?P<sensorname>\w+)/$', 'web.requests.postSensorUpdate'),
    url(r'^update/(?P<sensorname>\w+)/updates$', 'web.requests.getSensorUpdatesBySensorName'),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
)
