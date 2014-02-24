from django.conf.urls import patterns, include, url


# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()
urlpatterns = patterns('',
    # Examples:
    #Main URLs
    url(r'^$', 'web.views.views.index'),
    url(r'^rules/$', 'web.views.views.rules'),

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
    url(r'^rules/page/(?P<pagenr>\d+)/$', 'web.views.requests.getRulePage'),
    #TODO:
    url(r'^rules/byClass/(?P<classname>\w+)/(?P<pagenr>\d+)/$', 'web.views.requests.getRulePageByClass'),
    url(r'^ruleset/set/(?P<rulesetname>\w+)/$', 'web.views.requests.getRuleSet'),
    url(r'^sensors/parent/(?P<sensorname>\w+)/$', 'web.views.requests.getSensor'),
    url(r'^update/(?P<sensorname>\w+)/$', 'web.views.requests.postSensorUpdate'),
    url(r'^update/(?P<sensorname>\w+)/updates$', 'web.views.requests.getSensorUpdatesBySensorName'),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
)

urlpatterns += patterns('web.views.updateviews',
    url(r'^update/$', 'index'),
)
