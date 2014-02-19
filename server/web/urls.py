from django.conf.urls import patterns, include, url


# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()
urlpatterns = patterns('',
    # Examples:
    url(r'^$', 'web.views.index'),
    url(r'^ruleview2', 'web.views.ruleview2'),
    url(r'^getrulelistrange/(?P<minrange>\d+)/(?P<maxrange>\d+)', 'web.views.getRuleListRange'),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
)
