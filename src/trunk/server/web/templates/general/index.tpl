{# index.tpl is the main template for the website. #} 
{# It contains the main structure of the page and loads the global static files. #}
{#  #}

<!DOCTYPE html>
<html>
<head>
	{% load staticfiles %}
	<link type="text/css" rel="stylesheet" href="{% static 'css/style.css' %}" media="screen">
	<link type="text/css" rel="stylesheet" href="{% static 'css/bootstrap.css' %}" media="screen">
	<link type="text/css" rel="stylesheet" href="{% static 'css/bootstrap-theme.css' %}" media="screen">
	<!--<link type="text/css" rel="stylesheet" href="//netdna.bootstrapcdn.com/twitter-bootstrap/2.3.1/css/bootstrap-combined.min.css" media="screen">-->
	<script type="text/javascript" src="{% static 'js/jquery-1.11.0.js' %}"></script>
	<script type="text/javascript" src="{% static 'js/functions.js' %}"></script>
	<script type="text/javascript" src="{% static 'js/bootstrap.js' %}"></script>
	<script type="text/javascript" src="{% static 'js/bootstrap-paginator.js' %}"></script>
	
	<title>{% block title %} {{ title|default:"Snort Rule Manager" }} {% endblock %}</title>
</head>
<body>
			
		
		<div id="wrap" class="container no-padding">
			{% block nav %}
			{% include "general/nav.tpl" %}
			{% endblock %}
			<div id="content-wrap" class="row container">

					{% block content %}
					{% endblock %}	
				
			</div>
		</div>
		<div id="console-wrapper" class="">
			{% block console %}
			{% include "general/console.tpl" %}
			{% endblock %}
		</div>		
		
</body>

</html>