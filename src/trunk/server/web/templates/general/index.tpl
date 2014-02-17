<!DOCTYPE html>
<html>
<head>
	{% load staticfiles %}
	<link type="text/css" rel="stylesheet" href="{% static 'style.css' %}" media="screen">
	<script type="text/javascript" src="{% static 'js/jquery-1.11.0.js' %}"></script>
	<script type="text/javascript" src="{% static 'js/nav.js' %}"></script>
	<title>{% block title %} {{ title|default:"Snort Rule Manager" }} {% endblock %}</title>
</head>
<body>
	<div id="wrap">
		<div id="content-wrapper" class="">
			<div id="nav" class="">
				{% block nav %}
				{% include "general/nav.tpl" %}
				{% endblock %}
			</div>
			<div id="content-manipulator-wrap">
				<div id="manipulator">
					{% block manipulator %}
					{% endblock %}		
				</div>
				<div id="content">
					{% block content %}
					{% endblock %}	
				</div>
			</div>
		</div>
		<div id="console-wrapper" class="">
			{% block console %}
			{% include "general/console.tpl" %}
			{% endblock %}
		</div>		
			
	</div>
</body>

</html>