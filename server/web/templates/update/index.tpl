{% extends "general/index.tpl" %}

{% block content %}
	{% load staticfiles %}
	<script type="text/javascript" src="{% static 'js/functions.js' %}"></script>

	<div id="content" class="col-xs-10 col-sm-10 col-md-10 pull-right well">
		<div class="panel panel-default">
			<div class="panel-heading">
				<p>Update status:</p>
			</div>
			<div class="panel-body">
				<h1>Hasd</h1>
				<p>asdgya sd</p>
			</div>
		</div>
	</div>
	<div id="content" class="col-xs-10 col-sm-10 col-md-10 pull-right well">
		<div class="panel panel-default">
			<div class="panel-heading">
				<p>Update sources:</p>
			</div>
			{% if sources and sources|length > 0 %}
				{% for source in sources %}
        			<li class="list-group-item odd">{{ source.name }}</li>
        			<li class="sub-list list-group-item even" style="display: none"><pre>Heisann!</pre></li>
				{% endfor %}
			{% else %}
    			<li class="list-group-item odd">No update-sources is available.</li>
			{% endif %}
		</div>
	</div>
{% endblock %}
