{% extends "general/index.tpl" %}
{% block content %}
{% load staticfiles %}
<script type="text/javascript" src="{% static 'js/ruleset.js' %}"></script>
<div id="search-container" class="ruleset row col-xs-10 col-sm-10 col-md-10 pull-right">
	
	{% csrf_token %}
	<div class="input-group col-xs-6 col-sm-6 col-md-6 col-lg-6 pull-right">
		
		<select id="searchfield" class="form-control">
			<option value="sid">Name</option>
			
		</select>
		<span class="input-group-btn">
			<button class="btn btn-default" type="button">Search</button>
		</span>
		<input id="searchtext" type="text" class="form-control">
	</div>
	
</div>

{% block manipulator %}

{% include "general/manipulator.tpl" %}
		
{% endblock %}

<div id="content" class="ruleset col-xs-10 col-sm-10 col-md-10">

{% block ruleset %}

	<div class="ruleset-panel panel panel-default panel-info">
		<!-- Default panel contents -->
		<div class="panel-heading row">
			<div class="col-xs-1 col-sm-1 col-md-1">
				<input type="checkbox" id="checkbox-all">
			</div>
			<div class="col-xs-6 col-sm-6 col-md-6">
				<h4>Ruleset Name</h4>
			</div>
			<div class="col-xs-1 col-sm-1 col-md-1">
				<h4># Rules</h4>
			</div>
			<div class="col-xs-2 col-sm-2 col-md-2">
				<h4># Active</h4>
			</div>
			<div class="col-xs-1 col-sm-1 col-md-1">
				<h4>Sensors</h4>
			</div>
			<div class="col-xs-1 col-sm-1 col-md-1">
				<h4>On/Off</h4>
			</div>
		</div>
	</div>
	{% if ruleset_list %}
	{% for ruleset in ruleset_list %}
		<div id="{{ ruleset.ruleSetID }}" class="ruleset-panel panel panel-default">
			<!-- Default panel contents -->
			<div class="panel-heading row">
				<div class="col-xs-1 col-sm-1 col-md-1">
					<input type="checkbox" id="checkbox" ruleset="{{ ruleset.ruleSetID }}" rulesetname="{{ ruleset.ruleSetName }}">
				</div>
				<div class="col-xs-6 col-sm-6 col-md-6">
					<h4>{{ ruleset.ruleSetName }}</h4>
				</div>
				<div class="col-xs-1 col-sm-1 col-md-1">
					<span class="badge label-default">{{ ruleset.ruleSetRulesCount }}</span>
				</div>
				<div class="col-xs-2 col-sm-2 col-md-2">
					<span class="badge btn-success">{{ ruleset.ruleSetActiveRulesCount }}</span>
					<span class="badge btn-danger">{{ ruleset.ruleSetInActiveRulesCount }}</span>
				</div>
				<div class="col-xs-1 col-sm-1 col-md-1">
					<span class="badge btn-success">{{ ruleset.ruleSetActiveOnSensorsCount }}</span>
					<span class="badge btn-danger">{{ ruleset.ruleSetInActiveOnSensorsCount }}</span>
				</div>
				<div class="col-xs-1 col-sm-1 col-md-1">
					{% if ruleset.ruleSetActive %}<span id="onoff" class="badge btn-success">ON</span>
					{% else %} <span id="onoff" class="badge btn-danger">OFF</span> 
					{% endif %}
				</div>
			</div>
			{% if ruleset.ruleSetRulesCount %}
			<div class="panel-body" style="display:none;">
				<div id="rules" class="rules-panel panel panel-default">
					<!-- Default panel contents -->
					<div class="panel-heading row">
						<div class="col-xs-5 col-sm-5 col-md-5">
							
						</div>
						<div class="col-xs-2 col-sm-2 col-md-2">
							<h4>Rules</h4>
						</div>
						<div id="paginator-container" class="col-xs-5 col-sm-5 col-md-5">
							<div class="pull-right">
								<ul id="paginator" ruleset="{{ ruleset.ruleSetID }}" itemcount="{{ itemcount }}" pagelength="{{ pagelength }}" class="pagination"></ul>
							</div>
						</div>
						
					</div>
					<div id="rules-content" style="display:none;">
					</div>
				</div>
			</div>
			{% endif %}
			
		</div>
	{% endfor %}
		    
	{% else %}
	<li class="list-group-item odd">No rulesets are available.</li>
	{% endif %}
</div>

{% endblock %}

{% endblock %}
