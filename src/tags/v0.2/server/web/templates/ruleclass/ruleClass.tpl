{# manipulateForm.tpl is the template for displaying a list of ruleclasses.. #} 
{#  #}

{% extends "general/index.tpl" %}
{% block content %}
{% load staticfiles %}
<script type="text/javascript" src="{% static 'js/ruleclass.js' %}"></script>
<div id="search-container" class="ruleclass row col-xs-10 col-sm-10 col-md-10 pull-right">
	
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

<div id="content" class="ruleclass col-xs-10 col-sm-10 col-md-10">

{% block ruleset %}

	<div class="ruleclass-panel panel panel-default panel-info">
		<!-- Default panel contents -->
		<div class="panel-heading row">
			<div class="col-xs-1 col-sm-1 col-md-1">
				<input type="checkbox" id="checkbox-all">
			</div>
			<div class="col-xs-7 col-sm-7 col-md-7">
				<h4>Class Name</h4>
			</div>
			<div class="col-xs-1 col-sm-1 col-md-1">
				<h4>Priority</h4>
			</div>
			<div class="col-xs-1 col-sm-1 col-md-1">
				<h4># Rules</h4>
			</div>
			<div class="col-xs-2 col-sm-2 col-md-2">
				<h4># Active</h4>
			</div>
		</div>
	</div>
	{% if ruleclass_list %}
	{% for ruleclass in ruleclass_list %}
		<div id="{{ ruleclass.ruleClassID }}" class="ruleclass-panel panel panel-default">
			<!-- Default panel contents -->
			<div class="panel-heading row">
				<div class="col-xs-1 col-sm-1 col-md-1">
					<input type="checkbox" id="checkbox" ruleclass="{{ ruleclass.ruleClassID }}">
				</div>
				<div class="col-xs-7 col-sm-7 col-md-7">
					<h4>{{ ruleclass.ruleClassName }}</h4>
				</div>
				<div class="col-xs-1 col-sm-1 col-md-1">
					<span class="badge {{ ruleclass.ruleClassPriorityColor }}">{{ ruleclass.ruleClassPriority }}</span>
				</div>
				<div class="col-xs-1 col-sm-1 col-md-1">
					<span class="badge label-default">{{ ruleclass.ruleClassRulesCount }}</span>
				</div>
				<div class="col-xs-1 col-sm-1 col-md-1">
					<span class="badge btn-success">{{ ruleclass.ruleClassActiveRulesCount }}</span>
					<span class="badge btn-danger">{{ ruleclass.ruleClassInActiveRulesCount }}</span>
				</div>
			</div>
			
			<div class="panel-body" style="display:none;">
			<pre class="text-center">{{ ruleclass.ruleClassDescription }}</pre>
			{% if ruleclass.ruleClassRulesCount %}
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
								<ul id="paginator" ruleclass="{{ ruleclass.ruleClassID }}" itemcount="{{ itemcount }}" pagelength="{{ pagelength }}" class="pagination"></ul>
							</div>
						</div>
						
					</div>
					<div id="rules-content" style="display:none;">
					</div>
				</div>
			{% endif %}
			</div>
			
			
		</div>
	{% endfor %}
		    
	{% else %}
	<li class="list-group-item odd">No ruleclasses are available.</li>
	{% endif %}
</div>

{% endblock %}

{% endblock %}
