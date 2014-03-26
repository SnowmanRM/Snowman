{% extends "general/index.tpl" %}
{# rules.tpl is the template for the rules page. #} 
{# It contains a list of all rules present in the database. #}
{# It can also contain a list rules found through a search, which the user can do in the searchbar. #}

{% block content %}
{% load staticfiles %}
<script type="text/javascript" src="{% static 'js/tuning.js' %}"></script>
<div id="search-container" class="ruleset row col-xs-12 col-sm-102 col-md-12 pull-right">
	<div class="pull-left">
			<ul id="paginator" itemcount="{{ itemcount }}" pagelength="{{ pagelength }}" class="pagination">
				
			</ul>
		</div>
	{% csrf_token %}
	<div id="tuning-buttons" class="btn-group pull-right">
		<button id="edit" type="button" class="btn btn-default" data-toggle="modal" data-target="#editRuleSetModal">Edit Tuning</button>
		<button id="delete" type="button" class="btn btn-danger" data-toggle="modal" data-target="#deleteRuleSetModal"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Delete Tuning</button>
	</div>	
	
</div>
<div id="content" class="tuning col-xs-12 col-sm-12 col-md-12 well">

{% block rules %}

{% include "tuning/tuningPage.tpl" %}
		
{% endblock %}


</div>

{% endblock %}