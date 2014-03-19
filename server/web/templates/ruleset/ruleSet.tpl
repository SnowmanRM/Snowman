{# manipulateForm.tpl is the template for displaying a list of rulesets.. #} 
{#  #}


{% extends "general/index.tpl" %}
{% block content %}
{% load staticfiles %}
<script type="text/javascript" src="{% static 'js/ruleset.js' %}"></script>
<div id="search-container" class="ruleset row col-xs-10 col-sm-10 col-md-10 pull-right">
	
	{% csrf_token %}
	<div id="ruleset-buttons" class="btn-group pull-right">
		<button id="create" type="button" class="btn btn-default" data-toggle="modal" data-target="#createRuleSetModal">Create Ruleset</button>
		<button id="edit" type="button" class="btn btn-default" data-toggle="modal" data-target="#ruleSetModal">Edit Ruleset</button>
		<button id="edit" type="button" class="btn btn-danger" data-toggle="modal" data-target="#ruleSetModal"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Delete Ruleset</button>
		<button id="organize" type="button" class="btn btn-default" data-toggle="modal" data-target="#ruleSetModal">Organize Rulesets</button>
		<button id="organize" type="button" class="btn btn-default" data-toggle="modal" data-target="#ruleSetModal">Organize Rules</button>
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
	{% block rulesetlist %}
	{% include "ruleset/ruleSetListItems.tpl" %}
	{% endblock %}
</div>

{% endblock %}
<div class="modal fade" id="createRuleSetModal" tabindex="-1" role="dialog" aria-labelledby="createRuleSetModal" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
		   <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
		   <h4 class="modal-title" id="createRuleSetModal">Create Ruleset</h4>
		 </div>
		<div class="modal-body">
		  <form id="createRuleSetForm" class="form-horizontal" role="form">
		  	<div id="formContent">
		  		
		  	</div>
		</div>
		<div class="modal-footer">
		  <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
		  <button type="submit" class="btn btn-primary" id="create-submit" name="create-submit">Save changes</button>
		  </form>
		</div>
      
    </div>
  </div>
</div>
{% endblock %}
