{# ruleSet.tpl is the main template for displaying a list of rulesets. #} 
{#  #}


{% extends "general/index.tpl" %}
{% block content %}
{% load staticfiles %}
<script type="text/javascript" src="{% static 'js/ruleset.js' %}"></script>

	

<div id="ruleset-buttons" class="btn-group-vertical btn-block" style="display:none;">
	<button id="create" type="button" class="btn btn-default" data-toggle="modal" data-target="#createRuleSetModal">Create Ruleset</button>
	<button id="edit" type="button" class="btn btn-default" data-toggle="modal" data-target="#editRuleSetModal">Edit Ruleset</button>
	<button id="delete" type="button" class="btn btn-danger" data-toggle="modal" data-target="#deleteRuleSetModal"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Delete Ruleset(s)</button>
	<button id="reorganize" type="button" class="btn btn-default" data-toggle="modal" data-target="#reorganizeRulesModal">Reorganize Rules</button>
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

<div class="modal fade" id="editRuleSetModal" tabindex="-1" role="dialog" aria-labelledby="editRuleSetModal" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
		   <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
		   <h4 class="modal-title" id="editRuleSetModal">Edit Ruleset</h4>
		 </div>
		<div class="modal-body">
		  <form id="editRuleSetForm" class="form-horizontal" role="form">
		  	<div id="formContent">
		  		
		  	</div>
		</div>
		<div class="modal-footer">
		  <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
		  <button type="submit" class="btn btn-primary" id="edit-submit" name="edit-submit">Save changes</button>
		  </form>
		</div>
      
    </div>
  </div>
</div>

<div class="modal fade" id="deleteRuleSetModal" tabindex="-1" role="dialog" aria-labelledby="deleteRuleSetModal" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
		   <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
		   <h4 class="modal-title" id="deleteRuleSetModal">Delete Ruleset(s)</h4>
		 </div>
		<div class="modal-body">
		  <form id="deleteRuleSetForm" class="form-horizontal" role="form">
		  	<div id="formContent">
		  	{% csrf_token %}
		  		<div class="alert alert-danger row">
		  			<div class="col-sm-1">
		  			<span class="glyphicon glyphicon-warning-sign"></span>
		  			</div>
		  			<div class="col-sm-11">
		  				<strong>Are you absolutely sure you want to delete the Ruleset(s)? <br /><br />This cannot be reversed!</strong>
		  			</div>
		  		</div>
		  		<div class="alert alert-danger row">
		  			<div class="col-sm-1">
		  			<span class="glyphicon glyphicon-warning-sign"></span>
		  			</div>
		  			<div class="col-sm-11">
		  				<p>Any rules attached to the ruleset(s) will also be deleted!</p>
		  			</div>
		  		</div>
		  		<div class="alert alert-warning row">
		  			<div class="col-sm-1">
		  			<span class="glyphicon glyphicon-warning-sign"></span>
		  			</div>
		  			<div class="col-sm-11">
		  				<p>The parent of the ruleset(s) will inherit any child rulesets attached.</p>
		  			</div>
		  		</div>
		  	</div>
		</div>
		<div class="modal-footer">
		  <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
		  <button type="submit" class="btn btn-danger" id="delete-submit" name="delete-submit"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Delete Ruleset(s)</button>
		  </form>
		</div>
      
    </div>
  </div>
</div>

<div class="modal fade" id="reorganizeRulesModal" tabindex="-1" role="dialog" aria-labelledby="reorganizeRulesModal" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
		   <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
		   <h4 class="modal-title" id="reorganizeRulesModal">Edit Ruleset</h4>
		 </div>
		<div class="modal-body">
		  <form id="reorganizeRulesForm" class="form-horizontal" role="form">
		  	<div id="formContent">
		  		
		  	</div>
		</div>
		<div class="modal-footer">
		  <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
		  <button type="submit" class="btn btn-primary" id="reorganize-submit" name="reorganize-submit-submit">Save changes</button>
		  </form>
		</div>
      
    </div>
  </div>
</div>
{% endblock %}
