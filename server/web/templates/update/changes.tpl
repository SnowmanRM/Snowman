{# changes.tpl is the main template for displaying a list of changes in various updates. #} 

{% extends "general/index.tpl" %}

{% block content %}
	{% load staticfiles %}
	<script type="text/javascript" src="{% static 'js/update.js' %}"></script>
	
	<script type="text/javascript" src="{% static 'js/ruleset.js' %}"></script>
	<script type="text/javascript" src="{% static 'js/changes.js' %}"></script>

	{% block manipulator %}

	{% include "general/manipulator.tpl" %}
			
	{% endblock %}
	<div id="content" class="changes col-xs-10 col-sm-10 col-md-10 pull-right">
		<div class="update-panel panel panel-info">
			<div class="panel-heading row">
				<div class="col-sm-4">
					<h3>Source:</h3>  
				</div>
				<div class="col-sm-4">
					<h3>Update Time:</h3>  
				</div>
				<div class="col-sm-2">
					<h3>Total changes:</h3>
				</div>
				<div class="col-sm-2 text-right">
					
				</div>
			</div>
		</div>
		{% for update in updates %}
		<div class="update-panel panel panel-default" id="{{update.updateID}}">
			<div class="update panel-heading row">
				<div class="col-sm-4">
					<h3>{{update.updateName}}</h3>  
				</div>
				<div class="col-sm-4">
					<h3>{{update.updateTime|date:"Y-m-d h:m:s"}}</h3>  
				</div>
				<div class="col-sm-2">
					<span class="badge btn-success"><h3>{{update.updateChangeCount}}</h3></span>
				</div>
				<div class="col-sm-2 text-right">
					<button id="remove-update" update="{{update.updateID}}" class="btn btn-danger">Remove Update</button>
				</div>
			</div>
			<div class="panel-body" style="display: none;">
		
		
				<div class="panel panel-default">
					<div class="panel-heading row">
						<div class="col-sm-8">
							<h3>Pending RuleSet changes</h3>  
						</div>
						<div class="col-sm-2">
							<span class="badge btn-success"><h3>{{update.updatePendingChangeCount}}</h3></span>
						</div>
					</div>
					<div class="panel-body" style="display: none;">
						<p>When an update describes that a rule lives in another ruleset than it is in the current database, depending on
						the configuration it might be moved to the new ruleset, or left in the ruleset it already resides in. Anyway, these
						changes are recorded on this page, so that they can be confirmed by an operator. The following list is grouping the
						changes based on the updates the conflicts appear.</p>
		
						
							<div id="updateChanges">
								<form action="" method="post">
									{% csrf_token %}
									<table class="table">
										<tr><th></th><th>SID:</th><th>Rule Name</th><th>Original Ruleset</th><th>New Ruleset</th></tr>
										{% for change in update.pendingRuleSets %}
											<tr>
												<td><input type="checkbox" name="change-{{change.id}}" value="checked" /></td>
												<td>{{change.rule.SID}}</td>
												<td>{{change.rule.getCurrentRevision.msg}}</td>
												{% if change.moved == 0 %}
													<td class="success">{{change.originalSet.name}}</td>
													<td>{{change.newSet.name}}</td>
												{% else %}
													<td>{{change.originalSet.name}}</td>
													<td class="success">{{change.newSet.name}}</td>
												{% endif %}
											</tr>
										{% endfor %}
									</table>
									<input type="Submit" name="btn-change" value="Change Set" />
									<input type="Submit" name="btn-keep" value="Leave in Set" />
								</form>
							</div>
							
					</div>
				</div>
				
				<div class="new-rulesets panel panel-default">
					<div class="panel-heading row">
						<div class="col-sm-8">
							<h3>New Rulesets</h3>
						</div>
						<div class="col-sm-2">
							<span class="badge btn-success"><h3>{{update.updateNewRuleSetCount}}</h3></span>
						</div>
					</div>
					<div class="panel-body" style="display: none;">
						
						<p></p>
		
						
					</div>
				</div>
				
				<div class="new-rules panel panel-default">
					<div class="panel-heading row">
						<div class="col-sm-8">
							<h3>New Rules</h3>
						</div>
						<div class="col-sm-2">
							<span class="badge btn-success"><h3>{{update.updateNewRulesCount}}</h3></span>
						</div>
					</div>
					<div class="panel-body" style="display: none;">
						
						<p></p>
		
						
					</div>
				</div>
				
				<div class="new-revisions panel panel-default">
					<div class="panel-heading row">
						<div class="col-sm-8">
							<h3>Rules with new revisions</h3>
						</div>
						
						<div class="col-sm-2">
							<span class="badge btn-success"><h3>{{update.updateNewRevisionsCount}}</h3></span>
						</div>
					</div>
					<div class="panel-body" style="display: none;">
						
						<p></p>
		
						
					</div>
				</div>
			</div>
		</div>
		{% endfor %}
	</div>
{% endblock %}
