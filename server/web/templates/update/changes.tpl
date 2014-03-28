{% extends "general/index.tpl" %}

{% block content %}
	{% load staticfiles %}
	<script type="text/javascript" src="{% static 'js/update.js' %}"></script>

	<div id="content" class="col-xs-10 col-sm-10 col-md-10 pull-right well">
		<div class="panel panel-default">
			<div class="panel-heading">
				<p>Pending changes:</p>
			</div>
			<div class="panel-body">
				<h1>Pending changes.</h1>
				<p>When an update describes that a rule lives in another ruleset than it is in the current database, depending on
				the configuration it might be moved to the new ruleset, or left in the ruleset it already resides in. Anyway, these
				changes are recorded on this page, so that they can be confirmed by an operator. The following list is grouping the
				changes based on the updates the conflicts appear.</p>

				{% for update in updates %}
					<li class="list-group-item odd">Update from {{update.0.update.source.name}}, {{update.0.update.time}}</li>
					<li class="sub-list list-group-item even" style="display: none">
						<div id="updateChanges">
							<form action="" method="post">
								{% csrf_token %}
								<table class="table">
									<tr><th></th><th>SID:</th><th>Original Ruleset</th><th>New Ruleset</th></tr>
									{% for change in update %}
										<tr>
											<td><input type="checkbox" name="change-{{change.id}}" value="checked" /></td>
											<td>{{change.rule.SID}}</td>
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
					</li>
				{% endfor %}
			</div>
		</div>
	</div>
{% endblock %}
