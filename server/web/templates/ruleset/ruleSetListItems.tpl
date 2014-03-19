
{% block rulesetlist %}
{% if ruleset_list %}
	{% for ruleset in ruleset_list %}
		<div id="{{ ruleset.ruleSetID }}" class="ruleset-panel panel panel-default" tree-type="{% if ruleset.ruleSetHasChildren %}parent{% else %}child{% endif %}" tree-level="0" has-rules="{{ ruleset.ruleSetHasRules }}">
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
			
			<div class="panel-body" style="display:none;">
			{% if ruleset.ruleSetHasRules %}
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
			{% endif %}
			</div>
			
			
		</div>
	{% endfor %}
		    
{% elif ismain %}
	<li class="list-group-item odd">No rulesets are available.</li>
{% endif %}
{% endblock %}