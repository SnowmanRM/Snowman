{# rulepage.tpl is the template for the paginated list of rules on the rules page. #} 
{# It constructs a table based on the list of rules sent to the parser. #}
{#  #}

{% if rulesearch %}<div id="searchresult" itemcount="{{ itemcount }}" pagelength="{{ pagelength }}" searchstring="{{ searchstring }}">{% endif %}
<table id="{{ pagenr }}" class="table table-responsive table-bordered table-hover
{% if pagenr == 1 %} current{% endif %}"{% if ishidden %} style="display: none;"{% endif %} itemcount="{{ itemcount }}" pagelength="{{ pagelength }}">
	<thead>
	<tr>
		<th id="checkbox-all" class="text-left">
			<input type="checkbox">
		</th>
		<th class="text-center">
			SID
		</th>
		<th class="text-center">
			Rev
		</th>
		<th class="text-center">
			Updated
		</th>
		<th class="left">
			Name
		</th>
		<th class="text-center">
			Ruleset
		</th>
		<th class="text-center">
			Class
		</th>
		<th class="text-center">
			Priority
		</th>
		<th class="text-center">
			Status
		</th>
	</tr>
	</thead>
	<tbody>
		{% if rule_list %}
		{% for rule in rule_list %}
		<tr class="odd">
			<td class="text-left">
				<input id="checkbox" rid="{{rule.id}}" gid="{{ rule.generator_id }}" sid="{{ rule.SID }}" status="{% if rule.thresholds.count %} T{% endif %}
				{% if rule.suppress.count %} S{% endif %}" type="checkbox">
			</td>
			<td class="text-right">
				{{ rule.SID }}
			</td>
			<td class="text-right">
				{{ rule.getCurrentRevision.rev }}
			</td>
			<td class="text-right">
				{{ rule.getCurrentRevision.update.first.time|date:"Y-m-d" }}
			</td>
			<td class="wrappable">
				{{ rule.getCurrentRevision.msg }}
			</td>
			<td class="text-center">
				{{ rule.ruleSet.name }}
			</td>
			<td class="text-center">
				{{ rule.ruleClass.classtype }}
			</td>
			<td class="text-center">
				<span class="badge btn-primary">{{ rule.ruleClass.priority }}</span>
			</td>
			<td class="text-right">
				<div class="col-xs-4 col-sm-4 col-md-4 col-lg-4">
					{% if rule.thresholds.count %}<span class="badge btn-warning">T</span>{% endif %}
					{% if rule.suppress.count %}<span class="badge btn-warning">S</span>{% endif %}
				</div>
				<div class="col-xs-4 col-sm-4 col-md-4 col-lg-4">
					<span class="badge btn-success">{{ rule.ruleSet.sensors.count }}</span>
					<span class="badge btn-danger">{{ sensorcount|add:rule.ruleSet.sensors.count|cut:"-" }}</span>
				</div>
				<div class="col-xs-4 col-sm-4 col-md-4 col-lg-4">
					{% if rule.active %}<span id="onoff" class="badge btn-success">ON</span>{% else %} <span id="onoff" class="badge btn-danger">OFF</span> {% endif %}
				</div>
			</td>
		</tr>
		<tr class="even" style="display: none">
			<td colspan="9">
				<div class="row container-fluid">
					<div class="col-xs-6 col-sm-6 col-md-6 col-lg-6">
						<div class="panel panel-default">
		  					<div class="panel-heading">References</div>
							<div class="list-group">
							{% for reference in rule.getCurrentRevision.references.all %}
								<a class="list-group-item" href="{{ reference.referenceType.urlPrefix }}{{ reference.reference }}">{{ reference.referenceType.urlPrefix }}{{ reference.reference }}</a>
							{% endfor %}
							</div>
						</div>
					</div>
					<div class="col-xs-6 col-sm-6 col-md-6 col-lg-6">
						<div class="panel panel-default">
		  					<div class="panel-heading">Active On Sensors:</div>
		  					<ul class="list-group">
							{% for sensor in rule.ruleSet.sensors.all %}
								<li class="list-group-item">{{ sensor.name }}</li>
							{% endfor %}
							</ul>
		  				</div>
	  				</div>
  				</div>
  				<div class="row container-fluid">
					<div class="col-xs-12 col-sm-12 col-md-12 col-lg-12">
						<div class="panel panel-default">
							<div class="panel-heading">Rule</div>
							<div class="panel-body">
								<pre>{{ rule.getCurrentRevision.raw }}</pre>
							</div>
						</div>
					</div>
				</div>	
			</tr>
		</tr>
		 {% endfor %}
	    
	    {% else %}
	    <tr class="even"><td colspan="9">No rules are available.</tr></tr>
		{% endif %}
	</tbody>
</table>
{% if rulesearch %}</div>{% endif %}

{% comment %}

<div id="{{ pagenr }}" class="panel panel-default{% if pagenr == 1 %} current{% endif %}"{% if ishidden %} style="display: none;"{% endif %}>
	<!-- Default panel contents -->
	<div class="panel-heading row">
		<div id="sid" class="col-xs-1 col-sm-1 col-md-1">
			<input type="checkbox" class="pull-left">
			<p class="text-right">SID</p>
		</div>
		<div id="revision" class="col-xs-1 col-sm-1 col-md-1">
			<p class="text-center">Revision</p>
		</div>
		<div id="updated" class="col-xs-2 col-sm-2 col-md-2">
			<p class="text-center">Updated</p>
		</div>
		<div id="name" class="col-xs-4 col-sm-4 col-md-4">
			<p class="text-center">Name</p>
		</div>
		<div id="status" class="col-xs-4 col-sm-4 col-md-4">
			<p class="text-center">Status</p>
		</div>
	</div>


	<ul class="list-group">
		{% if rule_list %}
		{% for rev in rule_list %}
	        <li class="list-group-item row odd">
		        <div id="sid" class="col-xs-1 col-sm-1 col-md-1">
		        	<input type="checkbox" class="pull-left">
		        	<p class="text-right">{{ rev.rule.SID }}</p>
		        </div>
		        <div id="revision" class="col-xs-1 col-sm-1 col-md-1">
					<p class="text-center">Revision</p>
				</div>
				<div id="updated" class="col-xs-2 col-sm-2 col-md-2">
					<p class="text-center">Updated</p>
				</div>
				<div id="name" class="col-xs-4 col-sm-4 col-md-4">
					<p class="text-center">Name</p>
				</div>
		        <div id="status" class="col-xs-4 col-sm-4 col-md-4">
		        	<p class="text-right">
			        	<input type="checkbox" {% if rev.rule.active %} checked {% endif %}id="{{ rev.rule.SID }}" 
			        	class="ruleswitch" data-size="mini" data-on-color="success" data-off-color="danger">
		        	</p>
		        </div>
	        </li>
	        <li class="sub-list list-group-item even" style="display: none">
		        <pre>
		        	{{ rev.raw }}
		        </pre>
	        </li>
	    {% endfor %}
	    
	    {% else %}
	    <li class="list-group-item odd">No rules are available.</li>
		{% endif %}
	</ul>

</div>

{% endcomment %}