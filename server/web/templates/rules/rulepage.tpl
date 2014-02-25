
<table id="{{ pagenr }}" class="table table-responsive table-bordered table-hover
{% if pagenr == 1 %} current{% endif %}"{% if ishidden %} style="display: none;"{% endif %}>
	<thead>
	<tr>
		<th class="text-left">
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
			Status
		</th>
	</tr>
	</thead>
	<tbody>
		{% if rule_list %}
		{% for rule in rule_list %}
		<tr class="odd">
			<td class="text-left">
				<input type="checkbox">
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
			<td class="text-right">
				<span class="badge btn-success">{{ rule.ruleSet.sensors.count }}</span>
				<span class="badge btn-danger">{{ sensorcount|add:rule.ruleSet.sensors.count|cut:"-" }}</span>
				<input type="checkbox" {% if rule.active %} checked {% endif %}id="{{ rule.SID }}" 
			        	class="ruleswitch" data-size="mini" data-on-color="success" data-off-color="danger">
			</td>
		</tr>
		<tr class="even" style="display: none">
			<td colspan="7">
				<ul>
				{% for reference in rule.getCurrentRevision.references.all %}
					<li><a href="{{ reference.referenceType.urlPrefix }}{{ reference.reference }}">{{ reference.referenceType.urlPrefix }}{{ reference.reference }}</a></li>
				{% endfor %}
				</ul>
				<pre>{{ rule.getCurrentRevision.raw }}</pre>
			</tr>
		</tr>
		 {% endfor %}
	    
	    {% else %}
	    <tr class="even"><td colspan="7">No rules are available.</tr></tr>
		{% endif %}
	</tbody>
</table>


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