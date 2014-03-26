{# rulepage.tpl is the template for the paginated list of rules on the rules page. #} 
{# It constructs a table based on the list of rules sent to the parser. #}
{#  #}

{% if rulesearch %}<div id="searchresult" itemcount="{{ itemcount }}" pagelength="{{ pagelength }}" searchstring="{{ searchstring }}">{% endif %}
<table id="{{ pagenr }}" class="tuning table table-responsive table-bordered table-striped
{% if pagenr == 1 %} current{% endif %}"{% if ishidden %} style="display: none;"{% endif %} itemcount="{{ itemcount }}" pagelength="{{ pagelength }}">
	<thead>
	<tr>
		<th id="checkbox-all" class="text-left">
			<input type="checkbox">
		</th>
		<th class="text-center">
			Added
		</th>
		<th class="text-center">
			Added By
		</th>
		<th class="text-center">
			Type
		</th>
		<th class="text-center">
			Rule SID
		</th>
		<th class="text-center">
			Rule Name
		</th>
		<th class="text-center">
			Sensor
		</th>
		
		<th class="text-center">
			Content
		</th>
		<th class="text-center">
			Comment
		</th>
		
	</tr>
	</thead>
	<tbody>
		{% if thresholdList or suppressList %}
		{% for threshold in thresholdList %}
		<tr>
			<td class="text-left">
				<input id="checkbox" rid="{{rule.ruleID}}" gid="{{ rule.ruleGID }}" sid="{{ rule.ruleSID }}" status="{% if rule.ruleThresholdCount %} T{% endif %}
				{% if rule.ruleSuppressCount %} S{% endif %}" type="checkbox">
			</td>
			<td class="text-center wrappable">
				{{ threshold.comment.time|date:"Y-m-d h:m:s" }}
			</td>
			<td class="text-center">
				{{ threshold.comment.user }}
			</td>
			<td class="">
				Threshold
			</td>
			<td class="text-right">
				{{ threshold.rule.SID }}
			</td>
			<td class="text-left wrappable">
				{{ threshold.rule.getCurrentRevision.msg }}
			</td>
			<td class="text-center">
				{{ threshold.sensor.name }}
			</td>
			
			<td class="text-left">
				type {{ threshold.thresholdType }}, <br /> 
				track {{ threshold.track }}, <br /> 
				count {{ threshold.count }}, seconds {{ threshold.seconds }}
			</td>
			<td class="text-left wrappable">
				{{ threshold.comment.comment }}
			</td>
			
		</tr>
		 {% endfor %}
	    
	    {% else %}
	    <tr class="even"><td colspan="9">No rules are available.</tr></tr>
		{% endif %}
	</tbody>
</table>
{% if rulesearch %}</div>{% endif %}
