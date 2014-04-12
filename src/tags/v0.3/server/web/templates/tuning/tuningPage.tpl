{# tuningPage.tpl is the template for displaying a list of tuning objects. #} 

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
		{% if tuningList %}
		{% for tuning in tuningList %}
		<tr>
			<td class="text-left">
				<input id="checkbox" tuningid="{{ tuning.tuningID }}" tuningtype="{{ tuning.tuningType }}" type="checkbox">
			</td>
			<td class="text-center wrappable">
				{{ tuning.tuningAdded|date:"Y-m-d H:m:s" }}
			</td>
			<td class="text-center">
				{{ tuning.tuningUser }}
			</td>
			<td class="text-center">
				{{ tuning.tuningType }}
			</td>
			<td class="text-center">
				{{ tuning.tuningRuleSID }}
			</td>
			<td class="text-left wrappable">
				{{ tuning.tuningRuleName }}
			</td>
			<td class="text-center">
				{{ tuning.tuningSensorName }}
			</td>
			
			<td class="text-left wrappable">
				{{ tuning.tuningContent }}
			</td>
			<td class="text-left wrappable">
				{{ tuning.tuningComment }}
			</td>
			
		</tr>
		 {% endfor %}
	    
	    {% else %}
	    <tr class="even"><td colspan="9">No tuning available.</tr></tr>
		{% endif %}
	</tbody>
</table>
{% if rulesearch %}</div>{% endif %}
