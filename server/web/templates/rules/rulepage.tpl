<div id="{{ pagenr }}" class="panel panel-default{% if pagenr == 1 %} current{% endif %}"{% if ishidden %} style="display: none;"{% endif %}>
	<!-- Default panel contents -->
	<div class="panel-heading row"><input type="checkbox" class="pull-left"><p id="sid" class="col-xs-1 col-sm-1 col-md-1">SID</p><p id="rev" class="col-xs-1 col-sm-1 col-md-1">Revision</p><p id="updated" class="col-xs-1 col-sm-1 col-md-1">Updated</p></div>


	<ul class="list-group">
		{% if rule_list %}
		{% for rev in rule_list %}
	        <li class="list-group-item row odd"><input type="checkbox" class="pull-left"><p id="sid" class="col-xs-1 col-sm-1 col-md-1">{{ rev.rule.SID }}</p><p class="col-xs-10 col-sm-10 col-md-10"><span class="pull-right"><input type="checkbox" {% if rev.rule.active %} checked {% endif %}id="{{ rev.rule.SID }}" class="ruleswitch" data-size="mini" data-on-color="success" data-off-color="danger"></span></p></li>
	        <li class="sub-list list-group-item even" style="display: none"><pre>{{ rev.raw }}</pre></li>
	    {% endfor %}
	    
	    {% else %}
	    <li class="list-group-item odd">No rules are available.</li>
		{% endif %}
	</ul>

</div>