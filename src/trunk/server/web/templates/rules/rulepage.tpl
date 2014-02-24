<ul id="{{ pagenr }}" class="list-group{% if pagenr == 1 %} current{% endif %}"{% if ishidden %} style="display: none;"{% endif %}>
	{% if rule_list %}
	{% for rev in rule_list %}
        <li class="list-group-item odd">{{ rev.rule.SID }}<span class="pull-right"><input type="checkbox" {% if rev.rule.active %} checked {% endif %}id="{{ rev.rule.SID }}" class="ruleswitch" data-size="mini" data-on-color="success" data-off-color="danger"></span></li>
        <li class="sub-list list-group-item even" style="display: none"><pre>{{ rev.raw }}</pre></li>
    {% endfor %}
    
    {% else %}
    <li class="list-group-item odd">No rules are available.</li>
	{% endif %}
</ul>