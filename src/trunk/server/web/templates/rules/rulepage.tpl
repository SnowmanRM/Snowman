<ul id="{{ pagenr }}" class="list-group"{% if ishidden %} style="display: none;"{% endif %}>
	{% if rule_list %}
	{% for rev in rule_list %}
        <li class="list-group-item odd">{{ rev.rule.SID }}<span class="pull-right"><input type="checkbox" {% if rev.rule.active %} checked {% endif %}id="{{ rev.rule.SID }}" class="ruleswitch" data-size="mini" data-on-color="success" data-off-color="danger"></span></li>
        <li class="sub-list list-group-item list-group-item-warning even" style="display: none">{{ rev.raw }}</li>
    {% endfor %}
    
    {% else %}
    <li class="list-group-item odd">No rules are available.</li>
	{% endif %}
</ul>