{% if sources and sources|length > 0 %}
	{% for source in sources %}
		<li class="list-group-item odd">{{ source.source.name }}</li>
		<li class="sub-list list-group-item even" style="display: none">
			<p>Schedule: {{source.source.schedule}}</p>
			<p>Url: {{source.source.url}}</p>
			<p>Md5Url: {{source.source.md5url}}</p>
			<h4>Last 5 updates:</h4>
			<ul>
				{% for update in source.updates %}
					<li>{{update.time}} ({{update.ruleRevisions.count}} rule-changes)</li>
				{% endfor %}
			</ul>
		</li>
	{% endfor %}
{% else %}
	<li class="list-group-item odd">No update-sources is available.</li>
{% endif %}
