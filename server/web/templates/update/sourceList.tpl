{% if sources and sources|length > 0 %}
	{% for source in sources %}
		<li class="list-group-item odd">{{ source.source.name }}</li>
		<li class="sub-list list-group-item even" style="display: none">
			{% if source.updatable %}
				<p>Last Updated: {{source.lastUpdate}}</p>
				<p>Schedule: {{source.source.schedule}}</p>
				<p>Url: {{source.source.url}}</p>
				<p>Md5Url: {{source.source.md5url}}</p>
				<p><button class="runUpdate" id={{source.source.id}}>Run update now</button>
					<button data-toggle="modal" data-target="#editSource-{{source.source.id}}">Edit source</button></p>
			{% else %}
				<p>Last Updated: {{source.lastUpdate}}</p>
				<p><button data-toggle="modal" data-target="#editSource-{{source.source.id}}">Edit source</button></p>
			{% endif %}

			<h4>Last 5 updates:</h4>
			<ul>
				{% for update in source.updates %}
					<li>{{update.time}} ({{update.ruleRevisions.count}} rule-changes)</li>
				{% endfor %}
			</ul>
			
			<!-- Modal for editing the source.-->
			<div class="modal fade" id="editSource-{{source.source.id}}" tabindex="-1" role="dialog" aria-labelledby="editSourceModal-{{source.source.id}}" aria-hidden="true">
				<div class="modal-dialog">
					<div class="modal-content">
						<div class="modal-header">
							<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
							<h4 class="modal-title" id="editSourceModal-{{source.source.id}}">Edit "{{source.source.name}}"</h4>
						</div>
						<div class="modal-body">
							<form id="createSourceForm" action="/web/update/newSource/" method="post">
								{% csrf_token %}
								{{ source.form.as_p }}
							</form>
						</div>
						<div class="modal-footer">
							<button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
							<button type="button" class="btn btn-primary">Save changes</button>
						</div>
					</div>
				</div>
			</div>
		</li>
	{% endfor %}
{% else %}
	<li class="list-group-item odd">No update-sources is available.</li>
{% endif %}
