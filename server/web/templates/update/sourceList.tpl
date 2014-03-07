{% if sources and sources|length > 0 %}
	{% for source in sources %}
		<li class="list-group-item odd">{{ source.source.name }}</li>
		<li class="sub-list list-group-item even" style="display: none">
			{% if source.updatable %}
				<p>Last Updated: {{source.lastUpdate}}</p>
				<p>Schedule: {{source.source.schedule}}</p>
				<p>Url: {{source.source.url}}</p>
				<p>Md5Url: {{source.source.md5url}}</p>
				<div id="updateMessage-{{source.source.id}}">
					{% if source.source.locked %}
						<p>There are currently an update running for this source.</p>
					{% else %}
						<p><button class="runUpdate" id={{source.source.id}}>Run update now</button>
							<button data-toggle="modal" data-target="#editSource-{{source.source.id}}">Edit source</button></p>
					{% endif %}
				</div>
			{% else %}
				<p>Last Updated: {{source.lastUpdate}}</p>
				<div id="updateMessage-{{source.source.id}}">
					{% if source.source.locked == True %}
						<p>There are currently an update running for this source.</p>
					{% else %}
						<p><button data-toggle="modal" data-target="#editSource-{{source.source.id}}">Edit source</button></p>
					{% endif %}
				</div>
			{% endif %}
			
			<div class="progress" id="progressouter-{{source.source.id}}">
				<div class="progress-bar" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" style="width: 0%;" id="progress-{{source.source.id}}">
				</div>
			</div>

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
						<form id="editSourceForm" class="editSourceForm" action="/web/update/editSource/{{ source.source.id }}/" method="post">
							<div class="modal-body">
								<div id='editSourceForm'>
									{% csrf_token %}
									{{ source.newSourceForm.as_p }}
									<div id='TimeSelector'>
										{% if source.timeSelector %}
											{{ source.timeSelector.as_p }}
										{% endif %}
									</div>
								</div>
							</div>
							<div class="modal-footer">
								<button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
								<button type="submit" class="btn btn-primary">Save changes</button>
							</div>
						</form>
					</div>
				</div>
			</div>
		</li>
		<script>startProgressBar({{source.source.id}});</script>
	{% endfor %}
{% else %}
	<li class="list-group-item odd">No update-sources is available.</li>
{% endif %}
