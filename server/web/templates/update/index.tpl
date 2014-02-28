{% extends "general/index.tpl" %}

{% block content %}
	{% load staticfiles %}
	<script type="text/javascript" src="{% static 'js/update.js' %}"></script>

	<div id="content" class="col-xs-10 col-sm-10 col-md-10 pull-right well">
		<div class="panel panel-default">
			<div class="panel-heading">
				<p>Run manual update:</p>
			</div>
			<div class="panel-body">
				{% if debug %}
					<h1>{{debug}}</h1>
				{% endif %}
				
				<h2>Manual update</h2>
				<p>To manually run a update, please use the following form to upload a single file, or an 
				archive (.zip .tar .tar.gz) if the update contains more than one file (ie: .rule, 
				gen-msg.map, sid-msg.map, classification.conf etc.).</p>

				{% if uploadMessage %}
					<h3>Upload recieved</h3>
					<p>{{uploadMessage}}</p>
				{% else %}
					<div id="ManualUpdate">
						<form action="" method="post" enctype="multipart/form-data">
							{% csrf_token %}
							{{ manualUpdateForm.as_p }}
							<input type="submit" value="Submit" />
						</form>
					</div>
				{% endif %}
			</div>
		</div>
	</div>

	<div id="content" class="col-xs-10 col-sm-10 col-md-10 pull-right well">
		<div class="panel panel-default">
			<div class="panel-heading">
				<p>Update status:</p>
			</div>
			<div class="panel-body">
				<h2>Create new source</h2>
				<div id="newSource">
					<p>Click the button if you would like to add a new update-source:</p>
					<button>Create new source</button>
				</div>
				<h2>Information per source:</h2>
				<div id="sourceList">
					{% if sources and sources|length > 0 %}
						{% for source in sources %}
	        				<li class="list-group-item odd">{{ source.source.name }}</li>
	        				<li class="sub-list list-group-item even" style="display: none">
								{% if source.updatable %}
									<p>Last Updated: {{source.lastUpdate}} - <button class="runUpdate" id={{source.source.id}}>Run update now</button></p>
									<p>Schedule: {{source.source.schedule}}</p>
									<p>Url: {{source.source.url}}</p>
									<p>Md5Url: {{source.source.md5url}}</p>
								{% else %}
									<p>Last Updated: {{source.lastUpdate}}</p>
								{% endif %}

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
				</div>
			</div>
		</div>
	</div>
{% endblock %}
