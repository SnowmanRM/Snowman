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
				<p>To manually run a update, please use the following form to update a .rule file, or an archive (.zip
				.tar .tar.gz) if the update contains more than one file (ie: .rule, gen-msg.map, sid-msg.map, 
				classification.conf etc.).</p>

				{% if uploadMessage %}
					<h3>Upload recieved</h3>
					<p>{{uploadMessage}}</p>
				{% else %}
					<form action="" method="post" enctype="multipart/form-data">
						{% csrf_token %}
						{{ manualUpdateForm.as_p }}
						<input type="submit" value="Submit" />
					</form>
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
				<h2>Information per source:</h2>
				{% if sources and sources|length > 0 %}
					{% for source in sources %}
        				<li class="list-group-item odd">{{ source.source.name }}</li>
        				<li class="sub-list list-group-item even" style="display: none">
							<h4>Last 5 updates:</h4>
							<ul>
								{% for update in source.updates %}
									<li>{{update.time}} ({{update.ruleRevisions.all|length}} rule-changes)</li>
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
{% endblock %}
