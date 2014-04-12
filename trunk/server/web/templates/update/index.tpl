{% extends "general/index.tpl" %}

{% block content %}
	{% load staticfiles %}
	<script type="text/javascript" src="{% static 'js/update.js' %}"></script>

	<div id="content" class="well row">
		<div class="col-sm-6">
		<div class="panel panel-default">
			<div class="panel-heading">
				<h2 class="no-margin">Manual update</h2>
			</div>
			<div class="panel-body">
				{% if debug %}
					<h1>{{debug}}</h1>
				{% endif %}
				
				
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
		<div class="col-sm-6">
		<div class="panel panel-default">
			<div class="panel-heading">
				<h2 class="no-margin">Update status</h2>
			</div>
			<div class="panel-body">
				<h2 class="no-margin">Create new source</h2>
				<div id="newSource">
					<p>Click the button if you would like to add a new update-source:</p>
					<button>Create new source</button>
				</div>
				<h2>Information per source:</h2>
				<div id="sourceList">
					{% include "update/sourceList.tpl" %}
				</div>
			</div>
		</div>
		</div>
	</div>
{% endblock %}
