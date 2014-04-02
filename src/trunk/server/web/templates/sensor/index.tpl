{% extends "general/index.tpl" %}

{% block content %}
	{% load staticfiles %}
	<script type="text/javascript" src="{% static 'js/sensor.js' %}"></script>
	{% csrf_token %}
	<button class="btn" data-toggle="modal" data-target="#createSensorModal" id="create">Add Sensor</button>
	<div class="modal fade" id="createSensorModal" tabindex="-1" role="dialog" aria-labelledby="createSensorModalLabel" aria-hidden="true">
		<div class="modal-dialog">
			<div class="modal-content">
				<form id="createSensorForm" class="form-horizontal" target="" method="post">
					<div class="modal-header">
						<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
						<h4 class="modal-title" id="createSensorModalLabel">Create Sensor</h4>
					</div>
					<div class="modal-body">
						
						<div id="formContent">
						
						</div>
					</div>
					<div class="modal-footer">
						<button type="button" class="btn btn-default" data-dismiss="modal" id="create-close">Close</button>
						<button type="submit" class="btn btn-primary" id="create-submit">Save changes</button>
					</div>
				</form>
			</div>
		</div>
	</div>

	<div id="content" class="sensors col-xs-10 col-sm-10 col-md-10 pull-right well">
		
		{% include "sensor/sensorList.tpl" %}
			
	</div>
{% endblock %}
