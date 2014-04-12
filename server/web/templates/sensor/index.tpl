{% extends "general/index.tpl" %}

{% block content %}
	{% load staticfiles %}
	<script type="text/javascript" src="{% static 'js/sensor.js' %}"></script>

	<div class="modal fade" id="createSensorModal" tabindex="-1" role="dialog" aria-labelledby="createSensorModalLabel" aria-hidden="true">
		<div class="modal-dialog">
			<div class="modal-content">
				<form id="createSensorForm" class="form-horizontal" target="" method="post">
					<div class="modal-header">
						<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
						<h4 class="modal-title" id="createSensorModalLabel">Create Sensor</h4>
					</div>
					<div class="modal-body">
						<div id="modalAjaxReturn"></div>
						<div id="formContent">
							{% csrf_token %}
							{% for field in newSensorForm %}
								<div id="{{ field.id_for_label }}" class="form-group">
									<label class="col-sm-2 control-label" for="{{ field.id_for_label }}">{{ field.label }}</label>
									<div class="col-sm-10">{{ field }}</div>
								</div>
							{% endfor %}
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

	<div id="content" class="col-xs-10 col-sm-10 col-md-10 pull-right well">
		<div class="panel panel-default">
			<div class="panel-heading">
				<p>Sensors:</p>
			</div>
			<div class="panel-body">
				<div id="AJAX-Return"></div>
				<div id="csrf">{% csrf_token %}</div>
				<h1>Sensor administration</h1>
				<p>
					<button class="btn" data-toggle="modal" data-target="#createSensorModal">Add Sensor</button>
				</p>
				{% include "sensor/sensorList.tpl" %}
			</div>
		</div>
	</div>
{% endblock %}
