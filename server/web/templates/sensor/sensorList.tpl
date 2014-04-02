<!--<form id="sensorListForm" target="/web/sensor/edit/" method="post">-->
	{% csrf_token %}
	<table id="sensorList" class="sensors table table-responsive table-bordered table-hover">
		
		<thead {% if not isMain %}style="display:none;"{% endif %}>
			<tr>
				<th><input type="checkbox" id="checkbox-all" /></th>
				<th class="text-center">Name</th>
				<th class="text-center">IP-Address</th>
				<th class="text-center">Children</th>
				<th class="text-center">Status</th>
				<th class="text-center"></th>
			</tr>
		</thead>
		
		<tbody>
			{% for sensor in sensors %}
				<tr class="odd" id="{{sensor.sensorID}}" tree-type="{% if sensor.sensorHasChildren %}parent{% else %}child{% endif %}">
					<td><input id="checkbox" type="checkbox" name="selectSensor-{{sensor.sensorID}}" /></td>
					<td class="text-center">{{sensor.sensorName}}</td>
					<td class="text-center">{{sensor.sensorIP}}</td>
					<td class="text-center"><span class="badge btn-info">{{sensor.sensorChildrenCount}}</span></td>
					<td class="text-center">
						{% if sensor.sensorStatus == 0 %}
							<span class="badge btn-success">Available</span>
						{% elif sensor.sensorStatus == 1 %}
							<span class="badge btn-danger">Unavailable</span>
						{% elif sensor.sensorStatus == 2 %}
							<span class="badge btn">In-active</span>
						{% elif sensor.sensorStatus == 3 %}
							<span class="badge btn-warning">Autonomous</span>
						{% endif %}
					</td>
					<td class="text-right">
						<div class="btn-group">
						{% if sensor.sensorStatus != 3 %}
						
							<button id="regenerateSensorSecret" sid="{{sensor.sensorID}}" class="btn btn-danger">Generate new secret</button>
						
						{% endif %}
						{% if sensor.sensorStatus == 3 %}
						
							<button id="generateSensorRules" sid="{{sensor.sensorID}}" class="btn btn-info">Get Rules</button>
						
						{% endif %}
						{% if sensor.sensorStatus == 0 %}
						
							<button id="requestUpdate" sid="{{sensor.sensorID}}" class="btn btn-success">Request Update</button>
						
						{% endif %}
						</div>
					</td>
				</tr>
				<tr class="even" style="display:none;">
					<td colspan="6">
						{% if sensor.sensorHasChildren %}
						<div class="panel panel-info clear">
							<div class="panel-heading"><h4>Child Sensors</h4></div>
						</div>
						{% endif %}
					</td>
				</tr>
			{% endfor %}
		</tbody>
	</table>
<!--</form>-->
