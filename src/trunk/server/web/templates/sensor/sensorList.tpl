<table id="sensorList" class="table">
	<tr><th>Name:</th><th>IP-Address:</th><th>Secret</th><th>Status</th></tr>
	{% for sensor in sensors %}
		<tr>
			<td>{{sensor.name}}</td><td>{{sensor.ipAddress}}</td>
			<td class="sensorSecret-{{sensor.id}}">
				{% if sensor.getStatus != sensor.AUTONOMOUS %}
					<button class="regenerateSensorSecret" sid="{{sensor.id}}">Generate new secret</button>
				{% endif %}
			</td>
			<td>
				{% if sensor.getStatus == sensor.AVAILABLE %}
					<span class="badge btn-success">Available</span>
				{% elif sensor.getStatus == sensor.UNAVAILABLE %}
					<span class="badge btn-danger">Unavailable</span>
				{% elif sensor.getStatus == sensor.INACTIVE %}
					<span class="badge btn">In-active</span>
				{% elif sensor.getStatus == sensor.AUTONOMOUS %}
					<span class="badge btn-warning">Autonomous</span>
				{% endif %}
			</td>
		</tr>
	{% endfor %}
</table>
