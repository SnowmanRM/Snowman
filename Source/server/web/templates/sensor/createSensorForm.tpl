{% csrf_token %}
<div class="form-group" id="name">
	<label for="name" class="col-sm-2 control-label">Name:</label>
	<div class="col-sm-10">
		<input type="text" class="form-control" id="name" name="name" required />
	</div>
</div>
<div class="form-group" id="ip">
	<label for="ip" class="col-sm-2 control-label">IP-address:</label>
	<div class="col-sm-10">
		<input type="text" class="form-control" id="ip" name="ip" />
	</div>
</div>
<div class="form-group" id="autonomous">
	<label for="autonomous" class="col-sm-2 control-label">Autonomous:</label>
	<div class="col-sm-10">
		<input type="checkbox" class="form-control" id="autonomous" name="auto"/>
	</div>
</div>

<div class="form-group" id="children">
	<label for="children" class="col-sm-2 control-label">Set child sensors:</label>
	<div class="col-sm-10">
		<select multiple class="form-control" id="children" name="children" size="15">
			<option value="None" selected>None</option>
			{% if sensors %}
		{% for sensor in sensors %}
			<option value="{{ sensor.sensorID }}">{{ sensor.sensorName }}</option>
		{% endfor %}
	{% endif %}
		</select>
	</div>
</div>