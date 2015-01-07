{% csrf_token %}
<input type="hidden" id="id" name="id" value="{{sensor.id}}">
<div class="form-group" id="name">
	<label for="name" class="col-sm-2 control-label">Name:</label>
	<div class="col-sm-10">
		<input type="text" class="form-control" id="name" name="name" value="{{ sensor.name }}" required />
	</div>
</div>
<div class="form-group" id="ip">
	<label for="ip" class="col-sm-2 control-label">IP-address:</label>
	<div class="col-sm-10">
		<input type="text" class="form-control" id="ip" name="ip" value="{% if sensor.ipAddress != None %}{{ sensor.ipAddress }}{% endif %}" />
	</div>
</div>
<div class="form-group" id="autonomous">
	<label for="autonomous" class="col-sm-2 control-label">Autonomous:</label>
	<div class="col-sm-10">
		<input type="checkbox" class="form-control" id="autonomous" name="auto" {% if sensor.autonomous %}checked{% endif %}/>
	</div>
</div>

<div class="form-group" id="parent">
	<label for="parent" class="col-sm-2 control-label">Set parent sensor:</label>
	<div class="col-sm-10">
		<select multiple class="form-control" id="parent" name="parent" size="15">
			<option value="None" {% if sensorParent == None %}selected{% endif %}>None</option>
			{% if sensors %}
		{% for sensor in sensors %}
			<option value="{{ sensor.sensorID }}" {% if sensorParent != None %}{% if sensor.sensorID == sensorParent %}selected{% endif %}{% endif %}>{{ sensor.sensorName }}</option>
		{% endfor %}
	{% endif %}
		</select>
	</div>
</div>

<div class="form-group" id="children">
	<label for="children" class="col-sm-2 control-label">Set child sensors:</label>
	<div class="col-sm-10">
		<select multiple class="form-control" id="children" name="children" size="15">
			<option value="None" {% if sensorChildren == None %}selected{% endif %}>None</option>
			{% if sensors %}
		{% for sensor in sensors %}
			<option value="{{ sensor.sensorID }}" {% if sensorChildren != None %}{% if sensor.sensorID in sensorChildren %}selected{% endif %}{% endif %}>{{ sensor.sensorName }}</option>
		{% endfor %}
	{% endif %}
		</select>
	</div>
</div>