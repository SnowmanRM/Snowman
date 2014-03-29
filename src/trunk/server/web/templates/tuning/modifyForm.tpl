{# modifyForm.tpl is the template for the form used to enable/disable. #} 
{# It consists of various form elements needed for a enable/disable. #}
{#  #}

	{% csrf_token %}
	
  	<div class="form-group" id="ruleset">
  		<label for="ruleset" class="col-sm-2 control-label">Rulesets:</label>
  		<div class="col-sm-10">
  			<select multiple class="form-control" id="ruleset" name="ruleset" disabled></select>
  		</div>
  	</div>
  	<div class="form-group" id="global">
  		<label for="global" class="col-sm-2 control-label">Globally:</label>
  		<div class="col-sm-10">
  			<input type="checkbox" id="global" name="global">
  		</div>
  	</div>
  	<div class="form-group" id="sensors">
  		<label for="sensors" class="col-sm-2 control-label">Sensors:</label>
  		<div class="col-sm-10">
  			<select multiple class="form-control" id="sensors" name="sensors">
  				<option value="all" selected>All</option>
  				{% if allsensors %}
					{% for sensor in allsensors %}
						<option value="{{ sensor.id }}">{{ sensor.name }}</option>
					{% endfor %}
				{% endif %}
  			</select>
  		</div>
  	</div>
        