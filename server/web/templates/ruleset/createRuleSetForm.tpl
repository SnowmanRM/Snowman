
{% csrf_token %}
<div class="form-group" id="rulesetname">
	  		<label for="rulesetname" class="col-sm-2 control-label">Name:</label>
	  		<div class="col-sm-10">
	  			<input type="text" class="form-control" id="rulesetname" name="rulesetname" required />
	  		</div>
	  	</div>

	  	<div class="form-group" id="children">
	  		<label for="children" class="col-sm-2 control-label">Set child rulesets:</label>
	  		<div class="col-sm-10">
	  			<select multiple class="form-control" id="children" name="children" size="15">
	  				<option value="None" selected>None</option>
	  				{% if ruleset_list %}
						{% for ruleset in ruleset_list %}
							<option value="{{ ruleset.ruleSetID }}">{{ ruleset.ruleSetName }}</option>
						{% endfor %}
					{% endif %}
	  			</select>
	  		</div>
	  	</div>