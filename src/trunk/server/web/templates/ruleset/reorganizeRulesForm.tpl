{% csrf_token %}
	
  	<div class="form-group" id="sid">
  		<label for="sid" class="col-sm-2 control-label">GID:SID:</label>
  		<div class="col-sm-10">
  			<select multiple class="form-control" id="sid" name="sid" disabled></select>
  		</div>
  	</div>
  	<div class="form-group" id="parent">
	  		<label for="children" class="col-sm-2 control-label">Set new parent ruleset:</label>
	  		<div class="col-sm-10">
	  			<select class="form-control" id="parent" name="parent" size="15" required>
	  				{% if ruleset_list %}
						{% for ruleset in ruleset_list %}
						
							<option value="{{ ruleset.ruleSetID }}">
								{{ ruleset.ruleSetName }}
							</option>
							
						{% endfor %}
					{% endif %}
	  			</select>
	  		</div>
	  	</div>