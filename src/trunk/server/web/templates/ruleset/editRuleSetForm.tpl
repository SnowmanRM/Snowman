{# editRuleSetForm.tpl is the template for the form for editing of RuleSets. #} 

{% csrf_token %}
<input type="hidden" id="id" name="id" value="{{ruleSetID}}">
<div class="form-group" id="rulesetname">
	  		<label for="rulesetname" class="col-sm-2 control-label">Name:</label>
	  		<div class="col-sm-10">
	  			<input type="text" class="form-control" id="rulesetname" name="rulesetname" value="{{ ruleSetName }}" maxlength="100" required />
	  		</div>
	  	</div>

	  	<div class="form-group" id="parent">
	  		<label for="children" class="col-sm-2 control-label">Change parent ruleset:</label>
	  		<div class="col-sm-10">
	  			<select class="form-control" id="parent" name="parent" size="15">
	  				<option value="None" {% if ruleSetParent == None %}selected{% endif %}>None</option>
	  				{% if ruleset_list %}
						{% for ruleset in ruleset_list %}
						
							<option value="{{ ruleset.ruleSetID }}" {% if ruleSetParent != None %}{% if ruleset.ruleSetID == ruleSetParent %}selected{% endif %}{% endif %}>
								{{ ruleset.ruleSetName }}
							</option>
							
						{% endfor %}
					{% endif %}
	  			</select>
	  		</div>
	  	</div>
	  	<div class="form-group" id="children">
	  		<label for="children" class="col-sm-2 control-label">Change child rulesets:</label>
	  		<div class="col-sm-10">
	  			<select multiple class="form-control" id="children" name="children" size="15">
	  				<option value="None" {% if ruleSetChildren == None %}selected{% endif %}>None</option>
	  				{% if ruleset_list %}
						{% for ruleset in ruleset_list %}
							<option value="{{ ruleset.ruleSetID }}" {% if ruleSetChildren != None %}{% if ruleset.ruleSetID in ruleSetChildren %}selected{% endif %}{% endif %}>
								{{ ruleset.ruleSetName }}
							</option>
						{% endfor %}
					{% endif %}
	  			</select>
	  		</div>
	  	</div>