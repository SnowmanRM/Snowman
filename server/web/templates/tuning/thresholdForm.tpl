	{% csrf_token %}
	<input type="hidden" id="force" name="force" value="False">
  	<div class="form-group" id="sid">
  		<label for="sid" class="col-sm-2 control-label">GID:SID:</label>
  		<div class="col-sm-10">
  			<input type="text" class="form-control" id="sid" name="sid" placeholder="Set the rule in the '1:12345' syntax." required/>
  		</div>
  	</div>
  	<div class="form-group" id="type">
  		<label for="type" class="col-sm-2 control-label">Type:</label>
  		<div class="col-sm-10">
  			<select class="form-control" id="type" name="type">
  				<option value="1">Limit</option>
  				<option value="2">Threshold</option>
  				<option value="3">Both</option>
  			</select>
  		</div>
  	</div>
  	<div class="form-group" id="track">
  		<label for="track" class="col-sm-2 control-label">Track:</label>
  		<div class="col-sm-10">
  			<select class="form-control" id="track" name="track">
  				<option value="1">By Source</option>
  				<option value="2">By Destination</option>
  			</select>
  		</div>
  	</div>
  	<div class="form-group" id="count">
  		<label for="count" class="col-sm-2 control-label">Count:</label>
  		<div class="col-sm-10">
  			<input id="count" name="count" type="text" class="form-control" placeholder="Set the threshold count number."/>
  		</div>
  	</div>
  	<div class="form-group" id="seconds">
  		<label for="seconds" class="col-sm-2 control-label">Seconds:</label>
  		<div class="col-sm-10">
  			<input id="seconds" name="seconds" type="text" class="form-control" placeholder="Set the threshold time limit in seconds."/>
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
  	<div class="form-group" id="comment">
  		<label for="comment" class="col-sm-2 control-label">Comment:</label>
  		<div class="col-sm-10">
  			<input id="comment" name="comment" type="text" class="form-control" placeholder="Add a comment to this action.">
  		</div>
  	</div>
        