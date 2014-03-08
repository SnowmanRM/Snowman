
	{% csrf_token %}
	<input type="hidden" id="force" name="force" value="False">
  	<div class="form-group" id="sid">
  		<label for="sid" class="col-sm-2 control-label">GID:SID:</label>
  		<div class="col-sm-10">
  			<input type="text" class="form-control" id="sid" name="sid" placeholder="Set the rule in the '1:12345' syntax." required/>
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
  	<div class="form-group" id="ip">
  		<label for="ip" class="col-sm-2 control-label">IP:</label>
  		<div class="col-sm-10">
  			<input id="ip" name="ip" type="text" class="form-control" placeholder="Set the IP, delimit with comma: '1.1.1.1,2.2.2.2/24'." required/>
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
        