{# thresholdForm.tpl is the template for the form used to input thresholds. #} 
{# It consists of various form elements needed for a threshold. #}
{#  #}

	{% csrf_token %}
	{% if edit %}
		{% if eventFilter %}
			<input type="hidden" id="force" name="force" value="False">
			<input type="hidden" id="edit" name="edit" value="{{ eventFilter.id }}">
			<input type="hidden" class="form-control" id="sid" name="sid" value="{{ eventFilter.rule.generator.GID }}:{{ eventFilter.rule.SID }}"/>
			<input type="hidden" value="eventFilter" name="filterType">
		  	<div class="form-group" id="filter">
		  	{# TODO: korrekt styling av radio buttons. Dersom detection er aktiv skal "Type" være deaktivert.#}
		  		<label for="filter" class="col-sm-2 control-label">Filter type:</label>
		  		<div class="col-sm-10">
		  			 <div class="radio">
		  			 <label for="eventFilter">
						<input type="radio" value="eventFilter" name="filterType" checked="checked" disabled>event_filter</label>
					</div>
					<div class="radio">
					<label for="detectionFilter">
						<input type="radio" value="detectionFilter" name="filterType" disabled>detection_filter</label>
					</div>
		  		</div>
		  	</div>
		  	<div class="form-group" id="sid">
		  		<label for="sid" class="col-sm-2 control-label">GID:SID:</label>
		  		<div class="col-sm-10">
		  			<input type="text" class="form-control" id="sid" name="sid" value="{{ eventFilter.rule.generator.GID }}:{{ eventFilter.rule.SID }}" disabled/>
		  		</div>
		  	</div>
		  	<div class="form-group" id="type">
		  		<label for="type" class="col-sm-2 control-label">Type:</label>
		  		<div class="col-sm-10">
		  			<select class="form-control" id="type" name="type">
		  				<option value="1" {% if eventFilter.eventFilterType == 1 %}selected{%endif%}>Limit</option>
		  				<option value="2" {% if eventFilter.eventFilterType == 2 %}selected{%endif%}>Threshold</option>
		  				<option value="3" {% if eventFilter.eventFilterType == 3 %}selected{%endif%}>Both</option>
		  			</select>
		  		</div>
		  	</div>
		  	<div class="form-group" id="track">
		  		<label for="track" class="col-sm-2 control-label">Track:</label>
		  		<div class="col-sm-10">
		  			<select class="form-control" id="track" name="track">
		  				<option value="1" {% if eventFilter.track == 1 %}selected{%endif%}>By Source</option>
		  				<option value="2" {% if eventFilter.track == 2 %}selected{%endif%}>By Destination</option>
		  			</select>
		  		</div>
		  	</div>
		  	<div class="form-group" id="count">
		  		<label for="count" class="col-sm-2 control-label">Count:</label>
		  		<div class="col-sm-10">
		  			<input id="count" name="count" type="text" class="form-control" value="{{ eventFilter.count }}"/>
		  		</div>
		  	</div>
		  	<div class="form-group" id="seconds">
		  		<label for="seconds" class="col-sm-2 control-label">Seconds:</label>
		  		<div class="col-sm-10">
		  			<input id="seconds" name="seconds" type="text" class="form-control" value="{{ eventFilter.seconds }}"/>
		  		</div>
		  	</div>
		  	<div class="form-group" id="sensors">
		  		<label for="sensors" class="col-sm-2 control-label">Sensors:</label>
		  		<div class="col-sm-10">
		  			<select multiple class="form-control" id="sensors" name="sensors">
		  				{% if allsensors %}
							{% for sensor in allsensors %}
								<option value="{{ sensor.id }}" {% if sensor == eventFilter.sensor %}selected{%endif%}>{{ sensor.name }}</option>
							{% endfor %}
						{% endif %}
		  			</select>
		  		</div>
		  	</div>
		  	<div class="form-group" id="comment">
		  		<label for="comment" class="col-sm-2 control-label">Comment:</label>
		  		<div class="col-sm-10">
		  			<input id="comment" name="comment" type="text" class="form-control" value="{{ eventFilter.comment.comment }}">
		  		</div>
		  	</div>
		  	<div class="form-group" id="note">
		  		<label for="comment" class="col-sm-2 control-label"></label>
		  		<div class="col-sm-10">
		  			Note that only one filter of each type is allowed per rule per sensor. If multiple filters are specified in a hierarchy of sensors, the rule will assume the filter closest to the selected sensor (see documentation for details).
		  		</div>
		  	</div>
	  	{% elif detectionFilter %}
	  		<input type="hidden" id="force" name="force" value="False">
	  		<input type="hidden" id="edit" name="edit" value="{{ detectionFilter.id }}">
	  		<input type="hidden" class="form-control" id="sid" name="sid" value="{{ detectionFilter.rule.generator.GID }}:{{ detectionFilter.rule.SID }}"/>
	  		<input type="hidden" value="detectionFilter" name="filterType">
		  	<div class="form-group" id="filter">
		  	{# TODO: korrekt styling av radio buttons. Dersom detection er aktiv skal "Type" være deaktivert.#}
		  		<label for="filter" class="col-sm-2 control-label">Filter type:</label>
		  		<div class="col-sm-10">
		  			 <div class="radio">
		  			 <label for="eventFilter">
						<input type="radio" value="eventFilter" name="filterType" disabled>event_filter</label>
					</div>
					<div class="radio">
					<label for="detectionFilter">
						<input type="radio" value="detectionFilter" name="filterType" checked="checked" disabled>detection_filter</label>
					</div>
		  		</div>
		  	</div>
		  	<div class="form-group" id="sid">
		  		<label for="sid" class="col-sm-2 control-label">GID:SID:</label>
		  		<div class="col-sm-10">
		  			<input type="text" class="form-control" id="sid" name="sid" value="{{ detectionFilter.rule.generator.GID }}:{{ detectionFilter.rule.SID }}" disabled/>
		  		</div>
		  	</div>
		  	<div class="form-group" id="type">
		  		<label for="type" class="col-sm-2 control-label">Type:</label>
		  		<div class="col-sm-10">
		  			<select class="form-control" id="type" name="type" disabled>
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
		  				<option value="1" {% if detectionFilter.track == 1 %}selected{%endif%}>By Source</option>
		  				<option value="2"{% if detectionFilter.track == 1 %}selected{%endif%}>By Destination</option>
		  			</select>
		  		</div>
		  	</div>
		  	<div class="form-group" id="count">
		  		<label for="count" class="col-sm-2 control-label">Count:</label>
		  		<div class="col-sm-10">
		  			<input id="count" name="count" type="text" class="form-control" value="{{ detectionFilter.count }}"/>
		  		</div>
		  	</div>
		  	<div class="form-group" id="seconds">
		  		<label for="seconds" class="col-sm-2 control-label">Seconds:</label>
		  		<div class="col-sm-10">
		  			<input id="seconds" name="seconds" type="text" class="form-control" value="{{ detectionFilter.count }}"/>
		  		</div>
		  	</div>
		  	<div class="form-group" id="sensors">
		  		<label for="sensors" class="col-sm-2 control-label">Sensors:</label>
		  		<div class="col-sm-10">
		  			<select multiple class="form-control" id="sensors" name="sensors">
		  				{% if allsensors %}
							{% for sensor in allsensors %}
								<option value="{{ sensor.id }}" {% if sensor == detectionFilter.sensor %}selected{%endif%}>{{ sensor.name }}</option>
							{% endfor %}
						{% endif %}
		  			</select>
		  		</div>
		  	</div>
		  	<div class="form-group" id="comment">
		  		<label for="comment" class="col-sm-2 control-label">Comment:</label>
		  		<div class="col-sm-10">
		  			<input id="comment" name="comment" type="text" class="form-control" value="{{ detectionFilter.comment.comment }}" />
		  		</div>
		  	</div>
		  	<div class="form-group" id="note">
		  		<label for="comment" class="col-sm-2 control-label"></label>
		  		<div class="col-sm-10">
		  			Note that only one filter of each type is allowed per rule per sensor. If multiple filters are specified in a hierarchy of sensors, the rule will assume the filter closest to the selected sensor (see documentation for details).
		  		</div>
		  	</div>
	  	{% endif %}
	{% else %}
	<input type="hidden" id="force" name="force" value="False">
  	<div class="form-group" id="filter">
  	{# TODO: korrekt styling av radio buttons. Dersom detection er aktiv skal "Type" være deaktivert.#}
  		<label for="filter" class="col-sm-2 control-label">Filter type:</label>
  		<div class="col-sm-10">
  			 <div class="radio">
  			 <label for="eventFilter">
				<input type="radio" value="eventFilter" name="filterType" checked="checked">event_filter</label>
			</div>
			<div class="radio">
			<label for="detectionFilter">
				<input type="radio" value="detectionFilter" name="filterType" >detection_filter</label>
			</div>
  		</div>
  	</div>
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
  			<select multiple class="form-control" id="sensors" name="sensors" required>
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
  	<div class="form-group" id="note">
  		<label for="comment" class="col-sm-2 control-label"></label>
  		<div class="col-sm-10">
  			Note that only one filter of each type is allowed per rule per sensor. If multiple filters are specified in a hierarchy of sensors, the rule will assume the filter closest to the selected sensor (see documentation for details).
  		</div>
  	</div>      
  	{% endif %}  