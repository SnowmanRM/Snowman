{% extends "general/index.tpl" %}

{% block content %}
	{% load staticfiles %}
	<script type="text/javascript" src="{% static 'js/sensor.js' %}"></script>
	{% csrf_token %}
	
	<div id="manipulator" class="col-xs-2 col-sm-2 col-md-2">
		<div class="button-container well">
			<div class="btn-group-vertical btn-block">
				<button class="btn btn-success" data-toggle="modal" data-target="#createSensorModal" id="create">Add Sensor</button>
				<button class="btn btn-info" data-toggle="modal" data-target="#editSensorModal" id="edit">Edit Sensor</button>
				<button class="btn btn-danger" data-toggle="modal" data-target="#deleteSensorModal" id="delete"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Delete Sensors</button>
			</div>
		</div>
	</div>
	
	
	<div class="modal fade" id="createSensorModal" tabindex="-1" role="dialog" aria-labelledby="createSensorModalLabel" aria-hidden="true">
		<div class="modal-dialog">
			<div class="modal-content">
				<form id="createSensorForm" class="form-horizontal" target="" method="post">
					<div class="modal-header">
						<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
						<h4 class="modal-title" id="createSensorModalLabel">Create Sensor</h4>
					</div>
					<div class="modal-body">
						
						<div id="formContent">
						
						</div>
					</div>
					<div class="modal-footer">
						<button type="button" class="btn btn-default" data-dismiss="modal" id="create-close">Close</button>
						<button type="submit" class="btn btn-primary" id="create-submit">Save changes</button>
					</div>
				</form>
			</div>
		</div>
	</div>
	
	<div class="modal fade" id="editSensorModal" tabindex="-1" role="dialog" aria-labelledby="editSensorModal" aria-hidden="true">
	  <div class="modal-dialog">
	    <div class="modal-content">
	      <div class="modal-header">
			   <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
			   <h4 class="modal-title" id="editSensorModal">Edit Sensor</h4>
			 </div>
			<div class="modal-body">
			  <form id="editSensorForm" class="form-horizontal" role="form">
			  	<div id="formContent">
			  		
			  	</div>
			</div>
			<div class="modal-footer">
			  <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
			  <button type="submit" class="btn btn-primary" id="edit-submit" name="edit-submit">Save changes</button>
			  </form>
			</div>
	      
	    </div>
	  </div>
	</div>
	
	<div class="modal fade" id="deleteSensorModal" tabindex="-1" role="dialog" aria-labelledby="deleteSensorModal" aria-hidden="true">
	  <div class="modal-dialog">
	    <div class="modal-content">
	      <div class="modal-header">
			   <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
			   <h4 class="modal-title" id="deleteSensorModal">Delete Sensors</h4>
			 </div>
			<div class="modal-body">
			  <form id="deleteSensorForm" class="form-horizontal" role="form">
			  	<div id="formContent">
			  	{% csrf_token %}
			  		<div class="alert alert-danger row">
			  			<div class="col-sm-1">
			  			<span class="glyphicon glyphicon-warning-sign"></span>
			  			</div>
			  			<div class="col-sm-11">
			  				<strong>Are you absolutely sure you want to delete the Sensors? <br /><br />This cannot be reversed!</strong>
			  			</div>
			  		</div>
			  		<div class="alert alert-warning row">
			  			<div class="col-sm-1">
			  			<span class="glyphicon glyphicon-warning-sign"></span>
			  			</div>
			  			<div class="col-sm-11">
			  				<p>The parent of the Sensors will inherit any child Sensors attached.</p>
			  			</div>
			  		</div>
			  	</div>
			</div>
			<div class="modal-footer">
			  <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
			  <button type="submit" class="btn btn-danger" id="delete-submit" name="delete-submit"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Delete Sensors</button>
			  </form>
			</div>
	      
	    </div>
	  </div>
	</div>

	<div id="content" class="sensors col-xs-10 col-sm-10 col-md-10 pull-right well">
		
		{% include "sensor/sensorList.tpl" %}
			
	</div>
{% endblock %}
