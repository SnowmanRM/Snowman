/*
 * This script controls all the buttons and events on the Sensor page.
 * 
 * 
 */

function reloadSensorTable(f) {
	$.get("/web/sensors/getSensorList/", function(data) {
		$('#sensorList').html(data);
		f();
		initializeRegenerateSecretButtons();
	});
}

function initializeNewSensorForm() {
	// Overrides the submit button:
	$('#createSensorForm').unbind('submit');
	$('#createSensorForm').submit(function(event){
		// Post the data via AJAX
		$.post("/web/sensors/new/", $(this).serialize(), function(data, status){
			if(data.status == true) {
				$('#createSensorModal').modal('hide');
				$('#AJAX-Return').html("<p>" + data.message + data.password + "</p>");
				reloadSensorTable(function() {
					$('td.sensorSecret-' + data.id).html(data.password);
				});
			} else {
				$('#modalAjaxReturn').html("<p>" + data.message + "</p>");
			}
		});
		
		// Remove the default actions from the post-button.
		event.preventDefault();
	});
}

function initializeRegenerateSecretButtons() {
	$('button.regenerateSensorSecret').unbind('click');
	$('button.regenerateSensorSecret').click(function() {
		var d = {
			'sid': $(this).attr('sid'),
			'csrfmiddlewaretoken': $('#csrf').find('input').val(),
		};
		
		$.post("/web/sensors/regenerateSecret/", d, function(data, status) {
			if(data.status == true) {
				$('#sensorSecret-' + data.sid).html(data.password);
			}
		});
	});
}

// When the documents is finished loading, initialize everything.
$(document).ready(function(){
	initializeNewSensorForm();
	initializeRegenerateSecretButtons();
});
