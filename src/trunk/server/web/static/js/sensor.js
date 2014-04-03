/*
 * This script controls all the buttons and events on the Sensor page.
 * 
 * 
 */

function initializeClicks() {
	
	// Install click event so that when the header checkbox is clicked, all the other checkboxes is checked.
	$('table thead #checkbox-all').unbind('click');
	$('table thead #checkbox-all').click(function(event){
				
		if ($("table thead #checkbox-all").is(':checked')) {
            $("table #checkbox").each(function () {
                $(this).prop("checked", true);
            });

        } else {
            $("table #checkbox").each(function () {
                $(this).prop("checked", false);
            });
        }
		
	});

	
	// Installs click events on all rows.
	$('table tbody tr.odd').unbind('click');
	$('table tbody tr.odd').click(function(event){
		// This is to make sure a click on the switch doesnt trigger a row open.
		if($(event.target).is('#checkbox')||$(event.target).is('td#checkbox')){
            //event.preventDefault();
            return;
        }
		
		// Toggles clicked row on the 'active' css class so it changes color
		$(this).toggleClass("bg-primary");
		// Shows or hides the next row which is hidden by default.
		$(this).next().toggle();
		
		$(this).next().find('#sensorList tbody tr[tree-type="parent"]').each(function(){
			loadSensorChildren(this.id);
		});
		
	
	});
}

function initializeNewSensorForm() {
	$('button#create').unbind('click');
	$('button#create').click(function(event){
		// Reset this button in the form to default just in case.
		$('button#create-submit').prop("disabled",false);
		$('button#create-submit').attr('class','btn btn-primary');
		$('button#create-submit').html('Save changes');
		
		$.get('/web/sensors/getCreateSensorForm/',function(html){
			
			$('#createSensorForm #formContent').html(html);
		});
	});
	// Overrides the submit button:
	$('#createSensorForm').unbind('submit');
	$('#createSensorForm').submit(function(event){
		// Remove the default actions from the post-button.
		event.preventDefault();
		// Post the data via AJAX
		$.ajax({
			url: "/web/sensors/createSensor/",
			type: "post",
			dataType: "json",
			data: $(this).serialize(),
			success: function(data) {
				// These are flags that determine the outcome of the response.
				var success, warning, error = false;
				// Clean up any old alerts in the form.
				$('#createSensorForm .alert').remove();
				// We might get more than one response, so we iterate over them.
				$.each(data, function() {
					// If the response contains one of these strings, we put the response text near the relevant context and display it. 
					// We also set the outcome flags appropriately so we can handle things differently.
					if(this.response == "sensorCreationSuccess") {
						
						$('#createSensorForm #formContent').html('<h2 class="text-center">'+this.text+'</h2><h2 class="text-center">Here is the sensor secret:</h2>\
								<p class="alert alert-warning text-center">' + this.password + '</p>');
						
						success = true;
					}
					else if(this.response == "sensorNameExists") {
						
						$('#createSensorForm div#name div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
						
						$('#createSensorForm div#name div.col-sm-10 .alert').show("highlight");
						
						error = true;
					}
					else if(this.response == "noName") {
						
						$('#createSensorForm div#name div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
						
						$('#createSensorForm div#name div.col-sm-10 .alert').show("highlight");
						
						error = true;
					}
					else if(this.response == "badIP") {
						
						$('#createSensorForm div#ip div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
						
						$('#createSensorForm div#ip div.col-sm-10 .alert').show("highlight");
						
						error = true;
					}
					
					else if(this.response == "noPOST") {
						
						text = '<div class="alert alert-danger row" style="display: none;">\
							<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
							<div class="col-sm-11">'+this.text+'</div></div>'
						$('#createSensorForm div#formContent').append(text).prepend(text);
									
						$('#createSensorForm div#formContent .alert').show("highlight");
						
						error = true;
					}
				});
				// If the success-flag was set to true, everything went ok and we can show the user this outcome and close the modal.
				if( success ) {
					
					
					$('button#create-submit').hide();
					$('button#create-submit').prop("disabled",true);
					$('button#create-submit').attr('class','btn btn-success');
					$('button#create-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
					$('button#create-submit').show("highlight");
					
					
					$('#createSensorModal #create-close').click(function(event){
						event.preventDefault();
						location.reload(true);
					});
				
				}
				// If the outcome was not a success, we have to show this to the user.
				else if( warning || error ) {
					// If there was an error, we dont force a DB commit next time. The user has to fix the problem and recheck.
					if (error) {
						
						$('button#create-submit').attr('class','btn btn-danger');
						$('button#create-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
					}
					// If there is only a warning, we force a DB commit next time, but we warn the user of some things first, just in case.
					else {
						
						$('button#create-submit').attr('class','btn btn-warning');
						$('button#create-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
					}
				}
			}
		});
		
		
	});
}

function initializeEditSensorForm() {
	$('button#edit').unbind('click');
	$('button#edit').click(function(event){
		// Reset this button in the form to default just in case.
		$('button#edit-submit').prop("disabled",false);
		$('button#edit-submit').attr('class','btn btn-primary');
		$('button#edit-submit').html('Save changes');
		
		var _sensor = $('#checkbox:checked').first().attr('sensor');
		
		// We only load the form if something was selected.
		if (_sensor) {
			$.get('/web/sensors/getEditSensorForm/'+_sensor+'/',function(html){
				
				$('#editSensorForm #formContent').html(html);
				selectRemembers('select#children');
			});
		}
		// Else we just hide the modal again.
		else {
			setTimeout(function() {$('#editSensorModal').modal('hide')}, 1);
		}
	});
	// Overrides the submit button:
	$('#editSensorForm').unbind('submit');
	$('#editSensorForm').submit(function(event){
		// Remove the default actions from the post-button.
		event.preventDefault();
		// Post the data via AJAX
		$.ajax({
			url: "/web/sensors/editSensor/",
			type: "post",
			dataType: "json",
			data: $(this).serialize(),
			success: function(data) {
				// These are flags that determine the outcome of the response.
				var success, warning, error = false;
				// Clean up any old alerts in the form.
				$('#editSensorForm .alert').remove();
				// We might get more than one response, so we iterate over them.
				$.each(data, function() {
					// If the response contains one of these strings, we put the response text near the relevant context and display it. 
					// We also set the outcome flags appropriately so we can handle things differently.
					if(this.response == "sensorCreationSuccess") {
						
						text = '<div class="alert alert-success row" style="display: none;">\
							<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
							<div class="col-sm-11">'+this.text+'</div></div>'
						$('#editSensorForm div#formContent').append(text).prepend(text);
								
						$('#editSensorForm div#formContent .alert').show("highlight");
						
						success = true;
					}
					else if(this.response == "sensorDoesNotExist") {
						
						text = '<div class="alert alert-danger row" style="display: none;">\
							<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
							<div class="col-sm-11">'+this.text+'</div></div>'
						$('#editSensorForm div#formContent').append(text).prepend(text);
								
						$('#editSensorForm div#formContent .alert').show("highlight");
						
						error = true;
					}
					else if(this.response == "noName") {
						
						$('#editSensorForm div#name div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
						
						$('#editSensorForm div#name div.col-sm-10 .alert').show("highlight");
						
						error = true;
					}
					else if(this.response == "noSensorID") {
						
						$('#editSensorForm div#name div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
						
						$('#editSensorForm div#name div.col-sm-10 .alert').show("highlight");
						
						error = true;
					}
					else if(this.response == "badIP") {
						
						$('#editSensorForm div#ip div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
						
						$('#editSensorForm div#ip div.col-sm-10 .alert').show("highlight");
						
						error = true;
					}
					else if(this.response == "sensorParentInbreeding") {
						
						$('#editSensorForm div#parent div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
						
						$('#editSensorForm div#parent div.col-sm-10 .alert').show("highlight");
						
						error = true;
					}
					else if(this.response == "sensorChildInbreeding") {
						
						$('#editSensorForm div#children div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
						
						$('#editSensorForm div#children div.col-sm-10 .alert').show("highlight");
						
						error = true;
					}
					else if(this.response == "noPOST") {
						
						text = '<div class="alert alert-danger row" style="display: none;">\
							<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
							<div class="col-sm-11">'+this.text+'</div></div>'
						$('#editSensorForm div#formContent').append(text).prepend(text);
									
						$('#editSensorForm div#formContent .alert').show("highlight");
						
						error = true;
					}
				});
				// If the success-flag was set to true, everything went ok and we can show the user this outcome and close the modal.
				if( success ) {
					
					
					$('button#edit-submit').hide();
					$('button#edit-submit').prop("disabled",true);
					$('button#edit-submit').attr('class','btn btn-success');
					$('button#edit-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
					$('button#edit-submit').show("highlight");
					
					
					setTimeout(function() {$('#editSensorModal').modal('hide')}, 3000);
					setTimeout(function() {location.reload(true)}, 1000);
				
				}
				// If the outcome was not a success, we have to show this to the user.
				else if( warning || error ) {
					// If there was an error, we dont force a DB commit next time. The user has to fix the problem and recheck.
					if (error) {
						
						$('button#edit-submit').attr('class','btn btn-danger');
						$('button#edit-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
					}
					// If there is only a warning, we force a DB commit next time, but we warn the user of some things first, just in case.
					else {
						
						$('button#edit-submit').attr('class','btn btn-warning');
						$('button#edit-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
					}
				}
			}
		});
		
		
	});
}

function initializeDeleteSensorForm() {
	$('button#delete').unbind('click');
	$('button#delete').click(function(event){
		// Reset this button in the form to default just in case.
				
		var _sensors = $('#checkbox:checked[sensor]');
		
		// We only load the form if something was selected.
		if (_sensors.length > 0) {
			$(_sensors).each(function(){
				
				$('#deleteSensorForm #formContent').prepend('<input type="hidden" id="id" name="id" value="'+$(this).attr('sensor')+'">');
				
			});
		}
		// Else we just hide the modal again.
		else {
			setTimeout(function() {$('#deleteSensorModal').modal('hide')}, 1);
		}
	});
	// Overrides the submit button:
	$('#deleteSensorForm').unbind('submit');
	$('#deleteSensorForm').submit(function(event){
		// Remove the default actions from the post-button.
		event.preventDefault();
		// Post the data via AJAX
		$.ajax({
			url: "/web/sensors/deleteSensor/",
			type: "post",
			dataType: "json",
			data: $(this).serialize(),
			success: function(data) {
				// These are flags that determine the outcome of the response.
				var success, warning, error = false;
				// Clean up any old alerts in the form.
				//$('#deleteSensorForm .alert').remove();
				// We might get more than one response, so we iterate over them.
				$.each(data, function() {
					// If the response contains one of these strings, we put the response text near the relevant context and display it. 
					// We also set the outcome flags appropriately so we can handle things differently.
					if(this.response == "sensorSuccessfulDeletion") {
						
						text = '<div class="alert alert-success row" style="display: none;">\
							<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
							<div class="col-sm-11">'+this.text+'</div></div>'
						$('#deleteSensorForm div#formContent').append(text).prepend(text);
								
						$('#deleteSensorForm div#formContent .alert').show("highlight");
						
						success = true;
					}
					else if(this.response == "sensorDoesNotExist") {
						
						text = '<div class="alert alert-danger row" style="display: none;">\
							<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
							<div class="col-sm-11">'+this.text+'</div></div>'
						$('#deleteSensorForm div#formContent').append(text).prepend(text);
								
						$('#deleteSensorForm div#formContent .alert').show("highlight");
						
						error = true;
					}
					else if(this.response == "noIDsGiven") {
						
						text = '<div class="alert alert-success row" style="display: none;">\
							<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
							<div class="col-sm-11">'+this.text+'</div></div>'
						$('#deleteSensorForm div#formContent').append(text).prepend(text);
								
						$('#deleteSensorForm div#formContent .alert').show("highlight");
						
						error = true;
					}
				});
				// If the success-flag was set to true, everything went ok and we can show the user this outcome and close the modal.
				if( success ) {
					
					
					$('button#delete-submit').hide();
					$('button#delete-submit').prop("disabled",true);
					$('button#delete-submit').attr('class','btn btn-success');
					$('button#delete-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
					$('button#delete-submit').show("highlight");
					
					
					setTimeout(function() {$('#deleteSensorModal').modal('hide')}, 3000);
					setTimeout(function() {location.reload(true)}, 1000);
				
				}
				// If the outcome was not a success, we have to show this to the user.
				else if( warning || error ) {
					// If there was an error, we dont force a DB commit next time. The user has to fix the problem and recheck.
					if (error) {
						
						$('button#delete-submit').attr('class','btn btn-danger');
						$('button#delete-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
					}
					// If there is only a warning, we force a DB commit next time, but we warn the user of some things first, just in case.
					else {
						
						$('button#delete-submit').attr('class','btn btn-warning');
						$('button#delete-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
					}
				}
			}
		});
		
		
	});
}

function initializeRegenerateSecretButtons() {
	$('button#regenerateSensorSecret').unbind('click');
	$('button#regenerateSensorSecret').click(function() {
		var d = {
			'sid': $(this).attr('sid'),
			'csrfmiddlewaretoken': $('input[name="csrfmiddlewaretoken"]').val(),
		};
		
		$.post("/web/sensors/regenerateSecret/", d, function(data, status) {
			if(data.status == true) {
				alert("New secret is\n\n"+data.password);
			}
		});
	});
}

function initializeRequestUpdateButtons() {
	$('button#requestUpdate').unbind('click');
	$('button#requestUpdate').click(function() {
		var d = {
			'sid': $(this).attr('sid'),
			'csrfmiddlewaretoken': $('input[name="csrfmiddlewaretoken"]').val(),
		};
		
		$.post("/web/sensors/requestUpdate/", d, function(data, status) {
			if(data.status == true) {
				alert("SUCCESS!\n" + data.message)
			} else {
				alert("FAILED:\n" + data.message)
			}
		});
	});
}

function loadSensorChildren(sensorID) {
	var _sensorID = sensorID;
	
	$.get('/web/sensors/getSensorChildren/'+_sensorID+'/', function(html){
		$('#sensorList tbody tr#'+_sensorID+'').next().find('td .panel').append(html);
		initializeClicks();
	});
}

// When the documents is finished loading, initialize everything.
$(document).ready(function(){
	initializeClicks();
	initializeNewSensorForm();
	initializeRegenerateSecretButtons();
	initializeRequestUpdateButtons();
	initializeEditSensorForm();
	initializeDeleteSensorForm()
	$('#sensorList tbody tr[tree-type="parent"]').each(function(){
		loadSensorChildren(this.id);
	});
	animateManipulator();
});
