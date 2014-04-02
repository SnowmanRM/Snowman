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
	$('button#create').unbind('submit');
	$('button#create').click(function(event){
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
				$('#suppressForm .alert').remove();
				// We might get more than one response, so we iterate over them.
				$.each(data, function() {
					// If the response contains one of these strings, we put the response text near the relevant context and display it. 
					// We also set the outcome flags appropriately so we can handle things differently.
					if(this.response == "sensorCreationSuccess") {
						
						$('#createSensorForm #formContent').html('<h2 class="text-center">'+this.text+'</h2><h2 class="text-center">Here is the sensor secret:</h2>\
								<p class="alert alert-warning text-center">' + this.password + '</p>');
						
						success = true;
					}
					else if(this.response == "suppressExists") {
						
						$('#suppressForm div#sid div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'<br />SIDs: '+this.sids+'</div></div>');
						
						$('#suppressForm div#sid div.col-sm-10 .alert').show("highlight");
						
						warning = true;
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
						$('#createSensorForm input#force').val('False');
						$('button#create-submit').attr('class','btn btn-danger');
						$('button#create-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
					}
					// If there is only a warning, we force a DB commit next time, but we warn the user of some things first, just in case.
					else {
						$('#createSensorForm input#force').val('True');
						$('button#create-submit').attr('class','btn btn-warning');
						$('button#create-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
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
			'csrfmiddlewaretoken': $('#csrf').find('input').val(),
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
	$('#sensorList tbody tr[tree-type="parent"]').each(function(){
		loadSensorChildren(this.id);
	});
	
});
