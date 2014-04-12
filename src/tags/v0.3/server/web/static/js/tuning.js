/*
 * This script controls all the buttons and events on the Tuning pages.
 * 
 * 
 */


// This function initializes all the buttons and events.
function listInitialize() {
	$('#tuning-buttons #edit').unbind('click');
	$('#tuning-buttons #edit').click(function(event){
		
		tuningID = $('#checkbox:checked').first().attr('tuningID');
		tuningType = $('#checkbox:checked').first().attr('tuningtype');
		
		// We only load the form if something was selected.
		if (tuningID) {
			// We reset the tuningForm id.
			$('#tuningFormModal form').attr('id','tuningForm');
			$('#tuningFormModal button[type="submit"]').attr('id', 'tuning-submit');

			if (tuningType == "EventFilter") {
				// Load the form with AJAX.
				$.get('/web/tuning/getEventFilterForm/'+tuningID+'/', function(html){
					$('#tuningFormModal #formContent').html(html);			
					// Reset this button in the form to default just in case.
					$('button#tuning-submit').prop("disabled",false);
					$('button#tuning-submit').attr('class','btn btn-primary');
					$('button#tuning-submit').html('Save changes');
					
					// We change the form into a thresholdForm.
					$('#tuningFormModal form').attr('id','filterForm');
					$('#tuningFormModal #tuning-submit').attr('id', 'filter-submit');
					
					// We want the select in the form to remember choices.
					selectRemembers('select#sensors');
					
					// Install validators on a few of the form fields and set up the submit handler.
					$('#thresholdForm').validate({
						rules: {
							count: {
								required: true,
								number: true
							},
							seconds: {
								required: true,
								number: true				
							}
							
						},
						submitHandler: function(form) {
						
							submitThresholdForm(form);
						}
						
					});
				});
			}
			else if (tuningType == "DetectionFilter") {
				// Load the form with AJAX.
				$.get('/web/tuning/getDetectionFilterForm/'+tuningID+'/', function(html){
					$('#tuningFormModal #formContent').html(html);			
					// Reset this button in the form to default just in case.
					$('button#tuning-submit').prop("disabled",false);
					$('button#tuning-submit').attr('class','btn btn-primary');
					$('button#tuning-submit').html('Save changes');
					
					// We change the form into a thresholdForm.
					$('#tuningFormModal form').attr('id','filterForm');
					$('#tuningFormModal #tuning-submit').attr('id', 'filter-submit');
					
					// We want the select in the form to remember choices.
					selectRemembers('select#sensors');
					
					// Install validators on a few of the form fields and set up the submit handler.
					$('#thresholdForm').validate({
						rules: {
							count: {
								required: true,
								number: true
							},
							seconds: {
								required: true,
								number: true				
							}
							
						},
						submitHandler: function(form) {
						
							submitFilterForm(form);
						}
						
					});
				});
			}
			else if (tuningType == "Suppression") {
				// Load the form with AJAX.
				$.get('/web/tuning/getSuppressForm/'+tuningID+'/', function(html){
					$('#tuningFormModal #formContent').html(html);			
					// Reset this button in the form to default just in case.
					$('button#tuning-submit').prop("disabled",false);
					$('button#tuning-submit').attr('class','btn btn-primary');
					$('button#tuning-submit').html('Save changes');
					
					// We change the form into a suppressForm.
					$('#tuningFormModal form').attr('id','suppressForm');
					$('#tuningFormModal #tuning-submit').attr('id', 'suppress-submit');
					
					// We want the select in the form to remember choices.
					selectRemembers('select#sensors');
					
					// Install validators on a few of the form fields and set up the submit handler.
					$('#suppressForm').validate({
						submitHandler: function(form) {
							
							submitSuppressForm(form);
						}
						
					});
				});
			}
		}
		// Else we just hide the modal again.
		else {
			setTimeout(function() {$('#tuningFormModal').modal('hide')}, 1);
		}
		
	});
	$('#tuning-buttons #delete').unbind('click');
	$('#tuning-buttons #delete').click(function(event){
		
		var _tuningIDs = $('#checkbox:checked');
		// We only load the form if something was selected.
		if (_tuningIDs.length > 0) {
			
			// For each checked rule, we add them to the select list.
			$(_tuningIDs).each(function(){
				
				$('#deleteTuningModal #formContent').append('<input type="hidden" id="id" name="id" value="'+$(this).attr('tuningid')+'-'+$(this).attr('tuningtype')+'">');
			});
			
			// Install validators on a few of the form fields and set up the submit handler.
			$('#deleteTuningForm').submit(function(event){ event.preventDefault(); submitDeleteTuningForm(this)});			
		
		}
		// Else we just hide the modal again.
		else {
			setTimeout(function() {$('#deleteTuningModal').modal('hide')}, 1);
		}
	});
}

//This function handles submitting suppress forms and parsing the response.
function submitSuppressForm(form) {
	
	// We send the form serialized to the server.
	$.ajax({
		url: "/web/tuning/setSuppressOnRule/",
		type: "post",
		dataType: "json",
		data: $(form).serialize(),
		success: function(data) {
			// These are flags that determine the outcome of the response.
			var success, warning, error = false;
			// Clean up any old alerts in the form.
			$('#suppressForm .alert').remove();
			// We might get more than one response, so we iterate over them.
			$.each(data, function() {
				// If the response contains one of these strings, we put the response text near the relevant context and display it. 
				// We also set the outcome flags appropriately so we can handle things differently.
				if(this.response == "suppressAdded") {
					
					text = '<div class="alert alert-success row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#suppressForm div#formContent').append(text).prepend(text);
							
					$('#suppressForm div#formContent .alert').show("highlight");
					
					success = true;
				}
				else if(this.response == "suppressExists") {
					
					$('#suppressForm div#sid div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'<br />SIDs: '+this.sids+'</div></div>');
					
					$('#suppressForm div#sid div.col-sm-10 .alert').show("highlight");
					
					warning = true;
				}
				else if(this.response == "allSensors") {
					
					$('#suppressForm div#sensors div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#suppressForm div#sensors div.col-sm-10 .alert').show("highlight");
					
					warning = true;
				}
				else if(this.response == "noComment") {
					
					$('#suppressForm div#comment div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#suppressForm div#comment div.col-sm-10 .alert').show("highlight");

					warning = true;
				}
				else if (this.response == "invalidGIDSIDFormat") {
					
					$('#suppressForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#suppressForm div#sid div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "gidDoesNotExist") {
					
					$('#suppressForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#suppressForm div#sid div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "sidDoesNotExist") {
					
					$('#suppressForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#suppressForm div#sid div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "sensorDoesNotExist") {
					
					$('#suppressForm div#sensors div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#suppressForm div#sensors div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "ruleDoesNotExist") {
					
					$('#suppressForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#suppressForm div#sid div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "trackOutOfRange") {
					
					$('#suppressForm div#type div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#suppressForm div#type div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if(this.response == "addSuppressFailure") {
					
					$('#suppressForm input#force').val('False');
					text = '<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-danger form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>'
					$('#suppressForm div#formContent').append(text).prepend(text);
							
					$('#suppressForm div#formContent .alert').show("highlight");
					
					error = true;
				}
				else if (this.response == "badIP") {
					
					$('#suppressForm div#ip div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.ips+' '+this.text+'</div></div>');
							
					$('#suppressForm div#ip div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "noIPGiven") {
					
					$('#suppressForm div#ip div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#suppressForm div#ip div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "addSuppressAddressFailure") {
					
					$('#suppressForm div#ip div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#suppressForm div#ip div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				
			});
			
			// If the success-flag was set to true, everything went ok and we can show the user this outcome and close the modal.
			if( success ) {
				
				$('#suppressForm input#force').val('False');
				$('button#suppress-submit').hide();
				$('button#suppress-submit').prop("disabled",true);
				$('button#suppress-submit').attr('class','btn btn-success');
				$('button#suppress-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
				$('button#suppress-submit').show("highlight");
				
				setTimeout(function() {$('#suppressFormModal').modal('hide')}, 3000);
				setTimeout(function() {location.reload(true)}, 1000);
			
			}
			// If the outcome was not a success, we have to show this to the user.
			else if( warning || error ) {
				// If there was an error, we dont force a DB commit next time. The user has to fix the problem and recheck.
				if (error) {
					$('#suppressForm input#force').val('False');
					$('button#suppress-submit').attr('class','btn btn-danger');
					$('button#suppress-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
				}
				// If there is only a warning, we force a DB commit next time, but we warn the user of some things first, just in case.
				else {
					$('#suppressForm input#force').val('True');
					$('button#suppress-submit').attr('class','btn btn-warning');
					$('button#suppress-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
				}
			}
		}
		
	});
}

//This function handles submitting filter forms and parsing the response.
function submitFilterForm(form) {
	
	// We send the form serialized to the server.
	$.ajax({
		url: "/web/tuning/setFilterOnRule/",
		type: "post",
		dataType: "json",
		data: $(form).serialize(),
		success: function(data) {
			// These are flags that determine the outcome of the response.
			var success, warning, error = false;
			// Clean up any old alerts in the form.
			$('#filterForm .alert').remove();
			// We might get more than one response, so we iterate over them.
			$.each(data, function() {
				// If the response contains one of these strings, we put the response text near the relevant context and display it. 
				// We also set the outcome flags appropriately so we can handle things differently.
				if(this.response == "filterAdded") {
					
					text = '<div class="alert alert-success row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#filterForm div#formContent').append(text).prepend(text);
							
					$('#filterForm div#formContent .alert').show("highlight");
					
					success = true;
				}
				else if(this.response == "thresholdExists") {
					
					$('#filterForm div#sid div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'<br />SIDs: '+this.sids+'</div></div>');
					
					$('#filterForm div#sid div.col-sm-10 .alert').show("highlight");
					
					warning = true;
				}
				else if(this.response == "allSensors") {
					
					$('#filterForm div#sensors div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#filterForm div#sensors div.col-sm-10 .alert').show("highlight");
					
					warning = true;
				}
				else if(this.response == "noComment") {
					
					$('#filterForm div#comment div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#v div#comment div.col-sm-10 .alert').show("highlight");

					warning = true;
				}
				else if (this.response == "invalidGIDSIDFormat") {
					
					$('#filterForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#filterForm div#sid div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "gidDoesNotExist") {
					
					$('#filterForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#filterForm div#sid div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "sidDoesNotExist") {
					
					$('#filterForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#filterForm div#sid div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "sensorDoesNotExist") {
					
					$('#filterForm div#sensors div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#filterForm div#sensors div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "ruleDoesNotExist") {
					
					$('#filterForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#filterForm div#sid div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "typeOutOfRange") {
					
					$('#filterForm div#type div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#filterForm div#type div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "trackOutOfRange") {
					
					$('#filterForm div#type div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#filterForm div#type div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if(this.response == "addFilterFailure") {
					
					$('#filterForm input#force').val('False');
					text = '<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-danger form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>'
					$('#filterForm div#formContent').append(text).prepend(text);
							
					$('#filterForm div#formContent .alert').show("highlight");
					
					error = true;
				}
				
				
			});
			
			// If the success-flag was set to true, everything went ok and we can show the user this outcome and close the modal.
			if( success ) {
				
				
				$('#filterForm input#force').val('False');
				$('button#filter-submit').hide();
				$('button#filter-submit').prop("disabled",true);
				$('button#filter-submit').attr('class','btn btn-success');
				$('button#filter-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
				$('button#filter-submit').show("highlight");
				
				setTimeout(function() {$('#filterFormModal').modal('hide')}, 3000);
				setTimeout(function() {location.reload(true)}, 1000);
				
			}
			// If the outcome was not a success, we have to show this to the user.
			else if( warning || error ) {
				// If there was an error, we dont force a DB commit next time. The user has to fix the problem and recheck.
				if (error) {
					$('#filterForm input#force').val('False');
					$('button#filter-submit').attr('class','btn btn-danger');
					$('button#filter-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
				}
				// If there is only a warning, we force a DB commit next time, but we warn the user of some things first, just in case.
				else {
					$('#filterForm input#force').val('True');
					$('button#filter-submit').attr('class','btn btn-warning');
					$('button#filter-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
				}
			}
		}
		
		
	});
	
};

// This function submits deletions of tuning and parses the response.
function submitDeleteTuningForm(form){
	// We send the form serialized to the server.
	$.ajax({
		url: "/web/tuning/deleteTuning/",
		type: "post",
		dataType: "json",
		data: $(form).serialize(),
		success: function(data) {
			// These are flags that determine the outcome of the response.
			var success, warning, error = false;
			// We might get more than one response, so we iterate over them.
			$.each(data, function() {
				// If the response contains one of these strings, we put the response text near the relevant context and display it. 
				// We also set the outcome flags appropriately so we can handle things differently.
				if(this.response == "tuningSuccessfulDeletion") {
					
					text = '<div class="alert alert-success row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#deleteRuleSetForm div#formContent').append(text).prepend(text);
							
					$('#deleteRuleSetForm div#formContent .alert').show("highlight");
					
					success = true;
				}
				else if (this.response == "tuningDoesNotExists") {
					
					text = '<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#deleteRuleSetForm div#formContent').append(text).prepend(text);
							
					$('#deleteRuleSetForm div#formContent .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "invalidTuningType") {
					
					text = '<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#deleteRuleSetForm div#formContent').append(text).prepend(text);
							
					$('#deleteRuleSetForm div#formContent .alert').show("highlight");
							
					error = true;
				}
				else if(this.response == "noIDsGiven") {
					
					
					text = '<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#deleteRuleSetForm div#formContent').append(text).prepend(text);
							
					$('#deleteRuleSetForm div#formContent .alert').show("highlight");
							
					error = true;
				}
				
				// If the success-flag was set to true, everything went ok and we can show the user this outcome and close the modal.
				if( success ) {
					
					
					$('button#delete-submit').hide();
					$('button#delete-submit').prop("disabled",true);
					$('button#delete-submit').attr('class','btn btn-success');
					$('button#delete-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
					$('button#delete-submit').show("highlight");
					
					setTimeout(function() {$('#deleteRuleSetModal').modal('hide')}, 3000);
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
			});
		}
	});
	
}


// This function is used to dynamically retrieve a page that contains a list of rules.
function getPage(pageNr){
	// Copies pagenr to local _pagenr variable.
	var _pageNr = parseInt(pageNr); 
	
	// Ajax-call for the required page. We return it so we can use $.when
	return $.get('/web/tuning/page/'+_pageNr+'/', function(html) { 
		downloadId = $('table', $('<div/>').html(html)).attr("id");
		pageAlreadyExists = $('#content table[id="'+downloadId+'"]');

		if( pageAlreadyExists.length ) {

			$('#content [id="'+downloadId+'"]').replaceWith(html);
			
		}
		else {
	
			// When the content is loaded, append to content container.
			$('#content').append(html);
			
		}
		
		
		// We need to reinitialize all the click events and switchbuttons.
		listInitialize();

	})
	
}

//This function is used to dynamically retrieve a page that contains a list of rules.
function getSearchPage(pagenr, searchfield, searchstring){
	// Copies pagenr to local _pagenr variable.
	var _pagenr = parseInt(pagenr); 
	var _searchfield = searchfield;
	var _searchstring = searchstring;
		
	// Ajax-call for the required page. We return it so we can use $.when.
	// We also include the CSRF token so Django can know we are friendly.
	return $.ajax({
		url:'/web/tuning/search/'+_pagenr+'/',
		type:'POST',
		data: {searchf: _searchfield, searchs: _searchstring, csrfmiddlewaretoken: $('input').attr('name', 'csrfmiddlewaretoken').val()}
		
	}).done(function(html) { 
		// When the content is loaded, append to content container.
		
		$('#content').append(html);
		listInitialize();
		
	});
	
}

// This function is used to dynamically load three pages before and after the current page.
function loadNextPages(currentpage, pagecount) {
	
	// Copy passed variables to local variables.
	var _currentpage = currentpage;
	var _pagecount = pagecount;
	
	// Loop for -3 and +3 from the current page.
	for(var i=-3;i<=3;i++) {
		// We dont want negative page numbers or 
		// pages outside the actual page range
		if (_currentpage+i > 1 && _currentpage+i < _pagecount && _currentpage+i != _currentpage) {
			// Try to find a page element with this id nr.
			var _pageexists = $('#content .table#'+(_currentpage+i)+'').length;
			// If the page doesnt exist, we need to load it.
			if (!_pageexists) {
				// Loads the page it didnt find.
				getPage(_currentpage+i);
				
			}
		}
	}
	
}

//This function is used to dynamically load three pages before and after the current page.
//This function is utilized for the search pages.
function loadNextSearchPages(currentpage, pagecount, searchfield, searchstring) {
	
	// Copy passed variables to local variables.
	var _currentpage = currentpage;
	var _pagecount = pagecount;
	var _searchfield = searchfield;
	var _searchstring = searchstring;
	
	// Loop for -3 and +3 from the current page.
	for(var i=-3;i<=3;i++) {
		// We dont want negative page numbers or 
		// pages outside the actual page range
		if (_currentpage+i > 1 && _currentpage+i < _pagecount && _currentpage+i != _currentpage) {
			// Try to find a page element with this id nr.
			var _pageexists = $('#content .table#search'+(_currentpage+i)+'').length;
			// If the page doesnt exist, we need to load it.
			if (!_pageexists) {
				// Loads the page it didnt find.
				getSearchPage(_currentpage+i, _searchfield, _searchstring);
			}
		}
	}
	
}

// This function is used to switch between pages in the list.
function switchPage(page) {
	$(document).ajaxStop(function(){
		var _page = page;
		// Hide the page marked .current and then turn off its .current class.
		$('#content .current').hide().toggleClass('current');
		// Show the page we want and set it to contain the .current class. Select first in case ajax hickups and produces two.
		$('#content .table#'+_page).show().toggleClass('current');
	});
	
}

// This function loads the paginator used when displaying a full list of all rules.
function loadPaginator(currentpage, pagecount) {
	
	// We set some options for the paginator and its click function.
	var options = {
			currentPage: currentpage,
			totalPages: pagecount,
			numberOfPages: 3,
			bootstrapMajorVersion: 3,
			onPageClicked: function(e,originalEvent,type,page){
				
				originalEvent.preventDefault();
				// Load the next pages.
				loadNextPages(page, pagecount);
				// Hide the page we no longer want and show the one we want.
				switchPage(page);
				// We update the window location hash value.
				window.location.hash = page;
			}
	}
	
	// Start the paginator.
	$('#paginator').bootstrapPaginator(options);
	
}

//This function loads the paginator used when a search is done.
function loadSearchPaginator(currentpage, pagecount, _searchfield, _searchstring) {
	
	// We set some options for the paginator and its click function.
	var options = {
			currentPage: currentpage,
			totalPages: pagecount,
			numberOfPages: 3,
			bootstrapMajorVersion: 3,
			onPageClicked: function(e,originalEvent,type,page){
				originalEvent.preventDefault();
				// Hide the page we no longer want and show the one we want.
				switchPage('search'+page);
				
				// Load the next pages.
				loadNextSearchPages(page, pagecount, _searchfield, _searchstring);

			}
	}
	
	// Start the paginator.
	$('#paginator').bootstrapPaginator(options);
	
}

//This function initializes the search field and triggers on keyup.
function searchField() {

	$('#search-container input#searchtext').keyup(function(event){ // This is triggered when someone types in the inputfield.
		console.log(event);
		
		// We get the what we're searching in from the select.
		var _searchfield = $('#search-container select#searchfield').val();

		// This is the string we want to match.
		var _searchstring = $('#search-container input#searchtext').val();
		
		// If the searchstring is empty, user has emptied the field. We want to revert to pre-search state.
		if(!_searchstring) { 
			// Grab the window hash as reference to where we were.
			var hash = parseInt(window.location.hash.slice(1));
			// If theres a hashvalue and its not the first page.
			if (hash && hash != 1) {
				// We obviously want another page.
				var currentpage = hash;
			}
			else {
				var currentpage = 1;
			}
			// We have to find these variables again.
			var pagelength = $('#paginator').attr('pagelength');
			var itemcount = $('#paginator').attr('itemcount');
			pagecount =  Math.floor(itemcount / pagelength);
			if (itemcount%pagecount == 0) pagecount--; // If the mod is zero, there are no new items in the last page.
			if (pagecount == 0) pagecount++;
			// Switch back to the current page.
			switchPage(currentpage);
			// Reload the paginator to its former state.

			loadPaginator(currentpage, pagecount);
			// Remove any searchresult container from the DOM.
			$('#content #searchresult').remove();
		}
		
		if ( event.which == 13 || !event.which ) {
		     
		//delay(function(){	// We add a bit of delay.

				// Remove any previous searches from the DOM.
				$('#content #searchresult').remove();
				// We do an ajax call to retrieve the first page of the search results.
				$.when(getSearchPage(1, _searchfield, _searchstring)).done(function() {
					// Switch the page to the search result.
					switchPage('search1');
					// We retrieve some details about the search result to set page variables.
					searchitemcount = $('#content #searchresult').attr('itemcount');
					searchpagelength = $('#content #searchresult').attr('pagelength');
					searchpagecount = Math.ceil(searchitemcount / searchpagelength);
					if (searchitemcount%searchpagelength == 0) {searchpagecount--}
					if (searchpagecount < 1) {searchpagecount=1}
	
					// Load the paginator with the page variables for the search.
					loadSearchPaginator(1, searchpagecount, _searchfield, _searchstring);
				
					// Load the next pages of the search.
					loadNextSearchPages(1, searchpagecount, _searchfield, _searchstring);
				});
			
		//}, 500 );	// 500ms should be enough delay.
		}
	});	
	
	$( "#search-container #search-button" ).click(function() {
		
		  $( "#search-container input#searchtext" ).keyup();
		});
	
}

$(document).ready(function(){
	
	// Calls function to initialize click events and buttons.
	listInitialize();
	
	// Variables needed.
	var pagelength = $('table.tuning').attr('pagelength');
	var itemcount = $('table.tuning').attr('itemcount');
	pagecount =  Math.ceil(itemcount / pagelength);
	if (itemcount%pagelength == 0) pagecount--; // If the mod is zero, there are no new items in the last page.
	if (pagecount == 0) pagecount++;
	// We get a hash value if there is one.
	
	var hash = parseInt(window.location.hash.slice(1));
	
	// If theres a hashvalue and its not the first page.
	if (hash && hash != 1) {
		// We obviously want another page.
		var currentpage = hash;
	
		$.when(getPage(currentpage)).done(function(){switchPage(currentpage)});
		// Preload the first set of pages.
		loadNextPages(currentpage, pagecount);
	}
	else {
		var currentpage = 1;
		// Preload the first set of pages.
		loadNextPages(currentpage, pagecount);
	}
	
	// Preload the last page, but not if the hash points to the last page.
	if (hash != pagecount && pagecount > 1) {
		getPage(pagecount);
	}
	
	// Load the paginator.
	loadPaginator(currentpage, pagecount);
	
	// Initialize the search field above content.
	searchField();

});
