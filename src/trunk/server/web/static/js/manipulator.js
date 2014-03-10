/*
 * This javascript contains all the code used for the little button box on the left.
 * 
 */

function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// This function binds all the button clicks in the manipulator.
function initializeButtons() {
	
	$('#manipulator button#enable').click(function(event){

		// Get all selected rules and put their SIDs in a list:
		sids=$('#checkbox input:checked');
		if (sids.length > 0) {
			sidlist = [];
			$(sids).each(function(){
				sidlist.push($(this).attr('sid'))
			});
			
			// Call function to enable selected rules
			modifyRule("enable", sidlist);	
		}
	});
	
	$('#manipulator button#disable').click(function(event){

		// Get all selected rules and put their SIDs in a list:
		sids=$('#checkbox input:checked');
		if (sids.length > 0) {
			sidlist = [];
			$(sids).each(function(){
				sidlist.push($(this).attr('sid'))
			});
			
			// Call function to disable selected rules
			modifyRule("disable", sidlist);	
		}
	});	
	
	
	$('#manipulator button#threshold').click(function(event){
		// Load the form with AJAX.
		$.get('/web/tuning/getThresholdForm', function(html){
			// Put the form content into the container.
			$('#thresholdFormModal #formContent').html(html);
			// Get all checked checkboxes.
			sids=$('#checkbox input:checked');
			// If there are checkboxes checked, we need to do some extra stuff.
			if (sids.length > 0) {
				// We replace the input with a disabled select that displays the checked rules.
				$('#thresholdFormModal #formContent input#sid').replaceWith('<select multiple class="form-control" id="sid" name="sid" disabled></select>');
				// For each checked rule, we add them to the select list.
				$(sids).each(function(){
					$('#thresholdFormModal #formContent').prepend('<input type="hidden" id="id" name="id" value="'+$(this).attr('id')+'">');
					$('#thresholdFormModal #formContent select#sid').append('<option>'+$(this).attr('gid')+':'+$(this).attr('sid')+'|'+$(this).attr('status')+'</option>');
				});
			}
			
			// Reset this button in the form to default just in case.
			$('button#threshold-submit').prop("disabled",false);
			$('button#threshold-submit').attr('class','btn btn-primary');
			$('button#threshold-submit').html('Save changes');
			
		
		});
			
		
	});
	
	$('#manipulator button#suppress').click(function(event){
		// Load the form with AJAX.
		$.get('/web/tuning/getSuppressForm', function(html){
			// Put the form content into the container.
			$('#suppressFormModal #formContent').html(html);
			// Get all checked checkboxes.
			sids=$('#checkbox input:checked');
			// If there are checkboxes checked, we need to do some extra stuff.
			if (sids.length > 0) {
				// We replace the input with a disabled select that displays the checked rules.
				$('#suppressFormModal #formContent input#sid').replaceWith('<select multiple class="form-control" id="sid" name="sid" disabled></select>');
				// For each checked rule, we add them to the select list.
				$(sids).each(function(){
					
					$('#suppressFormModal #formContent').prepend('<input type="hidden" id="id" name="id" value="'+$(this).attr('id')+'">');
					$('#suppressFormModal #formContent select#sid').append('<option>'+$(this).attr('gid')+':'+$(this).attr('sid')+'|'+$(this).attr('status')+'</option>');
				});
			}
			// Reset this button in the form to default just in case.
			$('button#suppress-submit').prop("disabled",false);
			$('button#suppress-submit').attr('class','btn btn-primary');
			$('button#suppress-submit').html('Save changes');
			
		});
	});

}

/**
 * Function for turning a rule on or off globally.
 * Sends and AJAX request to the enableRule function
 * with a list of SIDs and a mode argument.
 *
 * mode = enable|disable
 * sidList = a plain list of strings representing SIDs
 */
function modifyRule(mode, sidList){

	// Get token and put it in the request header:
	var csrftoken = getCookie('csrftoken');	
	
	$.ajaxSetup({
	    beforeSend: function(xhr, settings) {
	            xhr.setRequestHeader("X-CSRFToken", csrftoken);
	    }
	});			
	
	// Execute the AJAX-request to modify rules in sidList:
	$.ajax({
		url: "/web/tuning/modifyRule",
		type: "post",
		dataType: "json",
		data: {mode: JSON.stringify(mode), sids: JSON.stringify(sidList)},
		success: function(data) {
			console.log("Modify rules "+sidlist+". Mode: "+mode);
		}
	});
}


// This function handles submitting threshold forms and parsing the response.
function submitThresholdForm(event) {
	
	// We send the form serialized to the server.
	$.ajax({
		url: "/web/tuning/setThresholdOnRule",
		type: "post",
		dataType: "json",
		data: $(event).serialize(),
		success: function(data) {
			// These are flags that determine the outcome of the response.
			var success, warning, error = false;
			// Clean up any old alerts in the form.
			$('#thresholdForm .alert').remove();
			// We might get more than one response, so we iterate over them.
			$.each(data, function() {
				// If the response contains one of these strings, we put the response text near the relevant context and display it. 
				// We also set the outcome flags appropriately so we can handle things differently.
				if(this.response == "thresholdAdded") {
					
					text = '<div class="alert alert-success row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#thresholdForm div#formContent').append(text).prepend(text);
							
					$('#thresholdForm div#formContent .alert').show("highlight");
					
					success = true;
				}
				else if(this.response == "thresholdExists") {
					
					$('#thresholdForm div#sid div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'<br />SIDs: '+this.sids+'</div></div>');
					
					$('#thresholdForm div#sid div.col-sm-10 .alert').show("highlight");
					
					warning = true;
				}
				else if(this.response == "allSensors") {
					
					$('#thresholdForm div#sensors div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#thresholdForm div#sensors div.col-sm-10 .alert').show("highlight");
					
					warning = true;
				}
				else if(this.response == "noComment") {
					
					$('#thresholdForm div#comment div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#thresholdForm div#comment div.col-sm-10 .alert').show("highlight");

					warning = true;
				}
				else if (this.response == "invalidGIDSIDFormat") {
					
					$('#thresholdForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#thresholdForm div#sid div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "gidDoesNotExist") {
					
					$('#thresholdForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#thresholdForm div#sid div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "sidDoesNotExist") {
					
					$('#thresholdForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#thresholdForm div#sid div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "sensorDoesNotExist") {
					
					$('#thresholdForm div#sensors div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#thresholdForm div#sensors div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "ruleDoesNotExist") {
					
					$('#thresholdForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#thresholdForm div#sid div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "typeOutOfRange") {
					
					$('#thresholdForm div#type div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#thresholdForm div#type div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if (this.response == "trackOutOfRange") {
					
					$('#thresholdForm div#type div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#thresholdForm div#type div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if(this.response == "addThresholdFailure") {
					
					$('#thresholdForm input#force').val('False');
					text = '<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-danger form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>'
					$('#thresholdForm div#formContent').append(text).prepend(text);
							
					$('#thresholdForm div#formContent .alert').show("highlight");
					
					error = true;
				}
				
				
			});
			
			// If the success-flag was set to true, everything went ok and we can show the user this outcome and close the modal.
			if( success ) {
				
				
				$('#thresholdForm input#force').val('False');
				$('button#threshold-submit').hide();
				$('button#threshold-submit').prop("disabled",true);
				$('button#threshold-submit').attr('class','btn btn-success');
				$('button#threshold-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
				$('button#threshold-submit').show("highlight");
				
				setTimeout(function() {$('#thresholdFormModal').modal('hide')}, 3000);
				setTimeout(function() {location.reload(true)}, 1000);
				
			}
			// If the outcome was not a success, we have to show this to the user.
			else if( warning || error ) {
				// If there was an error, we dont force a DB commit next time. The user has to fix the problem and recheck.
				if (error) {
					$('#thresholdForm input#force').val('False');
					$('button#threshold-submit').attr('class','btn btn-danger');
					$('button#threshold-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
				}
				// If there is only a warning, we force a DB commit next time, but we warn the user of some things first, just in case.
				else {
					$('#thresholdForm input#force').val('True');
					$('button#threshold-submit').attr('class','btn btn-warning');
					$('button#threshold-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
				}
			}
		}
		
		
	});
	
};

//This function handles submitting threshold forms and parsing the response.
function submitSuppressForm(event) {
	
	// We send the form serialized to the server.
	$.ajax({
		url: "/web/tuning/setSuppressOnRule",
		type: "post",
		dataType: "json",
		data: $(event).serialize(),
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

$(document).ready(function(){ 
	
	// We initialize the buttons so that they respond to clicks.
	initializeButtons();
	
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
	
	// Install validators on a few of the form fields and set up the submit handler.
	$('#suppressForm').validate({
		submitHandler: function(form) {
			
			submitSuppressForm(form);
		}
		
	});
			
});