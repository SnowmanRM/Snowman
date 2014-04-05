/*
 * This javascript contains all the code used for the little button box on the left.
 * 
 */

// This function binds all the button clicks in the manipulator.
function initializeButtons() {
	
	$('#manipulator button#enable').unbind('click');
	$('#manipulator button#enable').click(function(event){
		// Reset this button in the form to default just in case.
		$('button#modify-submit').prop("disabled",false);
		$('button#modify-submit').attr('class','btn btn-primary');
		$('button#modify-submit').html('Save changes');
		
		// Get all selected rules and put their SIDs in a list:
		sids=$('#checkbox:checked');
	
		if (sids.length > 0) {
			sidlist = [];
			setlist = [];
			setnames = [];
			// For each of them.
			$(sids).each(function(){
				// You can select both rules and rulesets at the same time, so we differentiate.
				if($(this).is('[sid]')) {
					sidlist.push($(this).attr('sid'));
				}
				else if ($(this).is('[ruleset]')) {
					setlist.push($(this).attr('ruleset'));
					setnames.push($(this).attr('rulesetname'));
				}
			});
			// Grab the CSRF token so Django is happy.
			token = $(this).find('input[name="csrfmiddlewaretoken"]').val();
			// If some rulesets were selected.
			if(setlist.length > 0) {
				// Load the form with AJAX.
				$.get('/web/tuning/getModifyForm/', function(html){
					// Put the form content into the container.
					$('#modifyFormModal #formContent').html(html);
					$('#modifyFormModal #formContent').prepend('<input type="hidden" id="mode" name="mode" value="enable">');
					// For each of the rulesets, put their names into the disabled select list and create a hidden input with their ID.
					$(setlist,setnames).each(function(i){
						$('#modifyFormModal #formContent').prepend('<input type="hidden" id="ruleset" name="ruleset" value="'+setlist[i]+'">');
						$('#modifyFormModal #formContent select#ruleset').append('<option>'+setnames[i]+'</option>');
					});
					
					// If someone checks the global checkbox, we disable the sensor selection.
					$('#modifyForm #global').click(function(event){
						if ($('#modifyForm #global').is(':checked')) {
							$('#modifyForm select#sensors').prop("disabled", true);
				        } else {
				        	$('#modifyForm select#sensors').prop("disabled", false);
				        }
					});
					// We set the submit event for the form.
					$('#modifyForm').submit(function(event) { event.preventDefault(); modifyRuleSet(this) });
					// We show the modal.
					$('#modifyFormModal').modal('show');
					
					
				});
			
			}
			// AND if some rules were selected.
			if (sidlist.length > 0) {
				// Call function to enable selected rules
				modifyRule("enable", sidlist, token);
			}

		}
	});
	$('#manipulator button#disable').unbind('click');
	$('#manipulator button#disable').click(function(event){
		// Reset this button in the form to default just in case.
		$('button#modify-submit').prop("disabled",false);
		$('button#modify-submit').attr('class','btn btn-primary');
		$('button#modify-submit').html('Save changes');
		// Get all selected rules and put their SIDs in a list:
		sids=$('#checkbox:checked');

		if (sids.length > 0) {
			sidlist = [];
			setlist = [];
			setnames = [];
			// For each of them.
			$(sids).each(function(){
				// You can select both rules and rulesets at the same time, so we differentiate.
				if($(this).is('[sid]')) {
					sidlist.push($(this).attr('sid'));
				}
				else if ($(this).is('[ruleset]')) {
					setlist.push($(this).attr('ruleset'));
					setnames.push($(this).attr('rulesetname'));
				}
			});
			// Grab the CSRF token so Django is happy.
			token = $(this).find('input[name="csrfmiddlewaretoken"]').val();
			// If some rulesets were selected.
			if(setlist.length > 0) {
				// Load the form with AJAX.
				$.get('/web/tuning/getModifyForm/', function(html){
					// Put the form content into the container.
					$('#modifyFormModal #formContent').html(html);
					$('#modifyFormModal #formContent').prepend('<input type="hidden" id="mode" name="mode" value="disable">');
					// For each of the rulesets, put their names into the disabled select list and create a hidden input with their ID.
					$(setlist,setnames).each(function(i){
						$('#modifyFormModal #formContent').prepend('<input type="hidden" id="ruleset" name="ruleset" value="'+setlist[i]+'">');
						$('#modifyFormModal #formContent select#ruleset').append('<option>'+setnames[i]+'</option>');
					});
					
					// If someone checks the global checkbox, we disable the sensor selection.
					$('#modifyForm #global').click(function(event){
						if ($('#modifyForm #global').is(':checked')) {
							$('#modifyForm select#sensors').prop("disabled", true);
				        } else {
				        	$('#modifyForm select#sensors').prop("disabled", false);
				        }
					});
					// We set the submit event for the form.
					$('#modifyForm').submit(function(event) { event.preventDefault(); modifyRuleSet(this) });
					// We show the modal.
					$('#modifyFormModal').modal('show');
					
					
				});
				
			}
			// AND if some rules were selected.
			if (sidlist.length > 0) {
				// Call function to disable selected rules
				modifyRule("disable", sidlist, token);
			}

		}
	});	
	
	$('#manipulator button#filter').unbind('click');
	$('#manipulator button#filter').click(function(event){
		// Get all checked checkboxes.
		sids=$('#checkbox:checked[sid]');
		// If there are checkboxes checked, we need to do some extra stuff.
		if (sids.length > 0) {
			// Load the form with AJAX.
			$.get('/web/tuning/getFilterForm/', function(html){
				// Put the form content into the container.
				$('#filterFormModal #formContent').html(html);
				
				// We replace the input with a disabled select that displays the checked rules.
				$('#filterFormModal #formContent input#sid').replaceWith('<select multiple class="form-control" id="sid" name="sid" disabled></select>');
				// For each checked rule, we add them to the select list.
				$(sids).each(function(){
					$('#filterFormModal #formContent').prepend('<input type="hidden" id="id" name="id" value="'+$(this).attr('rid')+'">');
					$('#filterFormModal #formContent select#sid').append('<option>'+$(this).attr('gid')+':'+$(this).attr('sid')+'|'+$(this).attr('status')+'</option>');
					$('#filterFormModal #formContent #filter input[name="filterType"]').click(function(event){
						// We disable the type selector if its a detectionFilter.
						if ($(this).attr('value') == 'eventFilter') {
							$('#filterFormModal #formContent #type select').prop("disabled", false);
						}
						else if ($(this).attr('value') == 'detectionFilter') {
							$('#filterFormModal #formContent #type select').prop("disabled", true);
						}
					});
				});
				
				
				// Reset this button in the form to default just in case.
				$('button#filter-submit').prop("disabled",false);
				$('button#filter-submit').attr('class','btn btn-primary');
				$('button#filter-submit').html('Save changes');
			});
		}
		else {
			setTimeout(function() {$('#filterFormModal').modal('hide')}, 1);
		}
			
		
	});
	$('#manipulator button#suppress').unbind('click');
	$('#manipulator button#suppress').click(function(event){
		// Get all checked checkboxes.
		sids=$('#checkbox:checked[sid]');
		// If there are checkboxes checked, we need to do some extra stuff.
		if (sids.length > 0) {
			// Load the form with AJAX.
			$.get('/web/tuning/getSuppressForm/', function(html){
				// Put the form content into the container.
				$('#suppressFormModal #formContent').html(html);
				
				// We replace the input with a disabled select that displays the checked rules.
				$('#suppressFormModal #formContent input#sid').replaceWith('<select multiple class="form-control" id="sid" name="sid" disabled></select>');
				// For each checked rule, we add them to the select list.
				$(sids).each(function(){
					
					$('#suppressFormModal #formContent').prepend('<input type="hidden" id="id" name="id" value="'+$(this).attr('rid')+'">');
					$('#suppressFormModal #formContent select#sid').append('<option>'+$(this).attr('gid')+':'+$(this).attr('sid')+'|'+$(this).attr('status')+'</option>');
				});
				
				// Reset this button in the form to default just in case.
				$('button#suppress-submit').prop("disabled",false);
				$('button#suppress-submit').attr('class','btn btn-primary');
				$('button#suppress-submit').html('Save changes');
				
			});
		}
		else {
			setTimeout(function() {$('#suppressFormModal').modal('hide')}, 1);
		}
	});

}
function modifyRuleSet(form){

	// Execute the AJAX-request to modify rules in sidList:
	$.ajax({
		url: "/web/tuning/modifyRule/",
		type: "post",
		dataType: "json",
		data: $(form).serialize(),
		success: function(data) {
			// These are flags that determine the outcome of the response.
			var success, warning, error = false;
			var alertstring = [];
			// Clean up any old alerts in the form.
			$('#modifyForm .alert').remove();
			// We might get more than one response, so we iterate over them.
			$.each(data, function() {
				// If the response contains one of these strings, we put the response text near the relevant context and display it. 
				// We also set the outcome flags appropriately so we can handle things differently.
				if(this.response == "ruleSetModificationSuccess") {
					$.each(this.sets, function() {
						if(this.mode == "enable"){
							parent = $('.panel .panel-heading #checkbox[ruleset="'+this.set+'"]').prop('checked', false).parent().parent();
							$(parent).find('span#onoff').switchClass('btn-danger', 'btn-success').html('ON');
							$(parent).effect("highlight");
						}
						else {
							parent = $('.panel .panel-heading #checkbox[ruleset="'+this.set+'"]').prop('checked', false).parent().parent();
							$(parent).find('span#onoff').switchClass('btn-success', 'btn-danger').html('OFF');
							$(parent).effect("highlight");
						}
					});
					
					success = true;
				}
				else if(this.response == "invalidMode") {
					alertstring.append(this.text);
							
					error = true;
				}
				else if(this.response == "ruleSetDoesNotExist") {
						
					alertstring.append(this.text);
							
					warning = true;
				}
			});
			if ( success && !warning && !error ) {
				
				//$('button#modify-submit').hide();
				$('button#modify-submit').prop("disabled",true);
				$('button#modify-submit').attr('class','btn btn-success');
				$('button#modify-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
				$('button#modify-submit').effect("highlight");
				
				setTimeout(function() {$('#modifyFormModal').modal('hide')}, 1500);
				
				setTimeout(function() {location.reload(true)}, 500);
			}
			else if( warning || error ) {
			
				alert(alertstring);
				setTimeout(function() {$('#modifyFormModal').modal('hide')}, 1500);
				//setTimeout(function() {location.reload(true)}, 3000);
			}
		}
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
function modifyRule(mode, sidList, token){
/*
	// Get token and put it in the request header:
	var csrftoken = getCookie('csrftoken');	
	
	$.ajaxSetup({
	    beforeSend: function(xhr, settings) {
	            xhr.setRequestHeader("X-CSRFToken", csrftoken);
	    }
	});			
	*/
	// Execute the AJAX-request to modify rules in sidList:
	$.ajax({
		url: "/web/tuning/modifyRule/",
		type: "post",
		dataType: "json",
		data: {mode: mode, sids: JSON.stringify(sidList), csrfmiddlewaretoken: token},
		success: function(data) {
			// These are flags that determine the outcome of the response.
			var success, warning, error = false;
			var alertstring = [];
			// We might get more than one response, so we iterate over them.
			$.each(data, function() {
				// If the response contains one of these strings, we put the response text near the relevant context and display it. 
				// We also set the outcome flags appropriately so we can handle things differently.
				if(this.response == "ruleModificationSuccess") {
					
					$.each(this.sids, function() {
						if(this.mode == "enable"){
							parent = $('table #checkbox[sid="'+this.sid+'"]').prop('checked', false).parent().parent();
							$(parent).find('span#onoff').switchClass('btn-danger', 'btn-success').html('ON');
							$(parent).effect("highlight");
						}
						else {
							parent = $('table #checkbox[sid="'+this.sid+'"]').prop('checked', false).parent().parent();
							$(parent).find('span#onoff').switchClass('btn-success', 'btn-danger').html('OFF');
							$(parent).effect("highlight");
						}
					});
					
					success = true;
				}
				else if(this.response == "invalidMode") {
					alertstring.push(this.text);
							
					error = true;
				}
				else if(this.response == "ruleDoesNotExist") {
						
					alertstring.push(this.text);
							
					warning = true;
				}
			});
			if ( success && !warning && !error ) {
				//setTimeout(function() {location.reload(true)}, 3000);
			}
			else if( warning || error ) {
			
				alert(alertstring);
				//setTimeout(function() {location.reload(true)}, 3000);
			}
		}
	});
}


// This function handles submitting threshold forms and parsing the response.
function submitFilterForm(event) {
	
	// We send the form serialized to the server.
	$.ajax({
		url: "/web/tuning/setFilterOnRule/",
		type: "post",
		dataType: "json",
		data: $(event).serialize(),
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
					
					$('#filterForm div#comment div.col-sm-10 .alert').show("highlight");

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

//This function handles submitting threshold forms and parsing the response.
function submitSuppressForm(event) {
	
	// We send the form serialized to the server.
	$.ajax({
		url: "/web/tuning/setSuppressOnRule/",
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
	$('#filterForm').validate({
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
	
	// Install validators on a few of the form fields and set up the submit handler.
	$('#suppressForm').validate({
		submitHandler: function(form) {
			
			submitSuppressForm(form);
		}
		
	});
			
});