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
}

function initializeNewUserForm() {
	$('button#create').unbind('click');
	$('button#create').click(function(event){
		// Reset this button in the form to default just in case.
		$('button#create-submit').prop("disabled",false);
		$('button#create-submit').attr('class','btn btn-primary');
		$('button#create-submit').html('Save changes');
		
		$.get('/web/users/getCreateUserForm/',function(html){
			
			$('#createUserForm #formContent').html(html);
		});
		
		$('#createUserForm').validate({
			rules: {
				email: {
					email: true
				},
				passwordConfirm: {
					equalTo: 'input#password'
				}
			},
			submitHandler: function(form) {
			    // do other things for a valid form
			    submitCreateUserForm(form);
			  }
			
		});
	});
}

function submitCreateUserForm(form) {
	
	
	// Post the data via AJAX
	$.ajax({
		url: "/web/users/createUser/",
		type: "post",
		dataType: "json",
		data: $(form).serialize(),
		success: function(data) {
			// These are flags that determine the outcome of the response.
			var success, warning, error = false;
			// Clean up any old alerts in the form.
			$('#createUserForm .alert').remove();
			// We might get more than one response, so we iterate over them.
			$.each(data, function() {
				// If the response contains one of these strings, we put the response text near the relevant context and display it. 
				// We also set the outcome flags appropriately so we can handle things differently.
				if(this.response == "userSuccessfullyCreated") {
					
					text = '<div class="alert alert-success row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#createUserForm div#formContent').append(text).prepend(text);
								
					$('#createUserForm div#formContent .alert').show("highlight");
					
					success = true;
				}
				else if(this.response == "userExists") {
					
					$('#createUserForm div#username div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#createUserForm div#username div.col-sm-10 .alert').show("highlight");
					
					error = true;
				}
				else if(this.response == "noName") {
					
					$('#createUserForm div#username div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#createUserForm div#username div.col-sm-10 .alert').show("highlight");
					
					error = true;
				}
				else if(this.response == "noPassword") {
					
					$('#createUserForm div#password div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#createUserForm div#password div.col-sm-10 .alert').show("highlight");
					
					error = true;
				}
				
				else if(this.response == "noPOST") {
					
					text = '<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#createUserForm div#formContent').append(text).prepend(text);
								
					$('#createUserForm div#formContent .alert').show("highlight");
					
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
				
				
				setTimeout(function() {$('#createUserModal').modal('hide')}, 3000);
				setTimeout(function() {location.reload(true)}, 1000);
			
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
}

function initializeResetPasswordForm() {
	$('button#resetPassword').unbind('click');
	$('button#resetPassword').click(function() {
		// Reset this button in the form to default just in case.
		$('button#reset-submit').prop("disabled",false);
		$('button#reset-submit').attr('class','btn btn-primary');
		$('button#reset-submit').html('Save changes');
		$('#resetPasswordForm #formContent').append('<input type="hidden" id="userid" name="userid" value="'+$(this).attr('user')+'">');
		$.get('/web/users/getResetPasswordForm/',function(html){
			
			$('#resetPasswordForm #formContent').append(html);
			
			
		});
		
		$('#resetPasswordForm').validate({
			rules: {
				passwordConfirm: {
					equalTo: 'input#password'
				}
			},
			submitHandler: function(form) {
			    // do other things for a valid form
			    submitResetPasswordForm(form);
			  }
			
		});
	});
}

function submitResetPasswordForm(form) {
	
	// Post the data via AJAX
	$.ajax({
		url: "/web/users/resetPassword/",
		type: "post",
		dataType: "json",
		data: $(form).serialize(),
		success: function(data) {
			// These are flags that determine the outcome of the response.
			var success, warning, error = false;
			// Clean up any old alerts in the form.
			$('#resetPasswordForm .alert').remove();
			// We might get more than one response, so we iterate over them.
			$.each(data, function() {
				// If the response contains one of these strings, we put the response text near the relevant context and display it. 
				// We also set the outcome flags appropriately so we can handle things differently.
				if(this.response == "passwordReset") {
					
					text = '<div class="alert alert-success row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#resetPasswordForm div#formContent').append(text).prepend(text);
								
					$('#resetPasswordForm div#formContent .alert').show("highlight");
					
					success = true;
				}
				else if(this.response == "userDoesNotExists") {
					
					text = '<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#resetPasswordForm div#formContent').append(text).prepend(text);
								
					$('#resetPasswordForm div#formContent .alert').show("highlight");
					
					error = true;
				}
				else if(this.response == "noPassword") {
					
					$('#createUserForm div#password div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#createUserForm div#password div.col-sm-10 .alert').show("highlight");
					
					error = true;
				}
				else if(this.response == "noPOST") {
					
					text = '<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#resetPasswordForm div#formContent').append(text).prepend(text);
								
					$('#resetPasswordForm div#formContent .alert').show("highlight");
					
					error = true;
				}
			});
			// If the success-flag was set to true, everything went ok and we can show the user this outcome and close the modal.
			if( success ) {
				
				
				$('button#reset-submit').hide();
				$('button#reset-submit').prop("disabled",true);
				$('button#reset-submit').attr('class','btn btn-success');
				$('button#reset-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
				$('button#reset-submit').show("highlight");
				
				
				setTimeout(function() {$('#resetPasswordModal').modal('hide')}, 3000);
				setTimeout(function() {location.reload(true)}, 1000);
			
			}
			// If the outcome was not a success, we have to show this to the user.
			else if( warning || error ) {
				// If there was an error, we dont force a DB commit next time. The user has to fix the problem and recheck.
				if (error) {
					
					$('button#reset-submit').attr('class','btn btn-danger');
					$('button#reset-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
				}
				// If there is only a warning, we force a DB commit next time, but we warn the user of some things first, just in case.
				else {
					
					$('button#reset-submit').attr('class','btn btn-warning');
					$('button#reset-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
				}
			}
		}
	});
	
}

function initializeDeleteUserForm() {
	$('button#delete').unbind('click');
	$('button#delete').click(function() {
	var _users = $('#checkbox:checked[user]');
		
		// We only load the form if something was selected.
		if (_users.length > 0) {
			$(_users).each(function(){
				if ($(this).attr('user') != $(this).attr('loginuser')) {
					$('#deleteUserForm #formContent').prepend('<input type="hidden" id="userid" name="userid" value="'+$(this).attr('user')+'">');
				}
			});
		}
		// Else we just hide the modal again.
		else {
			setTimeout(function() {$('#deleteUserModal').modal('hide')}, 1);
		}
	});
	$('#deleteUserForm').unbind('submit');
	$('#deleteUserForm').submit(function(event){
		// Remove the default actions from the post-button.
		event.preventDefault();
		// Post the data via AJAX
		$.ajax({
			url: "/web/users/deleteUser/",
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
					if(this.response == "userSuccessfulDeletion") {
						
						text = '<div class="alert alert-success row" style="display: none;">\
							<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
							<div class="col-sm-11">'+this.text+'</div></div>'
						$('#deleteUserForm div#formContent').append(text).prepend(text);
								
						$('#deleteUserForm div#formContent .alert').show("highlight");
						
						success = true;
					}
					else if(this.response == "userDoesNotExist") {
						
						text = '<div class="alert alert-danger row" style="display: none;">\
							<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
							<div class="col-sm-11">'+this.text+'</div></div>'
						$('#deleteUserForm div#formContent').append(text).prepend(text);
								
						$('#deleteUserForm div#formContent .alert').show("highlight");
						
						error = true;
					}
					else if(this.response == "noIDsGiven") {
						
						text = '<div class="alert alert-success row" style="display: none;">\
							<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
							<div class="col-sm-11">'+this.text+'</div></div>'
						$('#deleteUserForm div#formContent').append(text).prepend(text);
								
						$('#deleteUserForm div#formContent .alert').show("highlight");
						
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
					
					
					setTimeout(function() {$('#deleteUserModal').modal('hide')}, 3000);
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

//When the documents is finished loading, initialize everything.
$(document).ready(function(){
	initializeClicks();
	initializeNewUserForm();
	initializeResetPasswordForm();
	initializeDeleteUserForm();
	
	animateManipulator();
	
	
	
});