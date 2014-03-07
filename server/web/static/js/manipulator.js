
function initializeButtons() {
	
	$('#manipulator button#threshold').click(function(event){
		// Ajax the form.
		$.get('/web/tuning/getThresholdForm', function(html){

			$('#thresholdFormModal #formContent').html(html);
			
			sids=$('#checkbox input:checked');
			if (sids.length > 0) {
				$('#thresholdFormModal #formContent input#sid').replaceWith('<select multiple class="form-control" id="sid" name="sid" disabled></select>');
				$(sids).each(function(){
					$('#thresholdFormModal #formContent').prepend('<input type="hidden" id="id" name="id" value="'+$(this).attr('id')+'">');
					$('#thresholdFormModal #formContent select#sid').append('<option>'+$(this).attr('gid')+':'+$(this).attr('sid')+'|'+$(this).attr('status')+'</option>');
				});
			}
			$('button#threshold-submit').prop("disabled",false);
			$('button#threshold-submit').attr('class','btn btn-primary');
			$('button#threshold-submit').html('Save changes');
			
		
		});
			
		
	});
	
	$('#manipulator button#suppress').click(function(event){
		
		$.get('/web/tuning/getSuppressForm', function(html){

			$('#suppressFormModal #formContent').html(html);
		
			sids=$('#checkbox input:checked');

			if (sids.length > 0) {
				$('#suppressFormModal #formContent input#sid').replaceWith('<select multiple class="form-control" id="sid" name="sid" disabled></select>');
				$(sids).each(function(){
					
					$('#suppressFormModal #formContent').prepend('<input type="hidden" id="id" name="id" value="'+$(this).attr('id')+'">');
					$('#suppressFormModal #formContent select#sid').append('<option>'+$(this).attr('gid')+':'+$(this).attr('sid')+'|'+$(this).attr('status')+'</option>');
				});
			}
			
			$('button#suppress-submit').prop("disabled",false);
			$('button#suppress-submit').attr('class','btn btn-primary');
			$('button#suppress-submit').html('Save changes');
			
		});
	});

}

$(document).ready(function(){ 
	
	initializeButtons();
	
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
	
	$('#suppressForm').validate({
		submitHandler: function(form) {
			
			submitSuppressForm(form);
		}
		
	});
	
	function submitThresholdForm(event) {
		
		$.ajax({
			url: "/web/tuning/setThresholdOnRule",
			type: "post",
			dataType: "json",
			data: $(event).serialize(),
			success: function(data) {
				var button;
				$('#thresholdForm .alert').remove();
				$.each(data, function() {
					
					if(this.response == "thresholdAdded") {
						
						text = '<div class="alert alert-success row" style="display: none;">\
							<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
							<div class="col-sm-11">'+this.text+'</div></div>'
						$('#thresholdForm div#formContent').append(text).prepend(text);
								
						$('#thresholdForm div#formContent .alert').show("highlight");
						
						button = "success";
					}
					else if(this.response == "thresholdExists") {
						
						$('#thresholdForm div#sid div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'<br />SIDs: '+this.sids+'</div></div>');
						
						$('#thresholdForm div#sid div.col-sm-10 .alert').show("highlight");
						
						button = "warning";
					}
					else if(this.response == "allSensors") {
						
						$('#thresholdForm div#sensors div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
						
						$('#thresholdForm div#sensors div.col-sm-10 .alert').show("highlight");
						
						button = "warning";
					}
					else if(this.response == "noComment") {
						
						$('#thresholdForm div#comment div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
						
						$('#thresholdForm div#comment div.col-sm-10 .alert').show("highlight");

						button = "warning";
					}
					else if (this.response == "invalidGIDSIDFormat") {
						
						$('#thresholdForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#thresholdForm div#sid div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if (this.response == "gidDoesNotExist") {
						
						$('#thresholdForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#thresholdForm div#sid div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if (this.response == "sidDoesNotExist") {
						
						$('#thresholdForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#thresholdForm div#sid div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if (this.response == "sensorDoesNotExist") {
						
						$('#thresholdForm div#sensors div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#thresholdForm div#sensors div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if (this.response == "ruleDoesNotExist") {
						
						$('#thresholdForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#thresholdForm div#sid div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if (this.response == "typeOutOfRange") {
						
						$('#thresholdForm div#type div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#thresholdForm div#type div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if (this.response == "trackOutOfRange") {
						
						$('#thresholdForm div#type div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#thresholdForm div#type div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if(this.response == "addThresholdFailure") {
						
						$('#thresholdForm input#force').val('False');
						text = '<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-danger form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
						$('#thresholdForm div#formContent').append(text).prepend(text);
								
						$('#thresholdForm div#formContent .alert').show("highlight");
						
						button = "error";
					}
					
					
				});
				
				if( button == "success" ) {
					
					
					$('#thresholdForm input#force').val('False');
					$('button#threshold-submit').hide();
					$('button#threshold-submit').prop("disabled",true);
					$('button#threshold-submit').attr('class','btn btn-success');
					$('button#threshold-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
					$('button#threshold-submit').show("highlight");
					
					setTimeout(function() {$('#thresholdFormModal').modal('hide')}, 3000);
					location.reload(true);
					/*
					$('button#threshold-submit').prop("disabled",false);
					$('button#threshold-submit').attr('class','btn btn-primary');
					$('button#threshold-submit').html('Save changes');
					*/
				}
				else if( button == "warning" ) {
					
					$('#thresholdForm input#force').val('True');
					$('button#threshold-submit').attr('class','btn btn-warning');
					$('button#threshold-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
					
				}
				else if( button == "error" ) {
					
					
					$('button#threshold-submit').attr('class','btn btn-danger');
					$('button#threshold-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
					
				}
			}
			
			
		});
		
	};
	function submitSuppressForm(event) {
		
		$.ajax({
			url: "/web/tuning/setSuppressOnRule",
			type: "post",
			dataType: "json",
			data: $(event).serialize(),
			success: function(data) {
				var button;
				$('#suppressForm .alert').remove();
				$.each(data, function() {
					
					if(this.response == "suppressAdded") {
						
						text = '<div class="alert alert-success row" style="display: none;">\
							<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
							<div class="col-sm-11">'+this.text+'</div></div>'
						$('#suppressForm div#formContent').append(text).prepend(text);
								
						$('#suppressForm div#formContent .alert').show("highlight");
						
						button = "success";
					}
					else if(this.response == "suppressExists") {
						
						$('#suppressForm div#sid div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'<br />SIDs: '+this.sids+'</div></div>');
						
						$('#suppressForm div#sid div.col-sm-10 .alert').show("highlight");
						
						button = "warning";
					}
					else if(this.response == "allSensors") {
						
						$('#suppressForm div#sensors div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
						
						$('#suppressForm div#sensors div.col-sm-10 .alert').show("highlight");
						
						button = "warning";
					}
					else if(this.response == "noComment") {
						
						$('#suppressForm div#comment div.col-sm-10').append('<div class="alert alert-warning row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
						
						$('#suppressForm div#comment div.col-sm-10 .alert').show("highlight");

						button = "warning";
					}
					else if (this.response == "invalidGIDSIDFormat") {
						
						$('#suppressForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#suppressForm div#sid div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if (this.response == "gidDoesNotExist") {
						
						$('#suppressForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#suppressForm div#sid div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if (this.response == "sidDoesNotExist") {
						
						$('#suppressForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#suppressForm div#sid div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if (this.response == "sensorDoesNotExist") {
						
						$('#suppressForm div#sensors div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#suppressForm div#sensors div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if (this.response == "ruleDoesNotExist") {
						
						$('#suppressForm div#sid div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#suppressForm div#sid div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if (this.response == "trackOutOfRange") {
						
						$('#suppressForm div#type div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>');
								
						$('#suppressForm div#type div.col-sm-10 .alert').show("highlight");
								
						button = "error";
					}
					else if(this.response == "addSuppressFailure") {
						
						$('#suppressForm input#force').val('False');
						text = '<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-danger form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
						$('#suppressForm div#formContent').append(text).prepend(text);
								
						$('#suppressForm div#formContent .alert').show("highlight");
						
						button = "error";
					}
					
					
				});
				
				if( button == "success" ) {
					
					
					$('#suppressForm input#force').val('False');
					$('button#suppress-submit').hide();
					$('button#suppress-submit').prop("disabled",true);
					$('button#suppress-submit').attr('class','btn btn-success');
					$('button#suppress-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
					$('button#suppress-submit').show("highlight");
					
					setTimeout(function() {$('#suppressFormModal').modal('hide')}, 3000);
					location.reload(true);
					
				}
				else if( button == "warning" ) {
					
					$('#suppressForm input#force').val('True');
					$('button#suppress-submit').attr('class','btn btn-warning');
					$('button#suppress-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
					
				}
				else if( button == "error" ) {
					
					
					$('button#suppress-submit').attr('class','btn btn-danger');
					$('button#suppress-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
					
				}
			}
			
		});
	}
			
});