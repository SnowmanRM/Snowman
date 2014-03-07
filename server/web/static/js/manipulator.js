
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
		    
		  }
		
	});
	$('#suppressForm').submit(function(event) {
		event.preventDefault();
		console.log(event);
		
	});
	
	function submitThresholdForm(event) {
		
		$.ajax({
			url: "/web/tuning/setThresholdOnRule",
			type: "post",
			dataType: "json",
			data: $(event).serialize(),
			success: function(data) {
				var button;
				
				$.each(data, function() {
					
					if(this.response == "thresholdAdded") {
						$('#thresholdForm .alert').remove();
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
				});
				
				if( button == "success" ) {
					
					
					$('#thresholdForm input#force').val('False');
					$('button#threshold-submit').hide();
					$('button#threshold-submit').prop("disabled",true);
					$('button#threshold-submit').attr('class','btn btn-success');
					$('button#threshold-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
					$('button#threshold-submit').show("highlight");
					
					setTimeout(function() {$('#thresholdFormModal').modal('hide')}, 3000);
					
					
				}
				if( button == "warning" ) {
					
					$('#thresholdForm input#force').val('True');
					$('button#threshold-submit').attr('class','btn btn-warning');
					$('button#threshold-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
					
				}
			}
			
			
		});
		
	};
});