
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
			else if (sids.length == 0) {
				$('#thresholdFormModal #formContent select#sid').replaceWith('<input type="text" class="form-control" id="sid">');
				$('#thresholdFormModal #formContent').prepend('<input type="hidden" id="id" name="id" value="'+$(sids).attr('id')+'">');
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
			else if (sids.length == 0) {
				$('#suppressFormModal #formContent select#sid').replaceWith('<input type="text" class="form-control" id="sid">');
				$('#suppressFormModal #formContent').prepend('<input type="hidden" id="id" name="id" value="'+$(sids).attr('id')+'">');
				
			}
		});
	});

}

$(document).ready(function(){ 
	
	initializeButtons();
	
	$('thresholdForm').validate({
		submitHandler: function(form) {
			form.submit();
		  }
		
	});
	$('suppressForm').validate({
		submitHandler: function(form) {
		    form.submit();
		  }
		
	});
	$('#thresholdForm').submit(function(event) {
		event.preventDefault();
		console.log('click');
		
	});
	$('#suppressForm').submit(function(event) {
		event.preventDefault();
		console.log('click');
		
	});
	
});