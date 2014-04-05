function getUrlParameter(sParam)
{
    var sPageURL = window.location.search.substring(1);
    var sURLVariables = sPageURL.split('&');
    for (var i = 0; i < sURLVariables.length; i++) 
    {
        var sParameterName = sURLVariables[i].split('=');
        if (sParameterName[0] == sParam) 
        {
            return sParameterName[1];
        }
    }
}

$(document).ready(function(){
	
	$('#loginForm').submit(function(event){
		event.preventDefault();
		$('#loginForm .alert').remove();
		$.ajax({
			url:'/web/login/authenticate/',
			dataType: "json",
			data: $(this).serialize(),
			type: "post",
			success: function(data){
		
				if (data[0].response == "loginSuccess") {
					
					
					$('button').prop("disabled",true);
					$('button').attr('class','btn btn-success');
					$('button').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
					$('button').effect("highlight");
					setTimeout(function() {location.assign(getUrlParameter('next'))}, 1000);
					
					
				}
				else if (data[0].response == "userDoesNotExist") {
					$('#loginForm div#username div').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-9">'+data[0].text+'</div></div>');
					
					$('#loginForm div#username div .alert').show("highlight");
				}
				else if (data[0].response == "inactiveUser") {
					$('#loginForm div#username div').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-9">'+data[0].text+'</div></div>');
					
					$('#loginForm div#username div .alert').show("highlight");
				}
				else if (data[0].response == "invalidPassword") {
					$('#loginForm div#password div').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-9">'+data[0].text+'</div></div>');
					
					$('#loginForm div#password div .alert').show("highlight");
				}
			}
		
		});
	});
	
});