$(document).ready(function(){
	$('#nav a').click(function(event){
		event.preventDefault();
		$('#nav a').removeClass('selected');
		$(this).addClass('selected');	
		//$('#nav li a').addClass('selected');
	
	});
});
