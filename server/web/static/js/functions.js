
$(document).ready(function(){
	$('.list-group li').click(function(event){
		//event.preventDefault();
		$(this).next().toggle("fast","linear");
		//$(this).addClass('selected');	
		//$('#nav li a').addClass('selected');
	
	});
	$('#nav a').click(function(event){
		event.preventDefault();
		$('#nav a').removeClass('selected');
		$(this).addClass('selected');	
		//$('#nav li a').addClass('selected');
	
	});
	
	
	var pagecount = $('#paginator').attr('count');
	var options = {
		currentPage: 1,
		totalPages: pagecount,
		numberOfPages: 3,
		bootstrapMajorVersion: 3
	}

	$('#paginator').bootstrapPaginator(options);
	
	var el = $('#manipulator');
	var elpos_original = el.offset().top;
	$(window).scroll(function(){
	    var elpos = el.offset().top;
	    var windowpos = $(window).scrollTop();
	    var finaldestination = windowpos;
	    if(windowpos<elpos_original) {
	        finaldestination = elpos_original;
	        el.stop().animate({'top':0},500);
	    } else {
	        el.stop().animate({'top':finaldestination-elpos_original+10},500);
	    }
	});
	
});
