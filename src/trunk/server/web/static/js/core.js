// Make the manipulator follow you when you scroll.
function animateManipulator() {
	
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
	        el.stop().animate({'top':finaldestination-elpos_original},500);
	    }
	});
	
}

// Make the current page highlighted in nav.
function setCurrentNavigation() {
	
	$('.nav a[href$="'+location.pathname+'"]').parent().toggleClass("active");
	
}

$(document).ready(function(){ 
	
	// Make the current page highlighted in nav.
	setCurrentNavigation();
	
});
