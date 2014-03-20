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

function selectRemembers(element) {
	// Makes multiple select inputs remember selections.
	$(element).each(function(){    
	    var select = $(this), values = {};    
	    $('option',select).each(function(i, option){
	        values[option.value] = option.selected;        
	    }).click(function(event){        
	        values[this.value] = !values[this.value];
	        $('option',select).each(function(i, option){            
	            option.selected = values[option.value];        
	        });    
	    });
	});
}

//This function adds a delay to an event trigger.
var delay = (function(){
	var timer = 0;
  return function(callback, ms){
	  clearTimeout (timer);
    timer = setTimeout(callback, ms);
  };
})();

$(document).ready(function(){ 
	
	// Make the current page highlighted in nav.
	setCurrentNavigation();
	

	
});
