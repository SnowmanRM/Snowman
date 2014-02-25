// Initializes the collapsable lists on the page.
function listInitialize() {
	// Installs click events on all rows.
	$('li.odd').unbind('click');
	$('li.odd').click(function(event){
		// Toggles clicked row on the 'active' css class so it changes color
		$(this).toggleClass("active");
		// Shows or hides the next row which is hidden by default.
		$(this).next().slideToggle("fast","linear");
	});
}

$(document).ready(function(){
	listInitialize();
});
