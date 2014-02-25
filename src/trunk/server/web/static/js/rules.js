function listInitialize() {
	
	// Initializes the switchbuttons
	$(".ruleswitch").bootstrapSwitch()
	
	// Installs click events on all rows.
	$('table tbody tr.odd').unbind('click');
	$('table tbody tr.odd').click(function(event){
		// This is to make sure a click on the switch doesnt trigger a row open.
		if($(event.target).is('.bootstrap-switch span')){
            event.preventDefault();
            return false;
        }
		
		// Toggles clicked row on the 'active' css class so it changes color
		$(this).toggleClass("active");
		// Shows or hides the next row which is hidden by default.
		$(this).next().slideToggle("fast","linear");
	
	});
		
}

function getPage(pagenr){
	// Copies pagenr to local _pagenr variable.
	var _pagenr = parseInt(pagenr); 
	
	// Ajax-calls for the required page. We return it so we can use $.when
	return $.get('page/'+_pagenr+'/', function(html) { 
		// When the content is loaded, append to content container.
		$('#content').append(html);
		// We need to reinitialize all the click events and switchbuttons.
		listInitialize();

	})
	
}

function loadNextPages(currentpage, pagecount) {
	
	// Copy passed variables to local variables.
	var _currentpage = currentpage;
	var _pagecount = pagecount;
	
	// Loop for -3 and +3 from the current page.
	for(var i=-3;i<=3;i++) {
		// We dont want negative page numbers or 
		// pages outside the actual page range
		if (_currentpage+i > 1 && _currentpage+i < _pagecount && _currentpage+i != _currentpage) {
			// Try to find a page element with this id nr.
			var _pageexists = $('#content .table#'+(_currentpage+i)+'').length;
			// If the page doesnt exist, we need to load it.
			if (!_pageexists) {
				// Loads the page it didnt find.
				getPage(_currentpage+i);
			}
		}
	}
	
}

function switchPage(page) {
	
	var _page = page;
	
	$('#content .current').hide().toggleClass('current');
	$('#content .table#'+_page).show().toggleClass('current');
	
	
}

function loadPaginator(currentpage, pagecount) {
	
	// We set some options for the paginator and its click function.
	var options = {
			currentPage: currentpage,
			totalPages: pagecount,
			numberOfPages: 3,
			bootstrapMajorVersion: 3,
			onPageClicked: function(e,originalEvent,type,page){
				// Hide the page we no longer want and show the one we want.
				switchPage(page);
				
				// Load the next pages.
				loadNextPages(page, pagecount);
				// We update the window location hash value.
				window.location.hash = page;
			}
	}
	
	// Start the paginator.
	$('#paginator').bootstrapPaginator(options);
	
}

$(document).ready(function(){

	// Calls function to initialize click events and buttons.
	listInitialize();
	
	// Variables needed.
	var pagelength = $('#paginator').attr('pagelength');
	var itemcount = $('#paginator').attr('itemcount');
	var pagecount =  Math.floor(itemcount / pagelength);
	if (itemcount%pagecount == 0) pagecount--; // If the mod is zero, there are no new items in the last page.
	
	// We get a hash value if there is one.
	var hash = parseInt(window.location.hash.slice(1));
	
	// If theres a hashvalue and its not the first page.
	if (hash && hash != 1) {
		// We obviously want another page.
		var currentpage = hash;
	
		$.when(getPage(currentpage)).done(function(){switchPage(currentpage)});
		// Preload the first set of pages.
		loadNextPages(currentpage, pagecount);
	}
	else {
		var currentpage = 1;
		// Preload the first set of pages.
		loadNextPages(currentpage, pagecount);
	}
	
	// Preload the last page, but not if the hash points to the last page.
	if (hash != pagecount) {
		getPage(pagecount);
	}
	
	// Load the paginator.
	loadPaginator(currentpage, pagecount);

	// Make the manipulator follow you when you scroll.
	animateManipulator();
	
});
