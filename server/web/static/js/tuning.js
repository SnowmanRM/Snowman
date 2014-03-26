
function listInitialize() {
	
}

// This function is used to dynamically retrieve a page that contains a list of rules.
// This function is utilized for the regular list of all rules.
function getPage(pageNr){
	// Copies pagenr to local _pagenr variable.
	var _pageNr = parseInt(pageNr); 
	
	// Ajax-call for the required page. We return it so we can use $.when
	return $.get('/web/tuning/byRule/page/'+_pageNr+'/', function(html) { 
		downloadId = $('table', $('<div/>').html(html)).attr("id");
		pageAlreadyExists = $('#content table[id="'+downloadId+'"]');

		if( pageAlreadyExists.length ) {

			$('#content [id="'+downloadId+'"]').replaceWith(html);
			
		}
		else {
	
			// When the content is loaded, append to content container.
			$('#content').append(html);
			
		}
		
		
		// We need to reinitialize all the click events and switchbuttons.
		listInitialize();

	})
	
}

// This function is used to dynamically load three pages before and after the current page.
// This function is utilized for the regular list of all rules.
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

// This function is used to switch between pages in the list.
function switchPage(page) {
	
	var _page = page;
	// Hide the page marked .current and then turn off its .current class.
	$('#content .current').hide().toggleClass('current');
	// Show the page we want and set it to contain the .current class. Select first in case ajax hickups and produces two.
	$('#content .table#'+_page).show().toggleClass('current');
	
	
}

// This function loads the paginator used when displaying a full list of all rules.
function loadPaginator(currentpage, pagecount) {
	
	// We set some options for the paginator and its click function.
	var options = {
			currentPage: currentpage,
			totalPages: pagecount,
			numberOfPages: 3,
			bootstrapMajorVersion: 3,
			onPageClicked: function(e,originalEvent,type,page){
				
				
				// Load the next pages.
				loadNextPages(page, pagecount);
				// Hide the page we no longer want and show the one we want.
				switchPage(page);
				// We update the window location hash value.
				window.location.hash = page;
			}
	}
	
	// Start the paginator.
	$('#paginator').bootstrapPaginator(options);
	
}

$(document).ready(function(){
	
	// Calls function to initialize click events and buttons.
	//listInitialize();
	
	// Variables needed.
	var pagelength = $('table.tuning').attr('pagelength');
	var itemcount = $('table.tuning').attr('itemcount');
	pagecount =  Math.ceil(itemcount / pagelength);
	if (itemcount%pagelength == 0) pagecount--; // If the mod is zero, there are no new items in the last page.
	if (pagecount == 0) pagecount++;
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
		//loadNextPages(currentpage, pagecount);
	}
	
	// Preload the last page, but not if the hash points to the last page.
	if (hash != pagecount && pagecount > 1) {
		getPage(pagecount);
	}
	
	// Load the paginator.
	loadPaginator(currentpage, pagecount);

	// Make the manipulator follow you when you scroll.
	//animateManipulator();
	
	// Initialize the search field above content.
	//searchField();

});
