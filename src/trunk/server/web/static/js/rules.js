/*
*	Snort Rule Manager - Web Interface
*	rules.js
*	Contains all the specialized javascript used on the /web/rules page.
*
*/

// This function starts all click events within the rule list.
function listInitialize() {
	// Install click event so that when the header checkbox is clicked, all the other checkboxes is checked.
	$('table thead th#checkbox-all input').unbind('click');
	$('table thead th#checkbox-all input').click(function(event){
				
		if ($("table thead th#checkbox-all input").is(':checked')) {
            $("table.current #checkbox").each(function () {
                $(this).prop("checked", true);
            });

        } else {
            $("table.current #checkbox").each(function () {
                $(this).prop("checked", false);
            });
        }
		
	});

	
	// Installs click events on all rows.
	$('table tbody tr.odd').unbind('click');
	$('table tbody tr.odd').click(function(event){
		// This is to make sure a click on the switch doesnt trigger a row open.
		if($(event.target).is('#checkbox')||$(event.target).is('td#checkbox')){
            //event.preventDefault();
            return;
        }
		
		// Toggles clicked row on the 'active' css class so it changes color
		$(this).toggleClass("bg-primary");
		// Shows or hides the next row which is hidden by default.
		$(this).next().toggle();
	
	});

		
}
// This function is used to dynamically retrieve a page that contains a list of rules.
// This function is utilized for the regular list of all rules.
function getPage(pageNr){
	// Copies pagenr to local _pagenr variable.
	var _pageNr = parseInt(pageNr); 
	
	// Ajax-call for the required page. We return it so we can use $.when
	return $.get('page/'+_pageNr+'/', function(html) { 
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

// This function is used to dynamically retrieve a page that contains a list of rules.
// This function is utilized for the search pages.
function getSearchPage(pagenr, searchfield, searchstring){
	// Copies pagenr to local _pagenr variable.
	var _pagenr = parseInt(pagenr); 
	var _searchfield = searchfield;
	var _searchstring = searchstring;
		
	// Ajax-call for the required page. We return it so we can use $.when.
	// We also include the CSRF token so Django can know we are friendly.
	return $.ajax({
		url:'page/search/'+_pagenr+'/',
		type:'POST',
		data: {searchf: _searchfield, searchs: _searchstring, csrfmiddlewaretoken: $('input').attr('name', 'csrfmiddlewaretoken').val()}
		
	}).done(function(html) { 
		// When the content is loaded, append to content container.
		
		$('#content').append(html);
		listInitialize();
		
	});
	
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

// This function is used to dynamically load three pages before and after the current page.
// This function is utilized for the search pages.
function loadNextSearchPages(currentpage, pagecount, searchfield, searchstring) {
	
	// Copy passed variables to local variables.
	var _currentpage = currentpage;
	var _pagecount = pagecount;
	var _searchfield = searchfield;
	var _searchstring = searchstring;
	
	// Loop for -3 and +3 from the current page.
	for(var i=-3;i<=3;i++) {
		// We dont want negative page numbers or 
		// pages outside the actual page range
		if (_currentpage+i > 1 && _currentpage+i < _pagecount && _currentpage+i != _currentpage) {
			// Try to find a page element with this id nr.
			var _pageexists = $('#content .table#search'+(_currentpage+i)+'').length;
			// If the page doesnt exist, we need to load it.
			if (!_pageexists) {
				// Loads the page it didnt find.
				getSearchPage(_currentpage+i, _searchfield, _searchstring);
			}
		}
	}
	
}

// This function is used to switch between pages in the list.
function switchPage(page) {
	$(document).ajaxStop(function(){
		var _page = page;
		// Hide the page marked .current and then turn off its .current class.
		$('#content .current').hide().toggleClass('current');
		// Show the page we want and set it to contain the .current class. Select first in case ajax hickups and produces two.
		$('#content .table#'+_page).show().toggleClass('current');
	});
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
				
				originalEvent.preventDefault();
				// Load the next pages.
				loadNextPages(page, pagecount);
				// Hide the page we no longer want and show the one we want.
				switchPage(page);
				window.location.hash = page;
			}
	}
	
	// Start the paginator.
	$('#paginator').bootstrapPaginator(options);
	
}

// This function loads the paginator used when a search is done.
function loadSearchPaginator(currentpage, pagecount, _searchfield, _searchstring) {
	
	// We set some options for the paginator and its click function.
	var options = {
			currentPage: currentpage,
			totalPages: pagecount,
			numberOfPages: 3,
			bootstrapMajorVersion: 3,
			onPageClicked: function(e,originalEvent,type,page){
				originalEvent.preventDefault();
				// Hide the page we no longer want and show the one we want.
				switchPage('search'+page);
				
				// Load the next pages.
				loadNextSearchPages(page, pagecount, _searchfield, _searchstring);

			}
	}
	
	// Start the paginator.
	$('#paginator').bootstrapPaginator(options);
	
}

// This function initializes the search field and triggers on keyup.
function searchField() {

	$('#search-container input#searchtext').keyup(function(event){ // This is triggered when someone types in the inputfield.
		console.log(event);
		
		// We get the what we're searching in from the select.
		var _searchfield = $('#search-container select#searchfield').val();

		// This is the string we want to match.
		var _searchstring = $('#search-container input#searchtext').val();
		
		// If the searchstring is empty, user has emptied the field. We want to revert to pre-search state.
		if(!_searchstring) { 
			// Grab the window hash as reference to where we were.
			var hash = parseInt(window.location.hash.slice(1));
			// If theres a hashvalue and its not the first page.
			if (hash && hash != 1) {
				// We obviously want another page.
				var currentpage = hash;
			}
			else {
				var currentpage = 1;
			}
			// We have to find these variables again.
			var pagelength = $('#paginator').attr('pagelength');
			var itemcount = $('#paginator').attr('itemcount');
			pagecount =  Math.floor(itemcount / pagelength);
			if (itemcount%pagecount == 0) pagecount--; // If the mod is zero, there are no new items in the last page.
			if (pagecount == 0) pagecount++;
			// Switch back to the current page.
			switchPage(currentpage);
			// Reload the paginator to its former state.

			loadPaginator(currentpage, pagecount);
			// Remove any searchresult container from the DOM.
			$('#content #searchresult').remove();
		}
		
		if ( event.which == 13 || !event.which ) {
		     
		//delay(function(){	// We add a bit of delay.

				// Remove any previous searches from the DOM.
				$('#content #searchresult').remove();
				// We do an ajax call to retrieve the first page of the search results.
				$.when(getSearchPage(1, _searchfield, _searchstring)).done(function() {
					// Switch the page to the search result.
					switchPage('search1');
					// We retrieve some details about the search result to set page variables.
					searchitemcount = $('#content #searchresult').attr('itemcount');
					searchpagelength = $('#content #searchresult').attr('pagelength');
					searchpagecount = Math.ceil(searchitemcount / searchpagelength);
					if (searchitemcount%searchpagelength == 0) {searchpagecount--}
					if (searchpagecount < 1) {searchpagecount=1}
	
					// Load the paginator with the page variables for the search.
					loadSearchPaginator(1, searchpagecount, _searchfield, _searchstring);
				
					// Load the next pages of the search.
					loadNextSearchPages(1, searchpagecount, _searchfield, _searchstring);
				});
			
		//}, 500 );	// 500ms should be enough delay.
		}
	});	
	
	$( "#search-container button" ).click(function() {
		
		  $( "#search-container input#searchtext" ).keyup();
		});
	
}

$(document).ready(function(){
	
	// Calls function to initialize click events and buttons.
	listInitialize();
	
	// Variables needed.
	var pagelength = $('#paginator').attr('pagelength');
	var itemcount = $('#paginator').attr('itemcount');
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
		loadNextPages(currentpage, pagecount);
	}
	
	// Preload the last page, but not if the hash points to the last page.
	if (hash != pagecount && pagecount > 1) {
		getPage(pagecount);
	}
	
	// Load the paginator.
	loadPaginator(currentpage, pagecount);

	// Make the manipulator follow you when you scroll.
	animateManipulator();
	
	// Initialize the search field above content.
	searchField();

});
