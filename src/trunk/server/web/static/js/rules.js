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
		$(this).toggleClass("bg-primary");
		// Shows or hides the next row which is hidden by default.
		$(this).next().toggle();
	
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

function getSearchPage(pagenr, searchfield, searchstring){
	// Copies pagenr to local _pagenr variable.
	var _pagenr = parseInt(pagenr); 
	var _searchfield = searchfield;
	var _searchstring = searchstring;
	
	// Ajax-calls for the required page. We return it so we can use $.when
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

function loadSearchPaginator(currentpage, pagecount, _searchfield, _searchstring) {
	
	// We set some options for the paginator and its click function.
	var options = {
			currentPage: currentpage,
			totalPages: pagecount,
			numberOfPages: 3,
			bootstrapMajorVersion: 3,
			onPageClicked: function(e,originalEvent,type,page){
				// Hide the page we no longer want and show the one we want.
				switchPage('search'+page);
				
				// Load the next pages.
				loadNextSearchPages(page, pagecount, _searchfield, _searchstring);
				// We update the window location hash value.
				//window.location.hash = page;
			}
	}
	
	// Start the paginator.
	$('#paginator').bootstrapPaginator(options);
	
}

function searchField() {
	
	$('#search-container input#searchtext').keyup(function(){
		var _searchfield = $('#search-container select#searchfield').val();
		var _searchstring = $(this).val();
		if(!_searchstring) { 
			var hash = parseInt(window.location.hash.slice(1));
			// If theres a hashvalue and its not the first page.
			if (hash && hash != 1) {
				// We obviously want another page.
				var currentpage = hash;
			}
			else {
				var currentpage = 1;
			}
			switchPage(currentpage);
			loadPaginator(currentpage, pagecount);
			$('#content #searchresult').remove();
		}
		else {
			$('#content #searchresult').remove();
			$.when(getSearchPage(1, _searchfield, _searchstring)).done(function() {
				switchPage('search1');
				searchitemcount = $('#content #searchresult').attr('itemcount');
				searchpagelength = $('#content #searchresult').attr('pagelength');
				searchpagecount = Math.floor(searchitemcount / searchpagelength);
				if (searchitemcount%searchpagecount == 0) {searchpagecount--}
				if (searchpagecount < 1) {searchpagecount=1}
				console.log(searchpagecount);
				loadSearchPaginator(1, searchpagecount, _searchfield, _searchstring);
				loadNextSearchPages(1, searchpagecount, _searchfield, _searchstring);
			});
		}
	});	
	
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
	
	searchField();

});
