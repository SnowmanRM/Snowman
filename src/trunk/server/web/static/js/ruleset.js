// This function is used to dynamically load three pages before and after the current page.
// This function is utilized for the regular list of all rules.
function loadNextPages(ruleSet, currentpage, pagecount) {
	
	// Copy passed variables to local variables.
	var _currentpage = currentpage;
	var _pagecount = pagecount;
	var _ruleSet = ruleSet;

	// Loop for -3 and +3 from the current page.
	for(var i=-3;i<=3;i++) {
		// We dont want negative page numbers or 
		// pages outside the actual page range
		if (_currentpage+i > 1 && _currentpage+i < _pagecount && _currentpage+i != _currentpage) {
			
			// Try to find a page element with this id nr.
			var _pageexists = $('#content .ruleset-panel#'+_ruleSet+' #rules .table#'+(_currentpage+i)+'').length;
			// If the page doesnt exist, we need to load it.
			if (!_pageexists) {
				// Loads the page it didnt find.
				getPage(_ruleSet, _currentpage+i);
				
			}
		}
	}
	
}

//This function is used to switch between pages in the list.
function switchPage(ruleSet, page) {
	
	var _page = page;
	var _ruleSet = ruleSet;
	// Hide the page marked .current and then turn off its .current class.
	$('#content .ruleset-panel#'+_ruleSet+' #rules .current').hide().toggleClass('current');
	// Show the page we want and set it to contain the .current class.
	$('#content .ruleset-panel#'+_ruleSet+' #rules .table#'+_page).show().toggleClass('current');
	
	
}

//This function is used to dynamically retrieve a page that contains a list of rules.
//This function is utilized for the regular list of all rules.
function getPage(ruleSet,pageNr){
	// Copies pagenr to local _pagenr variable.
	var _pageNr = parseInt(pageNr); 
	var _ruleSet = parseInt(ruleSet);
	
	// Ajax-call for the required page. We return it so we can use $.when
	return $.get('/web/rules/ruleSet/'+_ruleSet+'/'+_pageNr+'/', function(html) { 
		/*downloadId = $('table', $('<div/>').html(html)).attr("id");
		pageAlreadyExists = $('#content table[id="'+downloadId+'"]');

		if( pageAlreadyExists.length ) {

			$('#content .rules-panel table[id="'+downloadId+'"]').replaceWith(html);
			
		}
		else {*/
	
			// When the content is loaded, append to content container.
			$('#content .ruleset-panel#'+_ruleSet+' #rules #rules-content').append(html);
			
		//}
		
		
		// We need to reinitialize all the click events and switchbuttons.
		listInitialize();

	})
	
}

function listInitialize() {
	
	
	// Initializes the switchbuttons
	//$(".ruleswitch").bootstrapSwitch()
	
	// Installs click events on all rows.
	$('div.panel-heading').unbind('click');
	$('div.panel-heading').click(function(event){
		// This is to make sure a click on the switch doesnt trigger a row open.
		if($(event.target).is('table td#checkbox')||$(event.target).is('input')||$(event.target).is('a')){
            //event.preventDefault();
			
            return;
        }
		
		if($(this).parent().is('.rules-panel')) {
			// Toggles clicked row on the 'active' css class so it changes color
			$(this).parent().toggleClass("panel-success");			
		}
		else if($(this).parent().is('.ruleset-panel')) {
			// Toggles clicked row on the 'active' css class so it changes color
			$(this).parent().toggleClass("panel-primary");
			if($(this).is('.loaded')) {
				;
			}
			else {
				var ruleSet = $(this).parent().attr('id');
				loadRuleSetRules(ruleSet);
				$(this).toggleClass("loaded");
			}
			
		}
		else {
			$(this).parent().toggleClass("panel-primary");
		}
		// Shows or hides the next row which is hidden by default.
		$(this).next().toggle();
	
	});

		
}

function loadPaginator(ruleSet, currentpage, pagecount) {
	
	// We set some options for the paginator and its click function.
	var options = {
			currentPage: currentpage,
			totalPages: pagecount,
			numberOfPages: 3,
			bootstrapMajorVersion: 3,
			onPageClicked: function(e,originalEvent,type,page){
				
				
				// Load the next pages.
				loadNextPages(ruleSet, page, pagecount);
				// Hide the page we no longer want and show the one we want.
				switchPage(ruleSet, page);
				// We update the window location hash value.
				//window.location.hash = page;
			}
	}
	
	// Start the paginator.
	$('#paginator[ruleset="'+ruleSet+'"]').bootstrapPaginator(options);
	
}

function loadRuleSetRules (ruleSet) {
	var _ruleSet = ruleSet;
	$.when(getPage(_ruleSet,1)).done(function(html){
		
		var pagelength = $('#content .ruleset-panel#'+_ruleSet+' #rules table').attr('pagelength');
		var itemcount = $('#content .ruleset-panel#'+_ruleSet+' #rules table').attr('itemcount');

		pagecount =  Math.ceil(itemcount / pagelength);

		if (itemcount%pagelength == 0) pagecount--; // If the mod is zero, there are no new items in the last page.
		var currentpage = 1;

		loadPaginator(_ruleSet, currentpage, pagecount);
		loadNextPages(_ruleSet, currentpage, pagecount);
		getPage(_ruleSet, pagecount);
		
	});
}

$(document).ready(function(){	
	
	// Calls function to initialize click events and buttons.
	listInitialize();
	
	// Make the manipulator follow you when you scroll.
	animateManipulator();
	
});
