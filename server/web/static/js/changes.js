/*
 * This script controls all the buttons and events on the Changes page.
 * 
 * 
 */

// This function initializes all the buttons.
function initialize() {
	
	// This opens and closes the panels.
	$('div.panel-heading').unbind('click');
	$('div.panel-heading').click(function(event){
		
		// This is to make sure a click on the switch doesnt trigger a row open.
		if($(event.target).is('#checkbox')||$(event.target).is('button')||$(event.target).is('a')){
            //event.preventDefault();
			
            return;
        }
		
		// Toggles clicked row on the 'active' css class so it changes color
		$(this).parent().toggleClass("panel-primary");

			
		
		// Shows or hides the next row which is hidden by default.
		$(this).next().toggle();
		
		// If what was clicked was in the new rules section.
		if($(this).parent().parent().parent().is('.new-rules')) {
			// We do nothing if its already loaded.
			if($(this).is('.rules-loaded')) {
				;
			}
			else {
				// Grab IDs and get the items for the list.
				var ruleSet = $(this).parent().attr('id');
				var update = $(this).parents('.update-panel').attr('id')
				loadRuleSetNewRules(ruleSet, update);
				$(this).toggleClass("rules-loaded");
			}
			
		}
		// If what was clicked was in the new revisions section.
		else if($(this).parent().parent().parent().is('.new-revisions')) {
			// We do nothing if its already loaded.
			if($(this).is('.rules-loaded')) {
				;
			}
			else {
				// Grab IDs and get the items for the list.
				var ruleSet = $(this).parent().attr('id');
				var update = $(this).parents('.update-panel').attr('id')
				loadRuleSetNewRuleRevisions(ruleSet, update);
				$(this).toggleClass("rules-loaded");
			}
			
		}
		// If what was clicked was an update.
		else if ($(this).parent().is('.update-panel')) {
			// We do nothing if its already loaded.
			if($(this).is('.loaded')) {
				;
			}
			else {
				// Grab IDs and get the items for the list.
				var update = $(this).parent().attr('id');
				loadNewRuleSets(update);
				loadNewRules(update);
				loadNewRuleRevisions(update);
				$(this).toggleClass("loaded");
			}
			
		}
		
	});
	
	// This button removes an update from the list.
	$('button#remove-update').unbind('click');
	$('button#remove-update').click(function(event){
		var _updateID = $(this).attr('update')
		
		$.get("/web/update/changes/removeUpdate/"+_updateID+"/", function() {
			
			location.reload(true);
		});
	});
}

// This function loads the list of new rulesets in an update.
function loadNewRuleSets(updateID) {
	
	var _updateID = updateID
	
	// We ajax in the elements.
	$.get('/web/ruleset/updateSets/'+_updateID+'/', function(html){
		// Add the new elements to where it belongs.
		$('#content .update-panel#'+_updateID+' .panel-body .new-rulesets .panel-body').append(html);
		// We have to reinitialize the buttons.
		listInitialize();
		initialize();
		
	});
	
}

//This function loads the list of new rules in an update.
function loadNewRules(updateID) {
	
	var _updateID = updateID
	
	// We ajax in the elements.
	$.get('/web/ruleset/updateRules/'+_updateID+'/', function(html){
		// Add the new elements to where it belongs.
		$('#content .update-panel#'+_updateID+' .panel-body .new-rules .panel-body').append(html);
		// We have to reinitialize the buttons.
		listInitialize();
		initialize();
	});
	
}
//This function loads the list of new rule revisions in an update.
function loadNewRuleRevisions(updateID) {
	
	var _updateID = updateID
	
	// We ajax in the elements.
	$.get('/web/ruleset/updateRuleRevisions/'+_updateID+'/', function(html){
		// Add the new elements to where it belongs.
		$('#content .update-panel#'+_updateID+' .panel-body .new-revisions .panel-body').append(html);
		// We have to reinitialize the buttons.
		listInitialize();
		initialize();
	});
	
}

//This function is used as a trigger when a ruleset is opened and is used to populate the table of rules within.
function loadRuleSetNewRules (ruleSet, update) {
	
	var _ruleSet = ruleSet;
	var _update = update;
	// We get the first page first.
	$.when(getNewRulesPage(_ruleSet,1, update)).done(function(html){
		// Grab some variables.
		var pagelength = $('#content .update-panel#'+_update+' .panel-body .new-rules .ruleset-panel#'+_ruleSet+' #rules table').attr('pagelength');
		var itemcount = $('#content .update-panel#'+_update+' .panel-body .new-rules .ruleset-panel#'+_ruleSet+' #rules table').attr('itemcount');
		
		// Calculates pagecounts.
		pagecount =  Math.ceil(itemcount / pagelength);
		if (itemcount%pagelength == 0) pagecount--; // If the mod is zero, there are no new items in the last page.
		if (pagecount == 0) pagecount++;
		var currentpage = 1;
		
		// We load the paginator for this set.
		loadNewRulesPaginator(_ruleSet, currentpage, pagecount, update);
		// We load the next pages of rules.
		loadNextNewRulesPages(_ruleSet, currentpage, pagecount, update);
		
		// We load the last page if theres more than one.
		if (pagecount > currentpage) {
			getNewRulesPage(_ruleSet, pagecount, update);
		}
	});
}

//This function is used as a trigger when a ruleset is opened and is used to populate the table of rules within.
function loadRuleSetNewRuleRevisions (ruleSet, update) {
	
	var _ruleSet = ruleSet;
	var _update = update;
	// We get the first page first.
	$.when(getNewRuleRevisionsPage(_ruleSet,1, update)).done(function(html){
		// Grab some variables.
		var pagelength = $('#content .update-panel#'+_update+' .panel-body .new-revisions .ruleset-panel#'+_ruleSet+' #rules table').attr('pagelength');
		var itemcount = $('#content .update-panel#'+_update+' .panel-body .new-revisions .ruleset-panel#'+_ruleSet+' #rules table').attr('itemcount');
		
		// Calculates pagecounts.
		pagecount =  Math.ceil(itemcount / pagelength);
		if (itemcount%pagelength == 0) pagecount--; // If the mod is zero, there are no new items in the last page.
		if (pagecount == 0) pagecount++;
		var currentpage = 1;
		
		// We load the paginator for this set.
		loadNewRuleRevisionsPaginator(_ruleSet, currentpage, pagecount, update);
		// We load the next pages of rules.
		loadNextNewRuleRevisionsPages(_ruleSet, currentpage, pagecount, update);
		
		// We load the last page if theres more than one.
		if (pagecount > currentpage) {
			getNewRuleRevisionsPage(_ruleSet, pagecount, update);
		}
	});
}

//This function is used to dynamically load three pages before and after the current page.
function loadNextNewRulesPages(ruleSet, currentpage, pagecount, update) {
	
	// Copy passed variables to local variables.
	var _currentpage = currentpage;
	var _pagecount = pagecount;
	var _ruleSet = ruleSet;
	var _update = update

	// Loop for -3 and +3 from the current page.
	for(var i=-3;i<=3;i++) {
		// We dont want negative page numbers or 
		// pages outside the actual page range
		if (_currentpage+i > 1 && _currentpage+i < _pagecount && _currentpage+i != _currentpage) {
			// Try to find a page element with this id nr.
			var _pageexists = $('#content .update-panel#'+_update+' .panel-body .new-rules .ruleset-panel#'+_ruleSet+' #rules .table#'+(_currentpage+i)+'').length;
			// If the page doesnt exist, we need to load it.
			if (!_pageexists) {
				// Loads the page it didnt find.
				getNewRulesPage(_ruleSet, _currentpage+i, _update);
				
			}
		}
	}
	
}

//This function is used to dynamically load three pages before and after the current page.
function loadNextNewRuleRevisionsPages(ruleSet, currentpage, pagecount, update) {
	
	// Copy passed variables to local variables.
	var _currentpage = currentpage;
	var _pagecount = pagecount;
	var _ruleSet = ruleSet;
	var _update = update

	// Loop for -3 and +3 from the current page.
	for(var i=-3;i<=3;i++) {
		// We dont want negative page numbers or 
		// pages outside the actual page range
		if (_currentpage+i > 1 && _currentpage+i < _pagecount && _currentpage+i != _currentpage) {
			// Try to find a page element with this id nr.
			var _pageexists = $('#content .update-panel#'+_update+' .panel-body .new-revisions .ruleset-panel#'+_ruleSet+' #rules .table#'+(_currentpage+i)+'').length;
			// If the page doesnt exist, we need to load it.
			if (!_pageexists) {
				// Loads the page it didnt find.
				getNewRuleRevisionsPage(_ruleSet, _currentpage+i, _update);
				
			}
		}
	}
	
}

//This function is used to switch between pages in the list.
function switchNewRulesPage(ruleSet, page, update) {
	$(document).ajaxStop(function(){
		var _page = page;
		var _ruleSet = ruleSet;
		var _update = update;
		// Hide the page marked .current and then turn off its .current class.
		$('#content .update-panel#'+_update+' .panel-body .new-rules .ruleset-panel#'+_ruleSet+' #rules .current').hide().toggleClass('current');
		// Show the page we want and set it to contain the .current class.
		$('#content .update-panel#'+_update+' .panel-body .new-rules .ruleset-panel#'+_ruleSet+' #rules .table#'+_page).show().toggleClass('current');
	});
	
}

//This function is used to switch between pages in the list.
function switchNewRuleRevisionsPage(ruleSet, page, update) {
	$(document).ajaxStop(function(){
		var _page = page;
		var _ruleSet = ruleSet;
		var _update = update;
		// Hide the page marked .current and then turn off its .current class.
		$('#content .update-panel#'+_update+' .panel-body .new-revisions .ruleset-panel#'+_ruleSet+' #rules .current').hide().toggleClass('current');
		// Show the page we want and set it to contain the .current class.
		$('#content .update-panel#'+_update+' .panel-body .new-revisions .ruleset-panel#'+_ruleSet+' #rules .table#'+_page).show().toggleClass('current');
	
	});
}

//This function is used to dynamically retrieve a page that contains a list of rules.
function getNewRulesPage(ruleSet,pageNr, update){
	// Copies pagenr to local _pagenr variable.
	var _pageNr = parseInt(pageNr); 
	var _ruleSet = parseInt(ruleSet);
	var _update = parseInt(update);
	
	// Ajax-call for the required page. We return it so we can use $.when
	return $.get('/web/rules/ruleSetNewRules/'+_ruleSet+'/'+_pageNr+'/'+_update+'/', function(html) { 
			
		// When the content is loaded, append to content container.
		$('#content .update-panel#'+_update+' .panel-body .new-rules .ruleset-panel#'+_ruleSet+' #rules #rules-content').append(html);
			
		// We need to reinitialize all the click events and switchbuttons.
		listInitialize();
		initialize();

	})
	
}

//This function is used to dynamically retrieve a page that contains a list of rules.
function getNewRuleRevisionsPage(ruleSet,pageNr, update){
	// Copies pagenr to local _pagenr variable.
	var _pageNr = parseInt(pageNr); 
	var _ruleSet = parseInt(ruleSet);
	var _update = parseInt(update);
	
	// Ajax-call for the required page. We return it so we can use $.when
	return $.get('/web/rules/ruleSetNewRuleRevisions/'+_ruleSet+'/'+_pageNr+'/'+_update+'/', function(html) { 
			
		// When the content is loaded, append to content container.
		$('#content .update-panel#'+_update+' .panel-body .new-revisions .ruleset-panel#'+_ruleSet+' #rules #rules-content').append(html);
			
		// We need to reinitialize all the click events and switchbuttons.
		listInitialize();
		initialize();

	})
	
}

// This function paginates the new rules list.
function loadNewRulesPaginator(ruleSet, currentpage, pagecount, update) {
	
	// We set some options for the paginator and its click function.
	var options = {
			currentPage: currentpage,
			totalPages: pagecount,
			numberOfPages: 3,
			bootstrapMajorVersion: 3,
			onPageClicked: function(e,originalEvent,type,page){
				
				originalEvent.preventDefault();
				// Load the next pages.
				loadNextNewRulesPages(ruleSet, page, pagecount, update);
				// Hide the page we no longer want and show the one we want.
				switchNewRulesPage(ruleSet, page, update);
				// We update the window location hash value.
				//window.location.hash = page;
			}
	}
	
	// Start the paginator.
	$('#content .update-panel#'+update+' .panel-body .new-rules  #paginator[ruleset="'+ruleSet+'"]').bootstrapPaginator(options);
	
}

// This function paginates the new revisions list.
function loadNewRuleRevisionsPaginator(ruleSet, currentpage, pagecount, update) {
	
	// We set some options for the paginator and its click function.
	var options = {
			currentPage: currentpage,
			totalPages: pagecount,
			numberOfPages: 3,
			bootstrapMajorVersion: 3,
			onPageClicked: function(e,originalEvent,type,page){
				
				originalEvent.preventDefault();
				// Load the next pages.
				loadNextNewRuleRevisionsPages(ruleSet, page, pagecount, update);
				// Hide the page we no longer want and show the one we want.
				switchNewRuleRevisionsPage(ruleSet, page, update);
				// We update the window location hash value.
				//window.location.hash = page;
			}
	}
	
	// Start the paginator.
	$('#content .update-panel#'+update+' .panel-body .new-revisions  #paginator[ruleset="'+ruleSet+'"]').bootstrapPaginator(options);
	
}


//When the documents is finished loading, initialize everything.
$(document).ready(function(){
	initialize();
});