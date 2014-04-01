// This function is used to dynamically load three pages before and after the current page.
// This function is utilized for the regular list of all rules.
function loadNextPages(ruleClass, currentpage, pagecount) {
	
	// Copy passed variables to local variables.
	var _currentpage = currentpage;
	var _pagecount = pagecount;
	var _ruleClass = ruleClass;

	// Loop for -3 and +3 from the current page.
	for(var i=-3;i<=3;i++) {
		// We dont want negative page numbers or 
		// pages outside the actual page range
		if (_currentpage+i > 1 && _currentpage+i < _pagecount && _currentpage+i != _currentpage) {
			
			// Try to find a page element with this id nr.
			var _pageexists = $('#content .ruleclass-panel#'+_ruleClass+' #rules .table#'+(_currentpage+i)+'').length;
			// If the page doesnt exist, we need to load it.
			if (!_pageexists) {
				// Loads the page it didnt find.
				getPage(_ruleClass, _currentpage+i);
				
			}
		}
	}
	
}

//This function is used to switch between pages in the list.
function switchPage(ruleClass, page) {
	$(document).ajaxStop(function(){
		var _page = page;
		var _ruleClass = ruleClass;
		// Hide the page marked .current and then turn off its .current class.
		$('#content .ruleclass-panel#'+_ruleClass+' #rules .current').hide().toggleClass('current');
		// Show the page we want and set it to contain the .current class.
		$('#content .ruleclass-panel#'+_ruleClass+' #rules .table#'+_page).show().toggleClass('current');
	});
	
}

//This function is used to dynamically retrieve a page that contains a list of rules.
//This function is utilized for the regular list of all rules.
function getPage(ruleClass,pageNr){
	// Copies pagenr to local _pagenr variable.
	var _pageNr = parseInt(pageNr); 
	var _ruleClass = parseInt(ruleClass);
	
	// Ajax-call for the required page. We return it so we can use $.when
	return $.get('/web/rules/ruleClass/'+_ruleClass+'/'+_pageNr+'/', function(html) { 
		/*downloadId = $('table', $('<div/>').html(html)).attr("id");
		pageAlreadyExists = $('#content table[id="'+downloadId+'"]');

		if( pageAlreadyExists.length ) {

			$('#content .rules-panel table[id="'+downloadId+'"]').replaceWith(html);
			
		}
		else {*/
	
			// When the content is loaded, append to content container.
			$('#content .ruleclass-panel#'+_ruleClass+' #rules #rules-content').append(html);
			
		//}
		
		
		// We need to reinitialize all the click events and switchbuttons.
		listInitialize();

	})
	
}

// This function intitializes all buttons and events on this page.
function listInitialize() {
	// Install click event so that when the header checkbox is clicked, all the other checkboxes is checked.
	$('.panel .panel-heading #checkbox-all').unbind('click');
	$('.panel .panel-heading #checkbox-all').click(function(event){
		
		if ($(".panel #checkbox-all").is(':checked')) {
            $(".panel .panel-heading input[type=checkbox]").each(function () {
                $(this).prop("checked", true);
            });

        } else {
            $(".panel .panel-heading input[type=checkbox]").each(function () {
                $(this).prop("checked", false);
            });
        }
		
	});
	$('table thead th#checkbox-all input').unbind('click');
	$('table thead th#checkbox-all input').click(function(event){
				
		if ($("table thead th#checkbox-all input").is(':checked')) {
            $("table.current td#checkbox input[type=checkbox]").each(function () {
                $(this).prop("checked", true);
            });

        } else {
            $("table.current td#checkbox input[type=checkbox]").each(function () {
                $(this).prop("checked", false);
            });
        }
		
	});

	
	// Installs click events on all rows.
	$('table tbody tr.odd').unbind('click');
	$('table tbody tr.odd').click(function(event){
		// This is to make sure a click on the switch doesnt trigger a row open.
		if($(event.target).is('#checkbox')||$(event.target).is('#checkbox')){
            //event.preventDefault();
            return;
        }
		
		// Toggles clicked row on the 'active' css class so it changes color
		$(this).toggleClass("bg-primary");
		// Shows or hides the next row which is hidden by default.
		$(this).next().toggle();
	
	});

	
	// Installs click events on all rows.
	$('div.panel-heading').unbind('click');
	$('div.panel-heading').click(function(event){
		// This is to make sure a click on the switch doesnt trigger a row open.
		if($(event.target).is('#checkbox')||$(event.target).is('input')||$(event.target).is('a')){
            //event.preventDefault();
			
            return;
        }
		// The click target was a rule panel.
		if($(this).parent().is('.rules-panel')) {
			// Toggles clicked row on the 'active' css class so it changes color
			$(this).parent().toggleClass("panel-success");			
		}
		// The click target was a ruleclass panel.
		else if($(this).parent().is('.ruleclass-panel')) {
			// Toggles clicked row on the 'active' css class so it changes color
			$(this).parent().toggleClass("panel-primary");
			// If elements are already loaded, we do nothing.
			if($(this).is('.loaded')) {
				;
			}
			else {
				// We load the rulelist for the clicked ruleclass.
				var ruleClass = $(this).parent().attr('id');
				loadRuleClassRules(ruleClass);
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

// This function paginates the rule lists.
function loadPaginator(ruleClass, currentpage, pagecount) {
	
	// We set some options for the paginator and its click function.
	var options = {
			currentPage: currentpage,
			totalPages: pagecount,
			numberOfPages: 3,
			bootstrapMajorVersion: 3,
			onPageClicked: function(e,originalEvent,type,page){
				
				originalEvent.preventDefault();
				// Load the next pages.
				loadNextPages(ruleClass, page, pagecount);
				// Hide the page we no longer want and show the one we want.
				switchPage(ruleClass, page);
				// We update the window location hash value.
				//window.location.hash = page;
			}
	}
	
	// Start the paginator.
	$('#paginator[ruleclass="'+ruleClass+'"]').bootstrapPaginator(options);
	
}
//This function is used as a trigger when a ruleclasses is opened and is used to populate the table of rules within.
function loadRuleClassRules (ruleClass) {
	var _ruleClass = ruleClass;
	// We get the first page first.
	$.when(getPage(_ruleClass,1)).done(function(html){
		// Grab some variables.
		var pagelength = parseInt($('#content .ruleclass-panel#'+_ruleClass+' #rules table').attr('pagelength'));
		var itemcount = parseInt($('#content .ruleclass-panel#'+_ruleClass+' #rules table').attr('itemcount'));
		
		// Calculates pagecounts.
		pagecount =  Math.ceil(itemcount / pagelength);
		if (itemcount%pagelength == 0) pagecount--; // If the mod is zero, there are no new items in the last page.
		if (pagecount == 0) pagecount++;
		var currentpage = 1;
		
		// We load the paginator for this class.
		loadPaginator(_ruleClass, currentpage, pagecount);
		// We load the next pages of rules.
		loadNextPages(_ruleClass, currentpage, pagecount);
		
		// We load the last page if theres more than one.
		if (pagecount > currentpage) {
			getPage(_ruleClass, pagecount);
		}
		
	});
}

$(document).ready(function(){
		
	// Calls function to initialize click events and buttons.
	listInitialize();
	
	// Make the manipulator follow you when you scroll.
	animateManipulator();
	
});


