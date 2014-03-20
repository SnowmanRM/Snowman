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
	// Install click event so that when the header checkbox is clicked, all the other checkboxes is checked.
	$('.panel .panel-heading #checkbox-all').click(function(event){
				
		if ($(".panel #checkbox-all").is(':checked')) {
            $(".panel .panel-heading #checkbox").each(function () {
                $(this).prop("checked", true);
            });

        } else {
            $(".panel .panel-heading #checkbox").each(function () {
                $(this).prop("checked", false);
            });
        }
		
	});
	// Install click event so that when the header checkbox is clicked, all the other checkboxes is checked.
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
		//console.log($(this).parent().is('.ruleset-panel'));
		if($(this).parent().is('.rules-panel')) {
			// Toggles clicked row on the 'active' css class so it changes color
			$(this).parent().toggleClass("panel-success");			
		}
		else if($(this).parent().is('.ruleset-panel')) {
			// Toggles clicked row on the 'active' css class so it changes color
			$(this).parent().toggleClass("panel-primary");

			if($(this).is('.rulesets-loaded') || $(this).parent().attr('tree-type') == "child") {
				;
			}
			else {
				
				$(this).parent().find('.panel-body .ruleset-panel[tree-type="parent"]').each(function(){
					loadRuleSetChildren(this.id);
					
				});
				listInitialize();
				$(this).toggleClass("rulesets-loaded");
			}
			
			if($(this).is('.rules-loaded') || $(this).parent().attr('has-rules') == "False") {
				;
			}
			else {
				var ruleSet = $(this).parent().attr('id');
				loadRuleSetRules(ruleSet);
				$(this).toggleClass("rules-loaded");
			}
			
		}
		else {
			$(this).parent().toggleClass("panel-primary");
		}
		// Shows or hides the next row which is hidden by default.
		
		$(this).next().toggle();
	
	});
	
	$('#ruleset-buttons #create').click(function(event){
		// Reset this button in the form to default just in case.
		$('button#create-submit').prop("disabled",false);
		$('button#create-submit').attr('class','btn btn-primary');
		$('button#create-submit').html('Save changes');
		selectRemembers('select#children');
		// Load the form with AJAX.
		$.get('/web/ruleset/getCreateRuleSetForm/', function(html){
			// Put the form content into the container.
			$('#createRuleSetModal #formContent').html(html);
			
			// Install validators on a few of the form fields and set up the submit handler.
			$('#createRuleSetForm').validate({
				submitHandler: function(form) {
					
					submitCreateRuleSetForm(form);
				}
				
			});
			
			/*// Get all checked checkboxes.
			sids=$('#checkbox:checked');
			// If there are checkboxes checked, we need to do some extra stuff.
			if (sids.length > 0) {
				// We replace the input with a disabled select that displays the checked rules.
				$('#thresholdFormModal #formContent input#sid').replaceWith('<select multiple class="form-control" id="sid" name="sid" disabled></select>');
				// For each checked rule, we add them to the select list.
				$(sids).each(function(){
					$('#thresholdFormModal #formContent').prepend('<input type="hidden" id="id" name="id" value="'+$(this).attr('rid')+'">');
					$('#thresholdFormModal #formContent select#sid').append('<option>'+$(this).attr('gid')+':'+$(this).attr('sid')+'|'+$(this).attr('status')+'</option>');
				});
			}
			*/
			
		
		});

	});
	
	$('#ruleset-buttons #edit').click(function(event){
		// Reset this button in the form to default just in case.
		$('button#edit-submit').prop("disabled",false);
		$('button#edit-submit').attr('class','btn btn-primary');
		$('button#edit-submit').html('Save changes');
		selectRemembers('select#children');
		var _ruleSet = $('#checkbox:checked').first().attr('ruleset');
		
		if (_ruleSet) {
			// Load the form with AJAX.
			$.get('/web/ruleset/getEditRuleSetForm/'+_ruleSet+'/', function(html){
				// Put the form content into the container.
				$('#editRuleSetModal #formContent').html(html);
				
				// Install validators on a few of the form fields and set up the submit handler.
				$('#editRuleSetForm').validate({
					submitHandler: function(form) {
						
						submitEditRuleSetForm(form);
					}
					
				});
				
				/*// Get all checked checkboxes.
				
				// If there are checkboxes checked, we need to do some extra stuff.
				if (sids.length > 0) {
					// We replace the input with a disabled select that displays the checked rules.
					$('#thresholdFormModal #formContent input#sid').replaceWith('<select multiple class="form-control" id="sid" name="sid" disabled></select>');
					// For each checked rule, we add them to the select list.
					$(sids).each(function(){
						$('#thresholdFormModal #formContent').prepend('<input type="hidden" id="id" name="id" value="'+$(this).attr('rid')+'">');
						$('#thresholdFormModal #formContent select#sid').append('<option>'+$(this).attr('gid')+':'+$(this).attr('sid')+'|'+$(this).attr('status')+'</option>');
					});
				}
				*/
				// Reset this button in the form to default just in case.
				$('button#edit-submit').prop("disabled",false);
				$('button#edit-submit').attr('class','btn btn-primary');
				$('button#edit-submit').html('Save changes');
				selectRemembers('select#children');
			
			});
		}
		else {
			setTimeout(function() {$('#editRuleSetModal').modal('hide')}, 1);
		}
	});
	
	$('#ruleset-buttons #delete').click(function(event){
		
		var _ruleSets = $('#checkbox:checked[ruleset]');
		console.log(_ruleSets);
		if (_ruleSets.length > 0) {
			
			// For each checked rule, we add them to the select list.
			$(_ruleSets).each(function(){
				$('#deleteRuleSetModal #formContent').append('<input type="hidden" id="id" name="id" value="'+$(this).attr('ruleset')+'">');
			});
			
			// Install validators on a few of the form fields and set up the submit handler.
			$('#deleteRuleSetForm').submit(function(event){ event.preventDefault(); submitDeleteRuleSetForm(this)});			
		
		}
		else {
			setTimeout(function() {$('#deleteRuleSetModal').modal('hide')}, 1);
		}
	});
}

function submitCreateRuleSetForm(form){
	
	// We send the form serialized to the server.
	$.ajax({
		url: "/web/ruleset/createRuleSet/",
		type: "post",
		dataType: "json",
		data: $(form).serialize(),
		success: function(data) {
			// These are flags that determine the outcome of the response.
			var success, warning, error = false;
			// Clean up any old alerts in the form.
			$('#createRuleSetForm .alert').remove();
			// We might get more than one response, so we iterate over them.
			$.each(data, function() {
				// If the response contains one of these strings, we put the response text near the relevant context and display it. 
				// We also set the outcome flags appropriately so we can handle things differently.
				if(this.response == "ruleSetCreated") {
					
					text = '<div class="alert alert-success row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#createRuleSetForm div#formContent').append(text).prepend(text);
							
					$('#createRuleSetForm div#formContent .alert').show("highlight");
					
					success = true;
				}
				else if(this.response == "noRuleSetName") {
					
					$('#createRuleSetForm div#rulesetname div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#createRuleSetForm div#rulesetname div.col-sm-10 .alert').show("highlight");
					
					error = true;
				}
				else if (this.response == "ruleSetExists") {
					
					$('#createRuleSetForm div#rulesetname div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
							
					$('#createRuleSetForm div#rulesetname div.col-sm-10 .alert').show("highlight");
							
					error = true;
				}
				else if(this.response == "ruleSetCreationFailure") {
					
					
					text = '<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>'
					$('#createRuleSetForm div#formContent').append(text).prepend(text);
							
					$('#createRuleSetForm div#formContent .alert').show("highlight");
					
					error = true;
				}
				
				// If the success-flag was set to true, everything went ok and we can show the user this outcome and close the modal.
				if( success ) {
					
					
					$('button#create-submit').hide();
					$('button#create-submit').prop("disabled",true);
					$('button#create-submit').attr('class','btn btn-success');
					$('button#create-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
					$('button#create-submit').show("highlight");
					
					setTimeout(function() {$('#createRuleSetModal').modal('hide')}, 3000);
					setTimeout(function() {location.reload(true)}, 1000);
				
				}
				// If the outcome was not a success, we have to show this to the user.
				else if( warning || error ) {
					// If there was an error, we dont force a DB commit next time. The user has to fix the problem and recheck.
					if (error) {
						
						$('button#create-submit').attr('class','btn btn-danger');
						$('button#create-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
					}
					// If there is only a warning, we force a DB commit next time, but we warn the user of some things first, just in case.
					else {
						
						$('button#create-submit').attr('class','btn btn-warning');
						$('button#create-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
					}
				}
			});
		}
	});
	
}

function submitEditRuleSetForm(form){
	
	// We send the form serialized to the server.
	$.ajax({
		url: "/web/ruleset/editRuleSet/",
		type: "post",
		dataType: "json",
		data: $(form).serialize(),
		success: function(data) {
			// These are flags that determine the outcome of the response.
			var success, warning, error = false;
			// Clean up any old alerts in the form.
			$('#editRuleSetForm .alert').remove();
			// We might get more than one response, so we iterate over them.
			$.each(data, function() {
				// If the response contains one of these strings, we put the response text near the relevant context and display it. 
				// We also set the outcome flags appropriately so we can handle things differently.
				if(this.response == "ruleSetSuccessfullyEdited") {
					
					text = '<div class="alert alert-success row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#editRuleSetForm div#formContent').append(text).prepend(text);
							
					$('#editRuleSetForm div#formContent .alert').show("highlight");
					
					success = true;
				}
				else if(this.response == "noRuleSetName") {
					
					$('#editRuleSetForm div#rulesetname div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#editRuleSetForm div#rulesetname div.col-sm-10 .alert').show("highlight");
					
					error = true;
				}
				else if(this.response == "ruleSetParentInbreeding") {
					
					$('#editRuleSetForm div#parent div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#editRuleSetForm div#parent div.col-sm-10 .alert').show("highlight");
					
					error = true;
				}
				else if(this.response == "ruleSetChildInbreeding") {
					
					$('#editRuleSetForm div#children div.col-sm-10').append('<div class="alert alert-danger row" style="display: none;">\
					<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
					<div class="col-sm-11">'+this.text+'</div></div>');
					
					$('#editRuleSetForm div#children div.col-sm-10 .alert').show("highlight");
					
					error = true;
				}
				else if (this.response == "ruleSetDoesNotExists") {
					
					text = '<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#editRuleSetForm div#formContent').append(text).prepend(text);
							
					$('#editRuleSetForm div#formContent .alert').show("highlight");
							
					error = true;
				}
				else if(this.response == "ruleSetNoChanges") {
					
					
					text = '<div class="alert alert-success row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#editRuleSetForm div#formContent').append(text).prepend(text);
							
					$('#editRuleSetForm div#formContent .alert').show("highlight");
					
					success = true;
				}
				
				// If the success-flag was set to true, everything went ok and we can show the user this outcome and close the modal.
				if( success ) {
					
					
					$('button#edit-submit').hide();
					$('button#edit-submit').prop("disabled",true);
					$('button#edit-submit').attr('class','btn btn-success');
					$('button#edit-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
					$('button#edit-submit').show("highlight");
					
					setTimeout(function() {$('#editRuleSetModal').modal('hide')}, 3000);
					setTimeout(function() {location.reload(true)}, 1000);
				
				}
				// If the outcome was not a success, we have to show this to the user.
				else if( warning || error ) {
					// If there was an error, we dont force a DB commit next time. The user has to fix the problem and recheck.
					if (error) {
						
						$('button#edit-submit').attr('class','btn btn-danger');
						$('button#edit-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
					}
					// If there is only a warning, we force a DB commit next time, but we warn the user of some things first, just in case.
					else {
						
						$('button#edit-submit').attr('class','btn btn-warning');
						$('button#edit-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
					}
				}
			});
		}
	});
	
}

function submitDeleteRuleSetForm(form){
	
	// We send the form serialized to the server.
	$.ajax({
		url: "/web/ruleset/deleteRuleSet/",
		type: "post",
		dataType: "json",
		data: $(form).serialize(),
		success: function(data) {
			// These are flags that determine the outcome of the response.
			var success, warning, error = false;
			// We might get more than one response, so we iterate over them.
			$.each(data, function() {
				// If the response contains one of these strings, we put the response text near the relevant context and display it. 
				// We also set the outcome flags appropriately so we can handle things differently.
				if(this.response == "ruleSetSuccessfulDeletion") {
					
					text = '<div class="alert alert-success row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#deleteRuleSetForm div#formContent').append(text).prepend(text);
							
					$('#deleteRuleSetForm div#formContent .alert').show("highlight");
					
					success = true;
				}
				else if (this.response == "ruleSetDoesNotExists") {
					
					text = '<div class="alert alert-danger row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-remove form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#deleteRuleSetForm div#formContent').append(text).prepend(text);
							
					$('#deleteRuleSetForm div#formContent .alert').show("highlight");
							
					error = true;
				}
				else if(this.response == "noIDsGiven") {
					
					
					text = '<div class="alert alert-success row" style="display: none;">\
						<div class="col-sm-1"><span class="glyphicon glyphicon-ok-cicle form-control-feedback"></span></div>\
						<div class="col-sm-11">'+this.text+'</div></div>'
					$('#deleteRuleSetForm div#formContent').append(text).prepend(text);
							
					$('#deleteRuleSetForm div#formContent .alert').show("highlight");
					
					success = true;
				}
				
				// If the success-flag was set to true, everything went ok and we can show the user this outcome and close the modal.
				if( success ) {
					
					
					$('button#delete-submit').hide();
					$('button#delete-submit').prop("disabled",true);
					$('button#delete-submit').attr('class','btn btn-success');
					$('button#delete-submit').html('<span class="glyphicon glyphicon-ok form-control-feedback"></span> Success');
					$('button#delete-submit').show("highlight");
					
					setTimeout(function() {$('#deleteRuleSetModal').modal('hide')}, 3000);
					setTimeout(function() {location.reload(true)}, 1000);
				
				}
				// If the outcome was not a success, we have to show this to the user.
				else if( warning || error ) {
					// If there was an error, we dont force a DB commit next time. The user has to fix the problem and recheck.
					if (error) {
						
						$('button#delete-submit').attr('class','btn btn-danger');
						$('button#delete-submit').html('<span class="glyphicon glyphicon-remove form-control-feedback"></span> Try again');
					}
					// If there is only a warning, we force a DB commit next time, but we warn the user of some things first, just in case.
					else {
						
						$('button#delete-submit').attr('class','btn btn-warning');
						$('button#delete-submit').html('<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Force change');
					}
				}
			});
		}
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

// This function is used as a trigger when a ruleset is opened and is used to populate the table of rules within.
function loadRuleSetRules (ruleSet) {
	var _ruleSet = ruleSet;
	// We get the first page first.
	$.when(getPage(_ruleSet,1)).done(function(html){
		// Grab some variables.
		var pagelength = $('#content .ruleset-panel#'+_ruleSet+' #rules table').attr('pagelength');
		var itemcount = $('#content .ruleset-panel#'+_ruleSet+' #rules table').attr('itemcount');
		
		// Calculates pagecounts.
		pagecount =  Math.ceil(itemcount / pagelength);
		if (itemcount%pagelength == 0) pagecount--; // If the mod is zero, there are no new items in the last page.
		var currentpage = 1;
		
		// We load the paginator for this set.
		loadPaginator(_ruleSet, currentpage, pagecount);
		// We load the next pages of rules.
		loadNextPages(_ruleSet, currentpage, pagecount);
		
		// We load the last page if theres more than one.
		if (pagecount > currentpage) {
			getPage(_ruleSet, pagecount);
		}
	});
}

function loadRuleSetChildren (ruleSet) {
	var _ruleSet = ruleSet
	var _treeLevel = $('#content .ruleset-panel#'+_ruleSet+'').attr('tree-level')
	
	$.get('/web/ruleset/children/'+_ruleSet+'/', function(html){
		
		$('#content .ruleset-panel#'+_ruleSet+' .panel-body').append(html);
		$('#content .ruleset-panel#'+_ruleSet+' .panel-body .ruleset-panel').attr("tree-level", parseInt(_treeLevel)+1);
		
	});
	
}

$(document).ready(function(){	
	
	
	
	// Make the manipulator follow you when you scroll.
	animateManipulator();
	
	$('#content .ruleset-panel').not('.panel-info').each(function(){
		
		loadRuleSetChildren(this.id);
	});
	
	// Calls function to initialize click events and buttons.
	listInitialize();
	
	

});
