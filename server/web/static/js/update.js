/*
 * This javascript-file is all the code specificly written for the update-pages. Misc
 * buttons and areas that should be clicable, and the relevant ajax is what is in this
 * form.
 */

// Initializes all the javascript for the update-pages.
function initialize() {
	// Initializes the collapsable lists on the page.
	//   Installs click events on all rows.
	$('li.odd').unbind('click');
	$('li.odd').click(function(event){
		// Toggles clicked row on the 'active' css class so it changes color
		$(this).toggleClass("bg-primary");
		// Shows or hides the next row which is hidden by default.
		$(this).next().slideToggle("fast","linear");
	});
	
	// Initializes the buttons for starting updates of a source.
	$('button.runUpdate').unbind('click');
	$('button.runUpdate').click(function(event){
		var id = $(this).attr('id')
		$.get("/web/update/runUpdate/" + id + "/", function(data, status){
			alert(data.message);
		});
	});
	
	// Initializes the forms on the page.
	initializeEditSourceForm();
	initializeNewSourceButton();
}

function reloadData() {
	// Refresh the source-list:
	$('#sourceList').load("/web/update/getSourceList/", function(){
		initialize()
	});
	// Refresh the update-manual form.
	$('#ManualUpdate').load("/web/update/getManualUpdateForm/", function(){
		initialize();
	});
}

// Retrieves the time-select form which corresponds to the selected update-interval via AJAX.
function getTimeSelector(selector) {
	var interval = $(selector).find("select").val();
	$(selector).find('#TimeSelector').load("/web/update/getTimeSelector/" + interval + "/", function(){});
}

// Initializes the newSource form
function initializeNewSourceForm() {
	// Overrides the submit button:
	$('#createSourceForm').unbind('submit');
	$('#createSourceForm').submit(function(event){
		var fields = $('#createSourceForm').find("input");
		var select = $('#createSourceForm').find("select");
		
		// Post the data via AJAX
		$.post("/web/update/newSource/", $(this).serialize(), function(data, status){
			// Replace the form with whatever the AJAX-call returns
			$('#newSource').html(data);
			// And initialize the form again, in case there is a new one.
			initializeNewSourceForm()
			
			reloadData();
		});
		
		// Remove the default actions from the post-button.
		event.preventDefault();
	});

	// Adds an event, so that we switch out the timeSelector every time
	//   the update-interval is changed.
	$('#createSourceForm').find("select").first().unbind('change');
	$('#createSourceForm').find("select").first().change(function() {
		getTimeSelector('#createSourceForm')
	});
}

// Method to initialize the editSource forms on the page.
function initializeEditSourceForm() {
	// Overrides the default submit-action for the submit-buttons.
	$('form.editSourceForm').unbind('submit');
	$('form.editSourceForm').submit(function(event){
		var fields = $(this).find("input");
		var select = $(this).find("select");
		url = $(this).attr('action');
		
		// Post the data using AJAX.
		$.post(url, $(this).serialize(), function(data, status){
			var id = $(data).find('id').text();
			var message = $(data).find('message').text();
			var success = $(data).find('success').text();
			var newform = $(data).find('newform').html();
			var form = $('#editSource-' + id).find('#editSourceForm.div');
			
			// Replace the edit-form with the form recieved by ajax, and 
			//   re-initialize the edit-forms.
			$(form).html(newform);
			initializeEditSourceForm();
			
			// If the server says that something successful happened, 
			//   reload the forms.
			if(success == "true") {
				$('#editSource-' + id).modal('hide');
				$('#editSource-' + id).on('hidden.bs.modal', function (e) {
					reloadData();
				});
			}
		});

		// Prevent the default submit-action.	
		event.preventDefault();
	});
	
	// Add a listener on the "schedule" select, so that we load the
	//   appropriate timeSelect form when the schedule is changed.
	$('form.editSourceForm').unbind('change');
	$('form.editSourceForm').find('select').change(function() {
		console.log($(this).attr('name'));
		if($(this).attr('name') == "schedule") {
			getTimeSelector($(this).closest('form'))
		}
	});
}

// Method which reloads the form for new Update-Sources.
function loadNewSourceForm() {
	$('#newSource').load("/web/update/newSource/", function(){
		initializeNewSourceForm()
	});
}

// Method which initializes the button which loads the newSource-form.
function initializeNewSourceButton() {
	$('#newSource').find("button").click(loadNewSourceForm);
}

function startStatusUpdates(sourceid) {
	var progresspump = setInterval(function(){
		/* query the completion percentage from the server */
		$.get("/web/update/getStatus/" + sourceid + "/", function(data){
			if(data.status == true) {
				$("#updateMessage-" + sourceid).show();
				$("#progressouter-" + sourceid).show();
				$("#updateButtons-" + sourceid).hide();
				/* update the progress bar width */
				$("#progress-" + sourceid).css('width',data.progress+'%');
				/* and display the numeric value */
				$("#progress-" + sourceid).html(data.progress+'%');
				$("#updateMessage-" + sourceid).html("<p>" + data.message + "</p>");
				
				/* test to see if the job has completed */
				if(data.progress > 99.999) {
					//clearInterval(progresspump);
					//$("#progressouter").removeClass("active");
					$("#progress-" + sourceid).html("Done");
					$("#updateMessage-" + sourceid).html("<p>Update complete</p>");
				}
			} else {
				$("#progressouter-" + sourceid).hide();
				$("#updateMessage-" + sourceid).hide();
				$("#updateButtons-" + sourceid).show();
			}
			var newlist = "<ul>\n";
			for(var i = 0; i < data.updates.length; i++) {
				newlist += "<li>" + data.updates[i].time + " (" + data.updates[i].changes + " changes)</li>\n";
			}
			newlist += "</ul>\n";
			$("#lastUpdates-" + sourceid).html(newlist);
		})
	}, 1000);
}

// When the documents is finished loading, initialize everything.
$(document).ready(function(){
	initialize();
});
