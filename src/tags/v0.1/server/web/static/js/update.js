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
	
	$('button.runUpdate').unbind('click');
	$('button.runUpdate').click(function(event){
		var id = $(this).attr('id')
		$.get("/web/update/runUpdate/" + id + "/", function(data, status){
			alert(data);
		});
	});
}

function getTimeSelector() {
	var interval = $('#createSourceForm').find("select").val();
	$('#TimeSelector').load("/web/update/getTimeSelector/" + interval + "/", function(){});
}

function overrideNewSorceSubmit() {
	$('#createSourceForm').submit(function(event){
		var fields = $('#createSourceForm').find("input");
		var select = $('#createSourceForm').find("select");
		var values = {}

		for(var i = 0; i < fields.length; i++) {
			values[fields[i].name] = fields[i].value;
		}
		for(var i = 0; i < select.length; i++) {
			values[select[i].name] = select[i].value;
		}
		
		$.post("/web/update/newSource/", values, function(data, status){
			$('#newSource').html(data);
			overrideNewSorceSubmit()

			$('#sourceList').load("/web/update/getSourceList/", function(){
				listInitialize();
			});
			$('#ManualUpdate').load("/web/update/getManualUpdateForm/", function(){
				listInitialize();
			});
		});
		
		event.preventDefault();
	});
	$('#createSourceForm').find("select").first().change(function() {
		getTimeSelector()
	});
}

function loadNewSourceForm() {
	$('#newSource').load("/web/update/newSource/", function(){
		overrideNewSorceSubmit()
	});
}

function initializeNewSourceButton() {
	$('#newSource').find("button").click(loadNewSourceForm);
}

$(document).ready(function(){
	listInitialize();
	initializeNewSourceButton()
});
