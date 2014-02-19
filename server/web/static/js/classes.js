


function Page(pagenr, lowobjects, highobjects, maxobjects) {
	var _pagenr = pagenr;
	var _lowobjects = lowobjects;
	var _highobjects = highobjects;
	var _maxobjects = maxobjects;
	var _rules = new Array();
	
	test = $.get('getrulelistrange/'+lowobjects+'/'+highobjects+'/')
	
	for (var i=0; i<maxobjects;i++)  {_rules[i] = new Rule()};
	
	this.getNr = function() {
		
		return _rules[0].getSid();
	}
	
	

}

function Rule() {
	var _sid = 1;
	
	this.getSid = function() {
		
		return _sid;
	}
}