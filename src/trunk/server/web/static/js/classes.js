


function Page(pagenr, lowobjects, highobjects, maxobjects) {
	var _pagenr = pagenr;
	var _lowobjects = lowobjects;
	var _highobjects = highobjects;
	var _maxobjects = maxobjects;
	var _rulerevs;
		
	this.start =  function() {
	//var rulerevs = new Array;
	return $.ajax({
		
		url: "getrulelistrange/"+_lowobjects+"/"+_highobjects+"/",
		dataType: "json"
	});
	
	}
	
	//console.log(_rulerevs)
	this.setrevs = function setrevs(revs) {
		
		_rulerevs = revs;
	}
	
	//for (var i=0; i<maxobjects;i++)  {_rules[i] = new Rule()};
	
	this.getNr = function() {
		
		return _rulerevs;
	}
	
	var x = 1;

}

function RuleRevision() {
	var _sid = 1;
	
	this.getSid = function() {
		
		return _sid;
	}
}