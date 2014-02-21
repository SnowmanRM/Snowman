function listInitialize() {
	
	$(".ruleswitch").bootstrapSwitch()
	
	$('.list-group li.odd').unbind('click');
	$('.list-group li.odd').click(function(event){
		//event.preventDefault();
		if($(event.target).is('.bootstrap-switch span')){
            event.preventDefault();
            return false;
        }
		$(this).toggleClass("active");
		$(this).next().slideToggle("fast","linear");
		//$(this).addClass('selected');	
		//$('#nav li a').addClass('selected');
	
	});
	
	$('#nav a').click(function(event){
		event.preventDefault();
		$('#nav a').removeClass('selected');
		$(this).addClass('selected');	
		//$('#nav li a').addClass('selected');
	
	});
	
	
}

function getFirstPages(nrofpages) {
	
	var _nrofpages = nrofpages;
	var _pages = new Array();
	var _ajax = new Array();
	
	//console.log(_page);
	
	for (var _i=1; _i <= nrofpages; _i++) {
		_ajax.push(
			$.get('getrulelist/'+_i+'/', function(html) { 
				_pages.push($('ul', $('<div/>').html(html)).hide().attr("id","2").parent().html()); 
			})
		);
	}
	
	
	$.when.apply($, _ajax).done(function() {
			
		for (page in _pages) {
			$('#content').append(_pages.pop());
			
		}
		listInitialize();
	});
	
	
	
	
	
}

function getLastPage(pagecount) {
	var _lastpage;
	
	var _pagecount = pagecount;
	
	$.when( 
	
			$.get('getrulelist/'+_pagecount+'/', function(html) { 
		
				_lastpage = $('ul', $('<div/>').html(html)).hide().attr("id",_pagecount).parent().html(); 
		
			})
	).then(function() {
		
		$('#content').append(_lastpage);
		listInitialize();
	
	});
}

function getPage(pagenr){
	
	var _page;
	
	var _pagenr = pagenr;
	
	
	$.when( 
	
		$.get('getrulelist/'+_pagenr+'/', function(html) { 
	
			_page = $('ul', $('<div/>').html(html)).hide().attr("id",pagenr).parent().html(); 
	
		})
	).then(function() {
		
		$('#content').append(_page);
		listInitialize();
	
	});
	
}


$(document).ready(function(){

	var pagedivisor = 10;
	var ruleitems = $('#paginator').attr('count');
	var pagecount =  Math.floor(ruleitems / pagedivisor);
	//console.log(ruleitems%pagecount);
	if (ruleitems%pagecount == 0) pagecount--;
	var currentpage = 1;
	
	
	getFirstPages(3);
	getLastPage(pagecount, ruleitems, pagedivisor);
	
	//$('#footer').append("<p>"+foo.getNr()+"</p>");
	
	
	listInitialize();
	
	var options = {
		currentPage: currentpage,
		totalPages: pagecount,
		numberOfPages: 3,
		bootstrapMajorVersion: 3,
		onPageClicked: function(e,originalEvent,type,page){
			
			//console.log(currentpage + page);
			$('#content ul.current').hide().toggleClass('current');
			$('#content ul#'+page).show().toggleClass('current');
			
			for(var i=-3;i<=3;i++) {
				if (page+i > 1 && page+i < pagecount) {
					var j = $('#content ul#'+(page+i)+'').length;
					console.log(j)
					if (!j) {
						console.log(j)
						getPage(page+i);
					}
				}
			}
			
			currentpage = page;
		}
	}

	$('#paginator').bootstrapPaginator(options);
	
	var el = $('#manipulator');
	var elpos_original = el.offset().top;
	$(window).scroll(function(){
	    var elpos = el.offset().top;
	    var windowpos = $(window).scrollTop();
	    var finaldestination = windowpos;
	    if(windowpos<elpos_original) {
	        finaldestination = elpos_original;
	        el.stop().animate({'top':0},500);
	    } else {
	        el.stop().animate({'top':finaldestination-elpos_original+10},500);
	    }
	});
	
});
