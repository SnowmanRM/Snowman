function listInitialize() {
	
$(".ruleswitch").bootstrapSwitch()
	
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

function getFirstPages(pagedivisor) {
	
	var _pagedivisor = pagedivisor;
	
	var _page2, _page3, _page4;
	
	$.when(
			$.get('getrulelistrange/'+_pagedivisor+'/'+_pagedivisor*2+'/', function(html) { 
				_page2 = $('ul', $('<div/>').html(html)).hide().attr("id","2").parent().html(); 
				}),
			$.get('getrulelistrange/'+_pagedivisor*2+'/'+_pagedivisor*3+'/', function(html) { 
				_page3 = $('ul', $('<div/>').html(html)).hide().attr("id","3").parent().html(); 
				}),
			$.get('getrulelistrange/'+_pagedivisor*3+'/'+_pagedivisor*4+'/', function(html) { 
				_page4 = $('ul', $('<div/>').html(html)).hide().attr("id","4").parent().html(); 
				})	
	
	).done(function() {
			
			$('#content').append(_page2).append(_page3).append(_page4);
			listInitialize();
	
	});
	
	
	
	
	
}

function getLastPage(pagecount, ruleitems, pagedivisor) {
	var _lastpage;
	
	_minrange = pagecount * pagedivisor;
	_maxrange = (ruleitems % pagecount) + _minrange;
	
	$.when( 
	
			$.get('getrulelistrange/'+_minrange+'/'+_maxrange+'/', function(html) { 
		
				_lastpage = $('ul', $('<div/>').html(html)).hide().attr("id",pagecount).parent().html(); 
		
			})
	).then(function() {
		
		$('#content').append(_lastpage);
		listInitialize();
	
	});
}

function getPage(pagenr, pagedivisor, pagecount){
	
	var _page;
	
	_minrange = pagecount * pagedivisor;
	_maxrange = (ruleitems % pagecount) + _minrange;
	
	$.when( 
	
		$.get('getrulelistrange/'+_minrange+'/'+_maxrange+'/', function(html) { 
	
			_lastpage = $('ul', $('<div/>').html(html)).hide().attr("id",pagenr).parent().html(); 
	
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
	var currentpage = 1;
	
	
	getFirstPages(pagedivisor);
	getLastPage(pagecount, ruleitems, pagedivisor);
	
	//$('#footer').append("<p>"+foo.getNr()+"</p>");
	
	
	listInitialize();
	
	var options = {
		currentPage: currentpage,
		totalPages: pagecount,
		numberOfPages: 3,
		bootstrapMajorVersion: 3,
		onPageClicked: function(e,originalEvent,type,page){
			
			console.log(currentpage + page);
			$('#content ul.current').hide().toggleClass('current');
			$('#content ul#'+page).show("fast","swing").toggleClass('current');
			
			for(var i=1;i<=3;i++) {
				if ($('#content ul#'+page+i).length == 0)
					getPage(page+i, pagedivisor, pagecount);
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
