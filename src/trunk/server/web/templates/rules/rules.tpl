{% extends "general/index.tpl" %}


{% block content %}
{% load staticfiles %}
<script type="text/javascript" src="{% static 'js/functions.js' %}"></script>

{% block manipulator %}

{% include "general/manipulator.tpl" %}
		
{% endblock %}

<div id="content" class="col-xs-10 col-sm-10 col-md-10 pull-right well">

{% block rules %}

{% include "rules/rulepage.tpl" %}
		
{% endblock %}


</div>
<div class="pull-right clear">
	<ul id="paginator" itemcount="{{ itemcount }}" pagelength="{{ pagelength }}" class="pagination">
		
	</ul>
</div>


{% endblock %}

<li class="first"><input type="checkbox"><b>ATTACKS</b> - Attack Execution or Backtrace Rules</li>
	<li><input type="checkbox"><b>DOS</b> - Denial of Service Rules</li>
	<li class="selected"><input type="checkbox"><b>POLICY</b> - Enterprise Policy Violation Rules</li>
	<li class="sub">
		<ul id="rule-list" class="sub-rule">						
			<li class="first"><input type="checkbox"><b>CHAT</b></li>
			<li><input type="checkbox"><b>MULTIMEDIA</b></li>
			<li class="selected"><input type="checkbox"><b>P2P</b></li>
			<li class="sub">
				<ul id="rule-list" class="sub-rule">						
					<li class="first selected"><input type="checkbox"><b>ET P2P Bittorrent P2P Client User-Agent (BTSP)</b></li>
					<li><p>alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET P2P Bittorrent P2P Client User-Agent (BTSP)"; flow:to_server,established; content:"User-Agent|3a| BTSP/"; http_header; reference:url,doc.emergingthreats.net/2011713; classtype:policy-violation; sid:2011713; rev:4;)</p></li>
					<li class="selected"><input type="checkbox"><b>ET P2P ed2k connection to server</b></li>
					<li class="last"><p>alert tcp any any -> any 4660:4799 (msg:"ET P2P ed2k connection to server"; flow: to_server,established; content:"|e3|"; depth:1; content:"|00 00 00 01|"; distance:2; within:4; reference:url,www.giac.org/practical/GCIH/Ian_Gosling_GCIH.pdf; reference:url,doc.emergingthreats.net/bin/view/Main/2000330; classtype:policy-violation; sid:2000330; rev:13;)</p></li>
				</ul>
			</li>
			<li class="last"><input type="checkbox"><b>POLICY</b></li>
		</ul>
	</li>
	<li class="last"><input type="checkbox"><b>SQL</b> - Database Service Rules</li>