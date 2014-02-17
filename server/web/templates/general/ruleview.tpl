{% extends "general/index.tpl" %}

{% block content %}
<ul id="rule-list" class="container">
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
</ul>

{% if rule_list %}
    <ul>
    {% for rulerev in rule_list %}
        <li><a href="#">{{ rulerev.rule.SID }}</a></li>
    {% endfor %}
    </ul>
{% else %}
    <p>No rules are available.</p>
{% endif %}

{% endblock %}

{% block manipulator %}
<ul>
	<li><a href="#" class="selected">Enable</a></li>
	<li><a href="#">Disable</a></li>
	<li><a href="#">Treshold</a></li>
	<li><a href="#">Suppress</a></li>
	<li><a href="#">Comment</a></li>
</ul>
{% endblock %}