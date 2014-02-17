<html>

<head>
<title>SRM</title>
<link type="text/css" rel="stylesheet" href="demo.css" media="screen">
<script type="text/javascript" src="jquery-1.11.0.js"></script>
<script type="text/javascript" src="demo.js"></script>
</head>
<body>
	<div id="wrap">
		<div id="content-wrapper" class="">
			<div id="nav" class="">
				<ul>
					<li><a href="/foo/bar" class="selected no-left-border">Nav1</a></li>
					<li><a href="#">Nav1</a></li>
					<li><a href="#">Nav1</a></li>
					<li><a href="#">Nav1</a></li>
				</ul>			
			</div>
			<div id="content-manipulator-wrap">
				<div id="manipulator">
					<ul>
						<li><a href="#" class="selected">Enable</a></li>
						<li><a href="#">Disable</a></li>
						<li><a href="#">Treshold</a></li>
						<li><a href="#">Suppress</a></li>
						<li><a href="#">Comment</a></li>
					</ul>
				</div>
				<div id="content">
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
				</div>		
			
				
			</div>
		</div>
		<div id="console-wrapper" class="">
			<div id="console-box" style="list-style-type: none;">				
				<li>I just did something ... 100%</li>
				<li>Currently working on ... 50%</li>	
			</div>
		</div>
	</div>

</body>

</html>
