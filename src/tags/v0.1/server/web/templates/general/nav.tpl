{# This is the navigational bar of the website. #}
<div class="navbar navbar-default no-radius">
	<div class="container">
		<div class="navbar-header">
			<button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">
				<span class="sr-only">Toggle navigation</span>
				<span class="icon-bar"></span>
				<span class="icon-bar"></span>
				<span class="icon-bar"></span>
			</button>
			<a class="navbar-brand" href="/web/">Snort&reg; Rule Manager</a>
		</div>
		<div class="navbar-collapse collapse">
			<ul class="nav navbar-nav">
				<li><a href="/web/">Dashboard</a></li>
				<li class="dropdown">
					<a href="/web/rules/" class="dropdown-toggle" data-toggle="dropdown">Rules <b class="caret"></b></a>
					<ul class="dropdown-menu">
					<li class=""><a href="/web/rules/">All Rules</a></li>
					<li><a href="/web/ruleset/">By Set</a></li>
					<li><a href="/web/ruleclass/">By Class</a></li>
					</ul>
				</li>
				<li class=""><a href="/web/sensors/">Sensors</a></li>
				 <li class="dropdown">
					<a href="/web/tuning/" class="dropdown-toggle" data-toggle="dropdown">Tuning <b class="caret"></b></a>
					<ul class="dropdown-menu">
					<li class=""><a href="/web/tuning/bysensor/">Sensors</a></li>
					<li><a href="/web/tuning/byrule/">Rules</a></li>
					</ul>
				</li>
				<li><a href="/web/update/">Update</a></li>
			</ul>
		</div>
	</div>
</div>