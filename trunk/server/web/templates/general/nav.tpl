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
			<a class="navbar-brand" href="/web/">Snowman&trade;</a>
		</div>
		<div class="navbar-collapse collapse">
			<ul class="nav navbar-nav">
				<li><a href="/web/">Dashboard</a></li>
				<li class="dropdown">
					<a href="/web/rules/" class="dropdown-toggle" data-toggle="dropdown">Rules <b class="caret"></b></a>
					<ul class="dropdown-menu">
					<li class=""><a href="/web/rules/">All Rules</a></li>
					<li><a href="/web/ruleSet/">By Set</a></li>
					<li><a href="/web/ruleClass/">By Class</a></li>
					</ul>
				</li>
				<li><a href="/web/sensors/">Sensors</a></li>
				<li><a href="/web/tuning/">Tuning</a></li>
				<li class="dropdown">
					<a href="/web/update/" class="dropdown-toggle" data-toggle="dropdown">Update <b class="caret"></b></a>
					<ul class="dropdown-menu">
						<li class=""><a href="/web/update/">Update</a></li>
						<li><a href="/web/update/changes/">Changes</a></li>
					</ul>
				</li>
				{% if user.is_staff %}<li><a href="/web/users/">User Administration</a></li>{% endif %}
			</ul>
			<div class="btn-group pull-right">
				<button id="syncAllSensors" class="btn btn-success">Sync All Sensors</button>
				{% if user.is_authenticated %}<button id="logOut" class="btn btn-warning">Logout</button>{% endif %}
			</div>
		</div>
		
	</div>
</div>
