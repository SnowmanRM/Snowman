<!DOCTYPE html>
<html style="height:100%;">
<head>
{% load staticfiles %}
	<link type="text/css" rel="stylesheet" href="{% static 'css/style.css' %}" media="screen">
	<link type="text/css" rel="stylesheet" href="{% static 'css/bootstrap/bootstrap.css' %}" media="screen">
	<link type="text/css" rel="stylesheet" href="{% static 'css/bootstrap/bootstrap-theme.css' %}" media="screen">
	<link type="text/css" rel="stylesheet" href="{% static 'css/bootstrap-switch/bootstrap-switch.css' %}" media="screen">
	<script type="text/javascript" src="{% static 'js/jquery/jquery-1.11.0.js' %}"></script>
	<script type="text/javascript" src="{% static 'js/jquery/jquery-ui-1.10.4.custom.js' %}"></script>
	<script type="text/javascript" src="{% static 'js/jquery/jquery.validate.js' %}"></script>
	<script type="text/javascript" src="{% static 'js/bootstrap/bootstrap.js' %}"></script>
	<script type="text/javascript" src="{% static 'js/bootstrap/bootstrap-paginator.js' %}"></script>
	<script type="text/javascript" src="{% static 'js/bootstrap/bootstrap-switch.js' %}"></script>
	<script type="text/javascript" src="{% static 'js/login.js' %}"></script>
</head>
<body style="height:100%;">
	<div id="loginContainer">
		<h1>Snowman</h1>
		<div id="loginFormContainer">
			<h3>Login</h3>
			<form id="loginForm" class="form-horizontal" role="form">
				{% csrf_token %}
				<div class="form-group" id="username">
					
					<label for="username" class="col-sm-4 control-label">Username:</label>
					<div class="col-sm-8">
						<input type="text" class="form-control" id="username" name="username" required />
					</div>
					
				</div>
				<div class="form-group" id="password">
					
					<label for="password" class="col-sm-4 control-label">Password:</label>
					<div class="col-sm-8">
						<input type="password" class="form-control" id="password" name="password" required />
					</div>
				
				</div>
				<div class="text-right">
					<button type="submit" class="btn btn-info">Login</button>
				</div>
			</form>
			
		</div>
		<div id="loginFooter" class="text-center">
			{% block footer %}
			{% include "general/footer.tpl" %}
			{% endblock %}
		</div>
	</div>
</body>
</html>