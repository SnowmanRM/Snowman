<response>
	<id>{{id}}</id>
	<success>{{success}}</success>
	
	{% if message %}
		<message>{{message}}</message>
	{% endif %}
	
	{% if form %}
		<newform>
			{% csrf_token %}
			{{ form.as_p }}
			<div id='TimeSelector'>
				{% if timeSelector %}
					{{ timeSelector.as_p }}
				{% endif %}
			</div>
		</newform>
	{% endif %}
</response>
