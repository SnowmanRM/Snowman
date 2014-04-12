<p>Please use the form below, to create a new update-source:</p>
{% if warningmessage %}<p>{{warningmessage}}</p>{% endif %}

{% if newSourceForm %}
	<form id="createSourceForm" action="/web/update/newSource/" method="post">
		{% csrf_token %}
		{{ newSourceForm.as_p }}
		<div id='TimeSelector'>
			{% if timeSelector %}
				{{ timeSelector.as_p }}
			{% endif %}
		</div>
		<input type="submit" value="Submit" />
	</form>
{% endif %}
