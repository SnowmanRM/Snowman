<form action="" method="post" enctype="multipart/form-data">
	{% csrf_token %}
	{{ manualUpdateForm.as_p }}
	<input type="submit" value="Submit" />
</form>
