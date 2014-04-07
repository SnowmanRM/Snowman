{% csrf_token %}
<div class="form-group" id="password">
	<label for="email" class="col-sm-2 control-label">Password:</label>
	<div class="col-sm-10">
		<input type="password" class="form-control" id="password" name="password" required/>
	</div>
</div>
<div class="form-group" id="passwordConfirm">
	<label for="passwordConfirm" class="col-sm-2 control-label">Confirm password:</label>
	<div class="col-sm-10">
		<input type="password" class="form-control" id="passwordConfirm" name="passwordConfirm" required/>
	</div>
</div>