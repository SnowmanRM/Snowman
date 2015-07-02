{% csrf_token %}
<div class="form-group" id="username">
	<label for="username" class="col-sm-2 control-label">Username:</label>
	<div class="col-sm-10">
		<input type="text" class="form-control" id="username" name="username" placeholder="Must be unique." required />
	</div>
</div>
<div class="form-group" id="firstName">
	<label for="firstName" class="col-sm-2 control-label">First name:</label>
	<div class="col-sm-10">
		<input type="text" class="form-control" id="firstName" name="firstName" placeholder="Optional" />
	</div>
</div>
<div class="form-group" id="lastName">
	<label for="lastName" class="col-sm-2 control-label">Last name:</label>
	<div class="col-sm-10">
		<input type="text" class="form-control" id="lastName" name="lastName" placeholder="Optional" />
	</div>
</div>
<div class="form-group" id="email">
	<label for="email" class="col-sm-2 control-label">Email:</label>
	<div class="col-sm-10">
		<input type="email" class="form-control" id="email" name="email" placeholder="Optional" />
	</div>
</div>
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
<div class="form-group" id="admin">
	<label for="admin" class="col-sm-2 control-label">Admin:</label>
	<div class="col-sm-10">
		<input type="checkbox" class="form-control" id="admin" name="admin"/>
	</div>
</div>