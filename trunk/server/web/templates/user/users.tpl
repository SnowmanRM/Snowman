{% extends "general/index.tpl" %}

{% block content %}
	{% load staticfiles %}
	<script type="text/javascript" src="{% static 'js/users.js' %}"></script>
	{% csrf_token %}
	
	<div id="manipulator" class="col-xs-2 col-sm-2 col-md-2">
		<div class="button-container well">
			<div class="btn-group-vertical btn-block">
				<button class="btn btn-success" data-toggle="modal" data-target="#createUserModal" id="create">Add User</button>
				<button class="btn btn-info" data-toggle="modal" data-target="#editUserModal" id="edit">Edit User</button>
				<button class="btn btn-danger" data-toggle="modal" data-target="#deleteUserModal" id="delete"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Delete User</button>
			</div>
		</div>
	</div>
	
	
	<div class="modal fade" id="createUserModal" tabindex="-1" role="dialog" aria-labelledby="createUserModal" aria-hidden="true">
		<div class="modal-dialog">
			<div class="modal-content">
				<form id="createUserForm" class="form-horizontal" target="" method="post">
					<div class="modal-header">
						<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
						<h4 class="modal-title" id="createUserModal">Create User</h4>
					</div>
					<div class="modal-body">
						
						<div id="formContent">
						
						</div>
					</div>
					<div class="modal-footer">
						<button type="button" class="btn btn-default" data-dismiss="modal" id="create-close">Close</button>
						<button type="submit" class="btn btn-primary" id="create-submit">Save changes</button>
					</div>
				</form>
			</div>
		</div>
	</div>
	
	<div class="modal fade" id="editUserModal" tabindex="-1" role="dialog" aria-labelledby="editUserModal" aria-hidden="true">
	  <div class="modal-dialog">
	    <div class="modal-content">
	      <div class="modal-header">
			   <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
			   <h4 class="modal-title" id="editUserModal">Edit User</h4>
			 </div>
			<div class="modal-body">
			  <form id="editUserForm" class="form-horizontal" role="form">
			  	<div id="formContent">
			  		
			  	</div>
			</div>
			<div class="modal-footer">
			  <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
			  <button type="submit" class="btn btn-primary" id="edit-submit" name="edit-submit">Save changes</button>
			  </form>
			</div>
	      
	    </div>
	  </div>
	</div>
	
	<div class="modal fade" id="resetPasswordModal" tabindex="-1" role="dialog" aria-labelledby="resetPasswordModal" aria-hidden="true">
	  <div class="modal-dialog">
	    <div class="modal-content">
	      <div class="modal-header">
			   <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
			   <h4 class="modal-title" id="resetPasswordModal">Reset Password</h4>
			 </div>
			<div class="modal-body">
			  <form id="resetPasswordForm" class="form-horizontal" role="form">
			  	<div id="formContent">
			  		
			  	</div>
			</div>
			<div class="modal-footer">
			  <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
			  <button type="submit" class="btn btn-primary" id="reset-submit" name="reset-submit">Save changes</button>
			  </form>
			</div>
	      
	    </div>
	  </div>
	</div>
	
	<div class="modal fade" id="deleteUserModal" tabindex="-1" role="dialog" aria-labelledby="deleteUserModal" aria-hidden="true">
	  <div class="modal-dialog">
	    <div class="modal-content">
	      <div class="modal-header">
			   <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
			   <h4 class="modal-title" id="deleteUserModal">Delete Users</h4>
			 </div>
			<div class="modal-body">
			  <form id="deleteUserForm" class="form-horizontal" role="form">
			  	<div id="formContent">
			  	{% csrf_token %}
			  		<div class="alert alert-danger row">
			  			<div class="col-sm-1">
			  			<span class="glyphicon glyphicon-warning-sign"></span>
			  			</div>
			  			<div class="col-sm-11">
			  				<strong>Are you absolutely sure you want to delete the Users? 
			  				<br /><br />This cannot be reversed!</strong>
			  			</div>
			  		</div>
			  	</div>
			</div>
			<div class="modal-footer">
			  <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
			  <button type="submit" class="btn btn-danger" id="delete-submit" name="delete-submit"><span class="glyphicon glyphicon-warning-sign form-control-feedback"></span> Delete Users</button>
			  </form>
			</div>
	      
	    </div>
	  </div>
	</div>

	<div id="content" class="users col-xs-10 col-sm-10 col-md-10 pull-right well">
		
		{% include "user/userList.tpl" %}
			
	</div>
{% endblock %}
