	{% csrf_token %}
	<table id="userList" class="users table table-striped table-responsive table-bordered">
		
		<thead>
			<tr>
				<th><input type="checkbox" id="checkbox-all" /></th>
				<th class="text-center">Username</th>
				<th class="text-center">Name</th>
				<th class="text-center">Email</th>
				<th class="text-center">Role</th>
				<th class="text-center"></th>
			</tr>
		</thead>
		
		<tbody>
			{% for userItem in users %}
				<tr id="{{userItem.id}}">
					<td><input id="checkbox" type="checkbox" user="{{userItem.id}}" loginuser="{{user.id}}" /></td>
					<td class="text-center">{{ userItem.username}}</td>
					<td class="text-center">{{ userItem.first_name }} {{ userItem.last_name }}</td>
					<td class="text-center">{{ userItem.email }}</td>
					<td class="text-center">
						{% if userItem.is_staff %}
							<span class="badge btn-success">Admin</span>
						{% else %}
							<span class="badge">User</span>
						{% endif %}
					</td>
					<td class="text-right">
						<button id="resetPassword" user="userItem" class="btn btn-danger"  data-toggle="modal" data-target="#resetPasswordModal">Reset Password</button>
					</td>
				</tr>
			{% endfor %}
		</tbody>
	</table>

