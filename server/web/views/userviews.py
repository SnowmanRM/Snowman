
from django.http import HttpResponse
from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User, Group
import json, logging


def index(request):
	
	context = {}
	
	context['users'] = User.objects.order_by('is_staff').reverse().filter(groups__name="Users")
	
	return render(request, 'user/users.tpl', context)

def getCreateUserForm(request):
	
	return render(request, 'user/createUserForm.tpl')

def createUser(request):
	
	logger = logging.getLogger(__name__)
	response = []
	
	if(request.POST):
		
		if request.POST.get('username'):
			username = request.POST.get('username')
		else:
			logger.warning("No username was given.")
			response.append({'response': 'noName', 'text': 'No username was given.'})
			return HttpResponse(json.dumps(response))
		
		try:
			User.objects.get(username=username)
			response.append({'response': 'userExists', 'text': 'Username already exists, try another.'})
			return HttpResponse(json.dumps(response))
		except User.DoesNotExist:
		
			if request.POST.get('password'):
				password = request.POST.get('password')
			else:
				logger.warning("No password was given.")
				response.append({'response': 'noPassword', 'text': 'No password was given.'})
				return HttpResponse(json.dumps(response))
			
			if request.POST.get('firstName'):
				firstName = request.POST.get('firstName')
			else:
				firstName = None
				
			if request.POST.get('lastName'):
				lastName = request.POST.get('lastName')
			else:
				lastName = None
				
			if request.POST.get('email'):
				email = request.POST.get('email')
			else:
				email = None
				
			if request.POST.get('admin'):
				admin = True
			else:
				admin = False
		
			user = User.objects.create(username=username,first_name=firstName,last_name=lastName,email=email,is_staff=admin)
			user.set_password(password)
			user.save()
			
			group = Group.objects.get(name="Users")
			group.user_set.add(user)
			
			logger.info("User created: "+str(user)+"")
			response.append({'response': 'userSuccessfullyCreated', 'text': 'User was successfully created.'})
	else:
		logger.warning("No data was given in POST.")
		response.append({'response': 'noPOST', 'text': 'No data was given in POST.'})

	return HttpResponse(json.dumps(response))
	
	
def getResetPasswordForm(request):
	
	return render(request, 'user/resetPasswordForm.tpl')
	
def resetPassword(request):
	logger = logging.getLogger(__name__)
	response = []
	
	if request.POST:
	
		if request.POST.get('userid'):
			userID = request.POST.get('userid')
			
			if request.POST.get('password'):
				password = request.POST.get('password')
			else:
				logger.warning("No password was given in POST.")
				response.append({'response': 'noPassword', 'text': 'No password was given in POST.'})
				return HttpResponse(json.dumps(response))
			
			try:
				user = User.objects.get(id=userID)
				
				user.set_password(password)
				user.save()
				
				logger.info('Password reset for user '+str(user)+'')
				response.append({'response': 'passwordReset', 'text': 'Password successfully reset.'})
				
			except User.DoesNotExist:
				logger.warning("Could not find User with ID: "+str(userID)+".")
				response.append({'response': 'userDoesNotExist', 'text': 'The User ID does not exist.'})
				return HttpResponse(json.dumps(response)) 
			
		else:
			logger.warning("No User ID was given in POST.")
			response.append({'response': 'noPOST', 'text': 'No User ID was given in POST.'})
			return HttpResponse(json.dumps(response))
	else:
		logger.warning("No data was given in POST.")
		response.append({'response': 'noPOST', 'text': 'No data was given in POST.'})
	
	return HttpResponse(json.dumps(response))

def getEditUserForm(request):
	
	return HttpResponse(1)

def editUser(request):
	
	return HttpResponse(1)

def deleteUser(request):
	# We set up the logger and a few lists.
	logger = logging.getLogger(__name__)
	response = []
	
	# We check to see if there are sensor IDs given.
	if request.POST.getlist('userid'):
		userIDs = request.POST.getlist('userid')
	else:
		response.append({'response': 'noIDsGiven', 'text': 'No User ID was given, deletion cancelled.'})
		return HttpResponse(json.dumps(response))
	
	for userID in userIDs:
		try:
			user = User.objects.get(id=userID)
			
			logger.info("User "+str(user)+" has been deleted.")
			user.delete()
			
		except User.DoesNotExist:
			response.append({'response': 'userDoesNotExists', 'text': 'User ID '+userID+' could not be found.'})
			logger.warning("User ID "+str(userID)+" could not be found.")
			return HttpResponse(json.dumps(response))
	
	response.append({'response': 'userSuccessfulDeletion', 'text': 'Users was successfully deleted.'})
	return HttpResponse(json.dumps(response))

def getLoginForm(request):
	
	return render(request, 'user/loginForm.tpl')

def authenticateLogin(request):
	
	response = []
	
	if request.POST.get('username'):
		username = request.POST['username']
	else:
		response.append({'response':'noUsername', 'text': 'No username was provided in POST.'})
		return HttpResponse(json.dumps(response))
	if request.POST.get('password'):
		password = request.POST['password']
	else:
		response.append({'response':'noPassword', 'text': 'No password was provided in POST.'})
		return HttpResponse(json.dumps(response))
	
	try:
		User.objects.get(username=username)
	except User.DoesNotExist:
		response.append({'response':'userDoesNotExist', 'text': 'The username does not exist.'})
		return HttpResponse(json.dumps(response))
	
	user = authenticate(username=username, password=password)
	
	if user is not None:
		if user.is_active:
			login(request, user)
			response.append({'response':'loginSuccess'})
		else:
			response.append({'response':'inactiveUser', 'text': 'User is inactive.'})
			return HttpResponse(json.dumps(response))
	else:
		response.append({'response':'invalidPassword', 'text': 'Wrong password, try again.'})
		return HttpResponse(json.dumps(response))
	
	
	return HttpResponse(json.dumps(response))

def logoutUser(request):
	logout(request)
	
	return HttpResponse(1)