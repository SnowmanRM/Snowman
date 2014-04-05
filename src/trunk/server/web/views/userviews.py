
from django.http import HttpResponse
from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
import json


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