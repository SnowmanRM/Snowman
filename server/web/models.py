from django.db import models
from django.contrib.auth.models import User, Group

# Create your models here.
class UserProfile(models.Model):
	pageLength = models.IntegerField(default=25)
	user = models.OneToOneField(User, primary_key=True, related_name="userProfile")