from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class User(AbstractUser):
    username=models.CharField(max_length=255,unique=True, primary_key=True)
    password=models.CharField(max_length=255)
    # email=models.CharField(max_length=255)

    USERNAME_FIELD='username'
    REQUIRED_FIELDS=[]
    