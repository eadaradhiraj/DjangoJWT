from rest_framework.views import APIView, View
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import AuthenticationFailed
from .serializers import ( 
    UserSerializer,
    # EmailVerificationSerializer,
    TaskSerializer,
    TaskPostSerializer,
    ResetPasswordRequestSerializer,
    SetNewPasswordSerializer,
    SetNewPasswordKnownSerializer
)
from .models import User, Tasks
import jwt
import os
from django.http import HttpResponsePermanentRedirect
from django.contrib.auth import get_user_model

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import (
    smart_str,
    force_str,
    smart_bytes,
    DjangoUnicodeDecodeError,
    force_bytes
)
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
import datetime
from django.urls import reverse
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi 
from rest_framework import permissions
from rest_framework.decorators import permission_classes


class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = ['http', 'https']

def get_payload_from_token(token):
    # token = request.META.get('HTTP_AUTHORIZATION')
    if not token:
        raise AuthenticationFailed('Unauthenticated!')
    try:
        payload = jwt.decode(token, 'secret', algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Unauthenticated!')
    return payload

def get_user_obj(request):
    return User.objects.get(
        username=get_payload_from_token(
            request.META.get('HTTP_AUTHORIZATION')
        ).get('username')
    )

class TaskPostView(APIView):
    @swagger_auto_schema()       
    def get(self, request):
        user_obj = get_user_obj(request)
        tasks = Tasks.objects.filter(username=user_obj).values()
        return Response(tasks)
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'taskname': openapi.Schema(type=openapi.TYPE_STRING, description='Add taskname'),
                'completion': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='completion', default=False),
            }
        )
    )
    def post(self, request):
        req_data = {
            "username": get_user_obj(request).id,
            "taskname": request.data['taskname'],
            "completion": request.data['completion'],
        }
        serializer = TaskPostSerializer(
            data=req_data
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class TaskView(APIView):
    @swagger_auto_schema()       
    def get(self, request, pk):
        tasks = Tasks.objects.filter(
            id=pk,
            username=get_user_obj(request)
        ).values()
        return Response(tasks, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'taskname': openapi.Schema(type=openapi.TYPE_STRING, description='Add taskname'),
                'completion': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='completion'),
            }
        )
    )
    def patch(self, request, pk):
        task = Tasks.objects.get(id=pk)
        serializer = TaskSerializer(
            task,
            data=request.data | {'username':get_user_obj(request).id},
            partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema()
    def delete(self, request, pk):
        try:
            task = Tasks.objects.get(id=pk, username=get_user_obj(request))
            task.delete()
            return Response(status=status.HTTP_200_OK)
        except:
            return Response(status=status.HTTP_404_NOT_FOUND)

class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
                str(user.is_active) + str(user.pk) + str(timestamp)
        )


email_verification_token = EmailVerificationTokenGenerator()

# Create your views here.
class RegisterView(APIView):
    @swagger_auto_schema(request_body=UserSerializer)
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(username=user_data['username'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        # relativeLink = reverse('email-verify')
        # absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
        # data = {'token':str(token), 'current_site':current_site}
        data = {
            'domain': current_site,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': email_verification_token.make_token(user),
        }
        return Response(data, status=status.HTTP_201_CREATED)

class RequestPasswordReset(generics.GenericAPIView):
    serializer_class = ResetPasswordRequestSerializer
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Add email'),
            }
        )
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data.get('email', '')
        if User.objects.filter(username=email).exists():
            user = User.objects.get(username=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            # relativeLink = reverse(
            #     'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            # redirect_url = request.data.get('redirect_url', '')
            # absurl = 'http://'+current_site + relativeLink
            # email_body = 'Hello, \n Use link below to reset your password  \n' + \
            #     absurl+"?redirect_url="+redirect_url
            # data = {'email_body': email_body, 'to_email': user.email,
            #         'email_subject': 'Reset your passsword'}
            return Response({'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)
        return Response({'msg': "User not found"}, status=status.HTTP_422_UNPROCESSABLE_ENTITY)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)

class VerifyEmail(APIView):
    def get_user_from_email_verification(self, uidb64:str, token: str):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.get(pk=uid)
        except:
            raise AuthenticationFailed('Incorrect token!')

        if user is not None \
                and \
                email_verification_token.check_token(user, token):
            return user
        raise AuthenticationFailed("User Not Found!")
    @swagger_auto_schema()
    def get(self, request, uidb64, token):
        user = self.get_user_from_email_verification(uidb64, token)
        user.is_verified = True
        user.save()
        return Response(
            {'success':True},
            status=status.HTTP_200_OK
        )

class LoginView(APIView):
    @swagger_auto_schema(request_body=UserSerializer)
    def post(self, request):
        username = request.data['username']
        password = request.data['password']

        user = User.objects.filter(username=username).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'username': user.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, "secret", algorithm="HS256")

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }
        return response


class UserView(APIView):
    def get(self, request):
        user = get_user_obj(request)
        serializer = UserSerializer(user)
        return Response(serializer.data)

class SetNewPasswordKnownAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordKnownSerializer
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'old_password': openapi.Schema(type=openapi.TYPE_STRING, description='Add old_password'),
                'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='Add new_password_again'),
                'new_password_again': openapi.Schema(type=openapi.TYPE_STRING, description='Add new_password_again'),                                
            }
        )
    )
    def patch(self, request):
        user = get_user_obj(request=request)
        if request.data.get("new_password")!=request.data.get("new_password_again"):
            return Response("New password not matching!", status=status.HTTP_400_BAD_REQUEST)
        if not user.check_password(request.data.get("old_password")):
            return Response("Old password wrong!", status=status.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user.set_password(request.data.get("new_password"))
            user.save()
            return Response("Password changed successfully", status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'success'
        }
        return response