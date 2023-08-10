from rest_framework.views import APIView
from rest_framework import authentication, permissions, generics, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed
from .serializers import ( 
    UserSerializer,
    EmailVerificationSerializer,
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
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.conf import settings
from django.contrib.sites.shortcuts import get_current_site
import datetime
from django.urls import reverse
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi 
from django.forms.models import model_to_dict
from .utils import Util

class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = ['http', 'https']


def get_payload(request):
    token = request.COOKIES.get('jwt')
    if not token:
        raise AuthenticationFailed('Unauthenticated!')

    try:
        payload = jwt.decode(token, 'secret', algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Unauthenticated!')
    return payload

class TaskPostView(APIView):
    authentication_classes = (authentication.TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)
    @swagger_auto_schema()       
    def get(self, request):
        payload = get_payload(request=request)
        tasks = Tasks.objects.filter(username=payload['email']).values()
        return Response(tasks)
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'taskname': openapi.Schema(type=openapi.TYPE_STRING, description='Add taskname'),
                'completion': openapi.Schema(type=openapi.TYPE_BOOLEAN, description='completion'),
            }
        )
    )
    def post(self, request):
        payload = get_payload(request=request)
        req_data = {
            "username": User.objects.filter(username=payload['email']).first(),
            "taskname": request.data['taskname'],
            "completion": request.data['completion'],
        }
        serializer = TaskPostSerializer(
            data=req_data
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

class TaskView(APIView):
    @swagger_auto_schema()       
    def get(self, request, pk):
        payload = get_payload(request=request)
        tasks = Tasks.objects.filter(id=pk).values()
        return Response(tasks)

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
        payload = get_payload(request=request)
        task = Tasks.objects.filter(id=pk, username=payload['username']).first()
        serializer = TaskSerializer(task, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema()
    def delete(self, request, pk):
        payload = get_payload(request=request)
        try:
            task = Tasks.objects.get(id=pk, username=payload['username'])
            task.delete()
            return Response(status=status.HTTP_200_OK)
        except:
            return Response(status=status.HTTP_404_NOT_FOUND)


# Create your views here.
class RegisterView(APIView):
    @swagger_auto_schema(request_body=UserSerializer)
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')
        absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
        email_body = 'Hi '+user.email + \
            ' Use the link below to verify your email \n' + absurl
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Verify your email'}

        Util.send_email(data)
        return Response(user_data, status=status.HTTP_201_CREATED)

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

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
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


# class PasswordTokenCheckAPI(generics.GenericAPIView):
#     serializer_class = SetNewPasswordSerializer
#     @swagger_auto_schema(request_body=SetNewPasswordSerializer)
#     def get(self, request, uidb64, token):
#         redirect_url = request.GET.get('redirect_url')
#         try:
#             id = smart_str(urlsafe_base64_decode(uidb64))
#             user = User.objects.get(id=id)
#             if not PasswordResetTokenGenerator().check_token(user, token):
#                 if len(redirect_url) > 3:
#                     return CustomRedirect(redirect_url+'?token_valid=False')
#                 else:
#                     return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')
#             if redirect_url and len(redirect_url) > 3:
#                 return CustomRedirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
#             else:
#                 return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')
#         except DjangoUnicodeDecodeError as identifier:
#             try:
#                 if not PasswordResetTokenGenerator().check_token(user):
#                     return CustomRedirect(redirect_url+'?token_valid=False')
#             except UnboundLocalError as e:
#                 return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class VerifyEmail(APIView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    @swagger_auto_schema(request_body=UserSerializer)
    def post(self, request):
        username = request.data['email']
        password = request.data['password']

        user = User.objects.filter(email=username).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'username': user.email,
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
        payload = get_payload(request=request)
        user = User.objects.filter(email=payload['username']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data)

class SetNewPasswordKnownAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordKnownSerializer
    def patch(self, request):
        payload = get_payload(request=request)
        user = User.objects.filter(email=payload['username']).first()
        if request.data.get("new_password")!=request.data.get("new_password_again"):
            return Response("New password not matching!", status=status.HTTP_400_BAD_REQUEST)
        if not user.check_password(request.data.get("old_password")):
            return Response("Old password wrong!", status=status.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user.set_password(request.data.get("new_password"))
            user.save()
            return Response("Password changed successfully", status=status.HTTP_200_OK)
        # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'success'
        }
        return response