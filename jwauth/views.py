from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .serializers import UserSerializer, TaskSerializer
from .models import User, Tasks
import jwt
import datetime
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi 
from django.forms.models import model_to_dict

def get_payload(request):
    token = request.COOKIES.get('jwt')
    if not token:
        raise AuthenticationFailed('Unauthenticated!')

    try:
        payload = jwt.decode(token, 'secret', algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Unauthenticated!')
    return payload

class TaskView(APIView):
    pk = openapi.Parameter('pk', openapi.IN_FORM,
                             description="field you want to order by to",
                             type=openapi.TYPE_INTEGER)
    @swagger_auto_schema(
        request_body=openapi.Schema(
            manual_parameters=[pk],
            type=openapi.TYPE_OBJECT,
            properties={
                # 'id': openapi.Schema(type=openapi.TYPE_INTEGER, description='Task ID to edit'),
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
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)        

    def get(self, request):
        payload = get_payload(request=request)
        tasks = Tasks.objects.filter(username=payload['username']).values()
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
            "username": User.objects.filter(username=payload['username']).first(),
            "taskname": request.data['taskname'],
            "completion": request.data['completion'],
        }
        serializer = TaskSerializer(
            data=req_data
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


# Create your views here.
class RegisterView(APIView):
    @swagger_auto_schema(request_body=UserSerializer)
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


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
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = User.objects.filter(username=payload['username']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data['username'])


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'success'
        }
        return response