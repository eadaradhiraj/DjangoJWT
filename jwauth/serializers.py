from rest_framework import serializers
from .models import User, Tasks
from rest_framework.exceptions import AuthenticationFailed
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator


# class EmailVerificationSerializer(serializers.ModelSerializer):
#     token = serializers.CharField(max_length=555)
#     class Meta:
#         model = User
#         fields = ['token']

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tasks
        fields = ['username', 'taskname', 'completion']

class TaskPostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tasks
        fields = ['username', 'taskname', 'completion']

class SetNewPasswordKnownSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        write_only=True
    )
    new_password = serializers.CharField(
        write_only=True
    )
    new_password_again = serializers.CharField(
        write_only=True
    )
    class Meta:
        fields = ['old_password', 'new_password', 'new_password_again']

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)


class ResetPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email']

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance