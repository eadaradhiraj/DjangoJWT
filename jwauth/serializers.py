from rest_framework import serializers
from .models import User, Tasks


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tasks
        fields = ['taskname', 'completion']

class TaskPostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tasks
        fields = ['username', 'taskname', 'completion']


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