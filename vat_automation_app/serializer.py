from .models import *
from rest_framework import serializers


class CategorySetupSerializer(serializers.ModelSerializer):
    class Meta:
        model = CategorySetup
        fields = '__all__'


class CategorySetupUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CategorySetup
        exclude = ('id',)


class CustomLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def validate(self, data):
        email = data.get('email', '')
        password = data.get('password', '')
        user = get_adapter().authenticate(self.context.get('request'), email=email, password=password)
        if not user:
            raise serializers.ValidationError('Invalid email or password.')
        data['user'] = user
        return data

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['name'] = user.name
        token['email'] = user.email
        token['is_superuser'] = user.is_superuser
        token['is_staff'] = user.is_staff

        return token


class SlabSerializer(serializers.ModelSerializer):
    class Meta:
        model = Slab
        fields = '__all__'
