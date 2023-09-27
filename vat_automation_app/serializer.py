from .models import *
from rest_framework import serializers
from datetime import datetime, timedelta
import random
import string
from django.core.mail import send_mail


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


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'full_name', 'email', 'password', 'phone_number')
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = CustomUser.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()

        # Generate and save OTP
        otp = self.generate_otp()
        self.save_otp(user, otp)

        # Send OTP via email (as shown in the previous response)
        self.send_otp_email(user, otp)  # New line to call the email sending function

        return user

    def generate_otp(self):
        digits = string.digits
        otp = ''.join(random.choice(digits) for i in range(5))
        return otp

    def save_otp(self, user, otp):
        otp_expiry = datetime.now() + timedelta(minutes=15)
        OTP.objects.create(token=otp, expire_time=otp_expiry, user=user)

    def send_otp_email(self, user, otp):
        subject = 'Your OTP Code'
        message = f'Your OTP code is: {otp}'
        from_email = 'email'  # Replace with your sender email
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)


class OTPVerificationSerializer(serializers.Serializer):
    otp_token = serializers.CharField(max_length=8)


class OTPResendSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
