from django.shortcuts import render
from rest_framework.views import APIView

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializer import *
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from django.db.models import F
from rest_framework.response import Response
from rest_framework import generics, status
from django.shortcuts import get_object_or_404
from datetime import datetime, timedelta
import random
import string
from django.core.mail import send_mail


# Create your views here.
class CategorySetupCreateView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        serializer = CategorySetupSerializer(data=request.data)
        sequence = request.data.get("sequence")
        CategorySetup.objects.filter(category_name=request.data.get('category_name'), sequence__gte=sequence).update(
            sequence=F('sequence') + 1)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CategorySetupListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, category_name):
        category_setup = CategorySetup.objects.filter(category_name=category_name).order_by('sequence')
        serializer = CategorySetupSerializer(category_setup, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CategorySetupRetrieveView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request, category_name, description):
        category_setup = CategorySetup.objects.filter(category_name=category_name, description=description).first()
        serializer = CategorySetupSerializer(category_setup)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, category_name, description):
        category_setup = CategorySetup.objects.get(category_name=category_name, description=description)
        serializer = CategorySetupUpdateSerializer(category_setup, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, category_name, description):
        category_setup = get_object_or_404(CategorySetup, category_name=category_name, description=description)

        CategorySetup.objects.filter(category_name=category_name, sequence__gt=category_setup.sequence).update(
            sequence=F('sequence') - 1)

        category_setup.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomLoginSerializer


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(str(e), status=status.HTTP_400_BAD_REQUEST)


class SlabCreateView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        serializer = SlabSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SlabListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        slab = Slab.objects.all()
        serializer = SlabSerializer(slab, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class SlabRetrieveView(APIView):
    permission_classes = [IsAdminUser]

    def get_slab(self, slab_id):
        try:
            return Slab.objects.get(pk=slab_id)
        except Slab.DoesNotExist:
            return None

    def get(self, request, slab_id):
        slab = self.get_slab(slab_id)
        if not slab:
            return Response("No slab found with this id", status=status.HTTP_404_NOT_FOUND)
        serializer = SlabSerializer(slab)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, slab_id):
        slab = self.get_slab(slab_id)
        if not slab:
            return Response("No slab found with this email", status=status.HTTP_404_NOT_FOUND)
        serializer = SlabSerializer(slab, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, slab_id):
        slab = self.get_slab(slab_id)
        if not slab:
            return Response("No slab found with this email", status=status.HTTP_404_NOT_FOUND)
        slab.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CustomUserCreateView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = (AllowAny,)


class OTPVerificationView(generics.CreateAPIView):
    permission_classes = (AllowAny,)

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return OTPVerificationSerializer

    def post(self, request, *args, **kwargs):
        otp_token = request.data.get('otp_token')
        id = kwargs.get('id')  # Assuming you pass the user ID as a URL parameter

        try:
            otp = OTP.objects.get(user__id=id, token=otp_token, expire_time__gte=datetime.now())
        except OTP.DoesNotExist:
            return Response({"message": "Invalid OTP or OTP expired"}, status=status.HTTP_400_BAD_REQUEST)

        # If OTP is valid, activate the user or perform any other required action
        user = CustomUser.objects.get(id=id)
        user.is_active = True
        user.email_verified = True
        user.save()

        # Optionally, delete the OTP entry once it's verified and used
        otp.delete()

        return Response({"message": "Account activated successfully"}, status=status.HTTP_200_OK)


class OTPResendView(generics.CreateAPIView):
    serializer_class = OTPResendSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        id = request.data.get('id')  # Get the username from the request data

        try:
            user = CustomUser.objects.get(id=id)
        except CustomUser.DoesNotExist:
            return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Generate and save new OTP
        otp = self.generate_otp()
        self.save_otp(user, otp)

        # Send new OTP via email
        self.send_otp_email(user, otp)

        return Response({"message": "New OTP sent successfully"}, status=status.HTTP_200_OK)

    def generate_otp(self):
        digits = string.digits
        otp = ''.join(random.choice(digits) for i in range(5))
        return otp

    def save_otp(self, user, otp):
        otp_expiry = datetime.now() + timedelta(minutes=15)
        OTP.objects.create(token=otp, expire_time=otp_expiry, user=user)

    def send_otp_email(self, user, otp):
        current_site = get_current_site(self.request)
        mail_subject = 'Your New OTP'
        message = render_to_string('otp_email_template.html', {
            'user': user,
            'otp': otp,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        })
        to_email = user.email
        send_mail(mail_subject, message, 'your_email@example.com', [to_email])
