from django.shortcuts import render
from rest_framework.views import APIView

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializer import *
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from django.db.models import F
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404


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
