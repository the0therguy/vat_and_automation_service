from django.urls import path, include
from .views import *
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)

urlpatterns = [
    path('api/v1/category-setup-create/', CategorySetupCreateView.as_view(), name='category-setup-create'),
    path('api/v1/category-setup-list/<str:category_name>/', CategorySetupListView.as_view(),
         name='category-setup-list'),
    path('api/v1/category-retrieve/<str:category_name>/<str:description>/', CategorySetupRetrieveView.as_view(),
         name='category-retrieve'),
    path('api/v1/signin/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/v1/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/v1/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('api/v1/logout/', LogoutView.as_view(), name='auth_logout'),
    path('api/v1/slab-create/', SlabCreateView.as_view(), name='slab-create'),
    path('api/v1/slab-list/', SlabListView.as_view(), name='slab-list'),
    path('api/v1/slab-retrieve/<int:slab_id>/', SlabRetrieveView.as_view(), name='slab-retrieve'),
    path('api/v1/signup/', CustomUserCreateView.as_view(), name='signup'),
    path('api/v1/verify-otp/<int:id>/', OTPVerificationView.as_view(), name='otp_verification_view'),
    path('api/v1/resend-otp/<int:id>/', OTPResendView.as_view(), name='resend_otp'),
    path('api/v1/change-password/', ChangePasswordView.as_view(), name='change-password'),
]
