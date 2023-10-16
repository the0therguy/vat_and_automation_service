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
    path('api/v1/verify-otp/<str:username>/', OTPVerificationView.as_view(), name='otp_verification_view'),
    path('api/v1/resend-otp/<int:id>/', OTPResendView.as_view(), name='resend_otp'),
    path('api/v1/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('api/v1/personal-details/', PersonalDetailsView.as_view(), name='personal-details'),
    path('api/v1/transaction/', TransactionView.as_view(), name='transaction-view'),
    path('api/v1/password_reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),
    path('api/v1/salary-report/', SalaryReportView.as_view(), name='salary-report'),
    path('api/v1/asset-and-liability/', AssetAndLiabilityReportView.as_view()),
    path('api/v1/return/', ReturnView.as_view(), name='return-view'),
    path('api/v1/check-admin/', CheckAdmin.as_view(), name='check-admin'),
    path('api/v1/test/<int:amount>/', TestingView.as_view())
]
