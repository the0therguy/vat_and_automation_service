from django.shortcuts import render
from rest_framework.views import APIView
import uuid
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
from decimal import Decimal
from .script import *
from django.conf import settings


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
    permission_classes = [IsAuthenticated]

    def get(self, request, category_name):
        category_setup = CategorySetup.objects.filter(category_name=category_name, active=True).order_by('sequence')
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
        username = kwargs.get('username')  # Assuming you pass the user ID as a URL parameter

        try:
            otp = OTP.objects.get(user__username=username, token=otp_token, expire_time__gte=datetime.now())
        except OTP.DoesNotExist:
            return Response({"message": "Invalid OTP or OTP expired"}, status=status.HTTP_400_BAD_REQUEST)

        # If OTP is valid, activate the user or perform any other required action
        user = CustomUser.objects.get(username=username)
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
        user_id = kwargs.get('id')  # Get the user ID from the URL

        try:
            user = CustomUser.objects.get(id=user_id)
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
        send_mail(mail_subject, message, settings.EMAIL_HOST_USER, [to_email])


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            old_password = serializer.data.get('old_password')
            new_password = serializer.data.get('new_password')

            # Check if the old password matches the current password
            if not check_password(old_password, request.user.password):
                return Response({"message": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

            # Change the password and save the user object
            request.user.set_password(new_password)
            request.user.save()
            create_user_activity({'action': 'update',
                                  'message': f"{request.user.username}'s password updated",
                                  'created_by': request.user})
            return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PersonalDetailsView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, user):
        try:
            return PersonalDetails.objects.get(user=user)
        except PersonalDetails.DoesNotExist:
            return None

    def get(self, request):
        personal_details = self.get_object(request.user)
        if not personal_details:
            return Response("No personal details found", status=status.HTTP_404_NOT_FOUND)
        serializer = PersonalDetailsSerializer(personal_details)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        if not request.user.email_verified:
            return Response('Email not verified', status=status.HTTP_400_BAD_REQUEST)
        request.data['user'] = request.user.id
        request.data['income_year_ended_on'] = datetime(datetime.now().year, 6, 30).date()
        request.data['assessment_year'] = str(datetime.now().year) + '-' + str(
            datetime.now().year + 1)[2:]
        request.data['email'] = request.user.email
        request.data['phone_number'] = request.user.phone_number
        serializer = PersonalDetailsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        personal_details = self.get_object(request.user)
        if not personal_details:
            return Response("No personal details found", status=status.HTTP_404_NOT_FOUND)
        serializer = PersonalDetailsUpdateSerializer(personal_details, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TransactionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        personal_details = PersonalDetails.objects.get(user=request.user)
        if not personal_details:
            return Response("No personal details found", status=status.HTTP_400_BAD_REQUEST)
        transaction = Transaction.objects.filter(user=request.user)
        serializer = TransactionSerializer(transaction, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        details = request.data.pop('details', None)
        try:
            personal_details = PersonalDetails.objects.get(user=request.user)
        except PersonalDetails.DoesNotExist:
            return Response("No personal details found", status=status.HTTP_400_BAD_REQUEST)

        request.data['user'] = request.user.id
        request.data['year'] = str(datetime.now().year) + '-' + str(
            datetime.now().year + 1)[2:]
        request.data['tin'] = personal_details.tin
        request.data['assess_name'] = personal_details.assess_name
        transaction = Transaction.objects.filter(**request.data)
        if not transaction:
            request.data['uuid'] = str(uuid.uuid4())
            transaction_serializer = TransactionSerializer(data=request.data)
            if not transaction_serializer.is_valid():
                return Response(transaction_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            transaction_serializer.save()
        else:
            transaction_serializer = TransactionSerializer(transaction)
        report, create = Report.objects.get_or_create(user=request.user, year=request.data['year'])
        details_data = []
        tax_amount = 0
        for index, detail in enumerate(details):
            detail['transaction'] = transaction_serializer.data.get('id')
            detail['transaction_row'] = index + 1

            detail_serializer = DetailsSerializer(data=detail)
            if not detail_serializer.is_valid():
                return Response(detail_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            if not detail['tax_exempted']:
                tax_amount += detail['amount']
            detail_serializer.save()
            details_data.append(detail_serializer.data)
        if request.data['category_name'] == 'Rebate':
            rebate = Decimal(min((report.taxable_income * Decimal(0.03)), tax_amount * 0.15, 100000))
            report.rebate = rebate
            report.save()
            transaction = Transaction.objects.get(id=transaction_serializer.data.get('id'))
            transaction.taxable_income = report.taxable_income
            transaction.save()
            return Response(details_data, status=status.HTTP_200_OK)
        slab_category = personal_details.are_you
        legal_guardian = personal_details.legal_guardian

        first_slab = Slab.objects.filter(select_one=slab_category).order_by('percentage').first()
        if request.data['category_name'] == 'Salary Private':
            tax_amount = tax_amount - min((tax_amount / 3.00),
                                          first_slab.amount + Decimal(
                                              50000.00) if legal_guardian else first_slab.amount)
        report.taxable_income += Decimal(tax_amount)
        net_tax, income_slab = tax_calculator(personal_details=personal_details,
                                              amount=report.taxable_income + Decimal(tax_amount))
        report.income_slab = income_slab
        report.net_tax = net_tax
        report.save()
        transaction = Transaction.objects.get(id=transaction_serializer.data.get('id'))
        transaction.taxable_income = report.taxable_income
        transaction.save()
        return Response(details_data, status=status.HTTP_200_OK)


class TestingView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, amount):
        print(amount)
        taxable_income = tax_calculator(personal_details=PersonalDetails.objects.get(user=request.user), amount=amount)
        print(taxable_income)

        return Response("Testing API", status=status.HTTP_200_OK)


class SalaryReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        personal_details = PersonalDetails.objects.get(user=request.user)
        if not personal_details:
            return Response("No personal details found", status=status.HTTP_400_BAD_REQUEST)
        salary_government_transaction = Transaction.objects.get(user=request.user,
                                                                year=str(datetime.now().year) + '-' + str(
                                                                    datetime.now().year + 1)[2:],
                                                                category_name='Salary Government')
        basic_info = {'Name of the Assess': salary_government_transaction.assess_name,
                      'TIN': salary_government_transaction.tin,
                      'government_taxable_income': salary_government_transaction.taxable_income}
        if not salary_government_transaction:
            return Response("No salary report found", status=status.HTTP_404_NOT_FOUND)
        government_details = Details.objects.filter(transaction=salary_government_transaction)
        if not government_details:
            return Response("No salary report found", status=status.HTTP_404_NOT_FOUND)
        government_details_serializer = DetailsSerializer(government_details, many=True)
        salary_private_transaction = Transaction.objects.get(user=request.user,
                                                             year=str(datetime.now().year) + '-' + str(
                                                                 datetime.now().year + 1)[2:],
                                                             category_name='Salary Private')
        if not salary_private_transaction:
            return Response("No salary report found", status=status.HTTP_404_NOT_FOUND)
        basic_info['private_taxable_income'] = salary_private_transaction.taxable_income
        private_details = Details.objects.filter(transaction=salary_private_transaction)
        if not private_details:
            return Response("No salary report found", status=status.HTTP_404_NOT_FOUND)

        private_details_serializer = DetailsSerializer(private_details, many=True)
        return Response(
            {'government_details': government_details_serializer.data,
             'private_details': private_details_serializer.data, 'basic_info': basic_info}, status=status.HTTP_200_OK)


class AssetAndLiabilityReportView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        assess_year = str(datetime.now().year) + '-' + str(datetime.now().year + 1)[2:]
        personal_details = PersonalDetails.objects.get(user=request.user)
        if not personal_details:
            return Response("Please fill personal details", status=status.HTTP_400_BAD_REQUEST)
        tin = personal_details.tin
        input_data = []
        for data in request.data:
            data['user'] = request.user.id
            data['assessment_year'] = assess_year
            data['tin'] = tin
            input_data.append(data)
        input_data_serializer = AssetAndLiabilitySerializer(data=input_data, many=True)
        if not input_data_serializer.is_valid():
            return Response(input_data_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        input_data_serializer.save()
        return Response(input_data_serializer.data, status=status.HTTP_200_OK)


class ReturnView(APIView):
    permission_classes = [IsAuthenticated]

    def get_transaction(self, category_name, user, year):
        try:
            return Transaction.objects.get(category_name=category_name, user=user, year=year)
        except Transaction.DoesNotExist:
            return None

    def get_report(self, user):
        try:
            return Report.objects.get(user=user)
        except Report.DoesNotExist:
            return None

    def get(self, request):
        personal_details = PersonalDetails.objects.get(user=request.user)
        if not personal_details:
            return Response("No personal details found", status=status.HTTP_400_BAD_REQUEST)
        return_details = {}
        assesment_year = str(datetime.now().year) + '-' + str(datetime.now().year + 1)[2:]
        return_details['Name of the Assessee'] = personal_details.assess_name
        return_details['TIN'] = personal_details.tin
        return_details['nid'] = personal_details.nid
        return_details['passport'] = personal_details.passport_number
        return_details['Assessment Year'] = assesment_year
        return_details['Circle'] = personal_details.circle
        return_details['Tax Zone'] = personal_details.tax_zone
        return_details['Resident Status'] = personal_details.resident_status
        return_details['tick_box'] = personal_details.are_you
        return_details['address'] = personal_details.address
        return_details['date_of_birth'] = personal_details.date_of_birth
        return_details['telephone'] = request.user.phone_number
        return_details['email'] = request.user.email
        return_details['year_ended_on'] = personal_details.income_year_ended_on
        salary_government = self.get_transaction(user=request.user, category_name='Salary Government',
                                                 year=assesment_year)
        salary = Decimal(0)
        if salary_government:
            salary += salary_government.taxable_income

        salary_private = self.get_transaction(user=request.user, category_name='Salary Private', year=assesment_year)
        if salary_private:
            salary += salary_private.taxable_income

        return_details['Income from Salaries (annex Schedule 1)'] = salary

        rent = self.get_transaction(user=request.user, category_name='House Income',
                                    year=assesment_year)
        if rent:
            return_details['Income from Rent (annex Schedule 2)'] = rent.taxable_income
        else:
            return_details['Income from Rent (annex Schedule 2)'] = Decimal(0)
        agriculture = self.get_transaction(user=request.user, category_name='Agriculture', year=assesment_year)
        if agriculture:
            return_details['Agricultural income (annex Schedule 3)'] = agriculture.taxable_income
        else:
            return_details['Agricultural income (annex Schedule 3)'] = Decimal(0)
        business = self.get_transaction(user=request.user, category_name='Business', year=assesment_year)
        if business:
            return_details['Income from business (annex Schedule 4)'] = business.taxable_income
        else:
            return_details['Income from business (annex Schedule 4)'] = Decimal(0)

        return_details['Capital gains'] = 0
        return_details['Income from Financial Assets (Bank interest/profit, Dividend, Securities etc.)'] = 0
        return_details['Income from other sources (Royalty, License fee, Honorarium, Fees, Govt. Incentive etc.)'] = 0
        return_details['Share of income from firm or AOP'] = 0
        return_details['Income of minor or spouse under section (if not assessee)'] = 0
        return_details['Foreign income'] = 0
        report = self.get_report(user=request.user)
        if not report:
            return Response('Please fill report first', status=status.HTTP_400_BAD_REQUEST)
        return_details['Gross tax on taxable Income '] = report.taxable_income
        if personal_details.resident_status == 'Non-Resident':
            return_details['Tax rebate (annex Schedule 5)'] = Decimal(0)
            return_details['Net tax after tax rebate (12-13)'] = 0
            return_details['Minimum tax'] = 0
            return_details['Tax Payable (Higher of 14 and 15)'] = 0
            return_details['Net wealth surcharge (if applicable)'] = 0
            return_details['Environmental surcharge (if applicable)'] = 0
            return_details['Delay Interest, Penalty or any other amount under the Income Tax Act (if any)'] = 0
            return Response(return_details, status=status.HTTP_200_OK)

        return_details['Tax rebate (annex Schedule 5)'] = report.rebate
        return_details['Net tax after tax rebate (12-13)'] = abs(report.taxable_income - report.rebate)
        if report.net_tax == Decimal(0):
            minimum_tax = Decimal(0)
        elif Decimal(1) <= report.net_tax <= Decimal(5000):
            minimum_tax = Decimal(5000)
        else:
            minimum_tax = report.net_tax
        return_details['Minimum tax '] = minimum_tax
        return_details['Tax Payable (Higher of 14 and 15)'] = max(minimum_tax,
                                                                  abs(report.taxable_income - report.rebate))
        return_details['Net wealth surcharge (if applicable)'] = 0
        return_details['Environmental surcharge (if applicable)'] = 0
        return_details['Delay Interest, Penalty or any other amount under the Income Tax Act (if any)'] = 0

        return Response(return_details, status=status.HTTP_200_OK)
