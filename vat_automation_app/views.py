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
from .script import *
from django.conf import settings
from decimal import Decimal
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str


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
        mail_subject = 'Your New OTP'
        message = f'Your OTP code is: {otp}'
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
        personal_details = self.get_object(request.user)
        assess_name = personal_details.assess_name
        tin = personal_details.tin
        if personal_details:
            serializer = PersonalDetailsUpdateSerializer(personal_details, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                if assess_name != request.data['assess_name']:
                    Transaction.objects.filter(user=request.user).update(assess_name=request.data['assess_name'])
                if tin != request.data['tin']:
                    Transaction.objects.filter(user=request.user).update(tin=request.data['tin'])
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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
        try:
            personal_details = PersonalDetails.objects.get(user=request.user)
        except PersonalDetails.DoesNotExist:
            return Response("No personal details found", status=status.HTTP_400_BAD_REQUEST)
        details = request.data.pop('details', None)

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
            transaction_serializer = TransactionSerializer(transaction.first())

        report, create = Report.objects.get_or_create(user=request.user, year=request.data['year'])
        details_data = []
        tax_amount = float(0)
        if request.data['category_name'] == 'Business':
            for index, detail in enumerate(details):
                detail_serializer = DetailsSerializer(data={
                    'transaction': transaction_serializer.data.get('id'),
                    'transaction_row': index + 1,
                    'description': detail,
                    'amount': details[detail],
                    'tax_exempted': True,
                    'comment': "",
                    'aggregated': "",
                })
                if not detail_serializer.is_valid():
                    return Response(detail_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                detail_serializer.save()
                details_data.append(detail_serializer.data)

            tax_amount = details['net_profit']
        else:
            for index, detail in enumerate(details):
                detail['transaction'] = transaction_serializer.data.get('id')
                detail['transaction_row'] = index + 1

                detail_serializer = DetailsSerializer(data=detail)
                if not detail_serializer.is_valid():
                    return Response(detail_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                if not detail['tax_exempted']:
                    tax_amount += float(detail['amount'])  # Convert amount to float
                detail_serializer.save()
                details_data.append(detail_serializer.data)
        if request.data['category_name'] == 'Rebate':
            rebate = min((float(report.taxable_income) * 0.03), float(tax_amount) * 0.15, 100000)  # Convert to float
            report.rebate = rebate
            report.save()
            transaction = Transaction.objects.get(id=transaction_serializer.data.get('id'))
            transaction.taxable_income = report.taxable_income
            transaction.save()
            return Response(details_data, status=status.HTTP_200_OK)
        slab_category = personal_details.are_you
        legal_guardian = personal_details.legal_guardian

        first_slab = Slab.objects.filter(select_one=slab_category).order_by('percentage').first()
        if not first_slab:
            return Response("No slab found", status=status.HTTP_400_BAD_REQUEST)
        if request.data['category_name'] == 'Salary Private':
            tax_amount = float(tax_amount) - min((float(tax_amount) / 3.00),
                                                 float(first_slab.amount) + 50000.00 if legal_guardian else float(
                                                     first_slab.amount))
        if isinstance(report.taxable_income, float):
            report.taxable_income = Decimal(report.taxable_income)  # Convert to float
        report.taxable_income += Decimal(tax_amount)  # Convert to float
        net_tax, income_slab = tax_calculator(personal_details=personal_details,
                                              amount=report.taxable_income)  # Convert to float
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

    def get_transaction(self, user, year, category_name):
        try:
            return Transaction.objects.get(user=user, year=year, category_name=category_name)
        except Transaction.DoesNotExist:
            return None

    def get(self, request):
        personal_details = PersonalDetails.objects.get(user=request.user)
        if not personal_details:
            return Response("No personal details found", status=status.HTTP_400_BAD_REQUEST)
        basic_info = {'Name of the Assess': personal_details.assess_name, 'TIN': personal_details.tin}
        salary_government_transaction = self.get_transaction(user=request.user,
                                                             year=str(datetime.now().year) + '-' + str(
                                                                 datetime.now().year + 1)[2:],
                                                             category_name='Salary Government')
        if not salary_government_transaction:
            salary_government_serializer = category_data(category_name='Salary Government')
            basic_info['government_taxable_income'] = 0.0
        else:
            basic_info['government_taxable_income'] = salary_government_transaction.taxable_income
            government_details = Details.objects.filter(transaction=salary_government_transaction)
            if not government_details:
                salary_government_serializer = category_data(category_name='Salary Government')
            else:
                salary_government_serializer = DetailsSerializer(government_details, many=True).data

        salary_private_transaction = self.get_transaction(user=request.user, year=str(datetime.now().year) + '-' + str(
            datetime.now().year + 1)[2:], category_name='Salary Private')
        if not salary_private_transaction:
            salary_private_serializer = category_data(category_name='Salary Private')
            basic_info['private_taxable_income'] = 0.0
        else:
            basic_info['private_taxable_income'] = salary_private_transaction.taxable_income
            private_details = Details.objects.filter(transaction=salary_private_transaction)
            if not private_details:
                salary_private_serializer = category_data(category_name='Salary Private')
            else:
                salary_private_serializer = DetailsSerializer(private_details, many=True).data

        return Response(
            {'government_details': salary_government_serializer,
             'private_details': salary_private_serializer, 'basic_info': basic_info}, status=status.HTTP_200_OK)


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
        basic_info = {}
        assesment_year = str(datetime.now().year) + '-' + str(datetime.now().year + 1)[2:]
        basic_info['Name_of_the_Taxpayer'] = personal_details.assess_name
        basic_info['TIN'] = personal_details.tin
        basic_info['National_ID_No'] = personal_details.nid
        basic_info['Passport_No'] = personal_details.passport_number
        basic_info['Assessment_Year'] = assesment_year
        basic_info['Circle'] = personal_details.circle
        basic_info['Tax_Zone'] = personal_details.tax_zone
        basic_info['Resident_Status'] = personal_details.resident_status
        basic_info['tick_box'] = personal_details.are_you
        basic_info['Address'] = personal_details.address
        basic_info['Date_of_Birth'] = personal_details.date_of_birth
        basic_info['Mobile'] = request.user.phone_number
        basic_info['e_mail'] = request.user.email
        basic_info['Year_Ended_On'] = personal_details.income_year_ended_on
        salary_government = self.get_transaction(user=request.user, category_name='Salary Government',
                                                 year=assesment_year)
        particulars_of_income = []
        salary = Decimal(0)
        if salary_government:
            salary += salary_government.taxable_income

        salary_private = self.get_transaction(user=request.user, category_name='Salary Private', year=assesment_year)
        if salary_private:
            salary += salary_private.taxable_income

        particulars_of_income.append({'particulars': 'Income from Employment (annex Schedule 1)', 'amount': salary})

        rent = self.get_transaction(user=request.user, category_name='House Income',
                                    year=assesment_year)
        if rent:
            particulars_of_income.append(
                {'particulars': 'Income from Rent (annex Schedule 2)', 'amount': rent.taxable_income})
        else:
            particulars_of_income.append(
                {'particulars': 'Income from Rent (annex Schedule 2)', 'amount': float(0)})
        agriculture = self.get_transaction(user=request.user, category_name='Agriculture', year=assesment_year)
        if agriculture:
            particulars_of_income.append(
                {'particulars': 'Income from Agriculture (annex Schedule 3)', 'amount': agriculture.taxable_income})
        else:
            particulars_of_income.append(
                {'particulars': 'Income from Agriculture (annex Schedule 3)', 'amount': float(0)})
        business = self.get_transaction(user=request.user, category_name='Business', year=assesment_year)
        if business:
            particulars_of_income.append(
                {'particulars': 'Income from Business (annex Schedule 4)', 'amount': business.taxable_income})
        else:
            particulars_of_income.append(
                {'particulars': 'Income from Business (annex Schedule 4)', 'amount': float(0)})

        particulars_of_income.append({'particulars': 'Income from Capital Gain', 'amount': float(0)})
        particulars_of_income.append(
            {'particulars': 'Income from Financial Assets (Bank Interest, Dividend, Securities Profit etc)',
             'amount': float(0)})
        particulars_of_income.append(
            {'particulars': 'Income from Other Sources (Royalty, License Fees, Honorarium, Govt. Incentive etc.)',
             'amount': float(0)})
        particulars_of_income.append(
            {'particulars': 'Share of Income from Firm or AoP',
             'amount': float(0)})
        particulars_of_income.append(
            {'particulars': 'Income of Minor or Spouse (if not Taxpayer)',
             'amount': float(0)})
        particulars_of_income.append(
            {'particulars': 'Taxable Income from Abroad',
             'amount': float(0)})

        tax_consumption = []
        particulars_of_tax_payment = []
        report = self.get_report(user=request.user)
        if not report:
            return Response('Please fill report first', status=status.HTTP_400_BAD_REQUEST)
        tax_consumption.append({'particular': 'Gross Tax on Taxable Income', 'amount': report.taxable_income})
        if personal_details.resident_status == 'Non-Resident':
            tax_consumption.append({'particular': 'Tax Rebate (annex Schedule 5)', 'amount': float(0)})
            tax_consumption.append({'particular': 'Net Tax after Rebate (12  – 13)', 'amount': float(0)})
            tax_consumption.append({'particular': 'Minimum Tax', 'amount': float(0)})
            tax_consumption.append({'particular': 'Tax Payable (Higher of 14 and 15)', 'amount': float(0)})
            tax_consumption.append({'particular': '(a) Net Wealth Surcharge (if applicable)', 'amount': float(0)})
            tax_consumption.append({'particular': '(b) Environmental Surcharge (if applicable)', 'amount': float(0)})
            tax_consumption.append(
                {'particular': 'Delay Interest, Penalty or any other amount Under Income Tax Act (if any)',
                 'amount': float(0)})
            particulars_of_tax_payment.append(
                {'particular': 'Tax Deducted or Collected at Source (attach proof)', 'amount': float(0)})
            particulars_of_tax_payment.append(
                {'particular': 'Advance Tax paid (attach proof)', 'amount': float(0)})
            particulars_of_tax_payment.append(
                {'particular': 'Adjustment of Tax Refund {mention assessment year(s) of refund}', 'amount': float(0)})
            particulars_of_tax_payment.append(
                {'particular': 'Tax Paid with this Return', 'amount': float(0)})
            return Response({'Basic_Info': basic_info, 'Particulars_of_Income': particulars_of_income,
                             'Tax_Consumption': tax_consumption,
                             'Particulars_of_Tax_Payment': particulars_of_tax_payment}, status=status.HTTP_200_OK)
        if report.net_tax == float(0):
            minimum_tax = float(0)
        elif float(1) <= report.net_tax <= float(5000):
            minimum_tax = float(5000)
        else:
            minimum_tax = report.net_tax

        tax_consumption.append({'particular': 'Tax Rebate (annex Schedule 5)', 'amount': report.rebate})
        tax_consumption.append(
            {'particular': 'Net Tax after Rebate (12  – 13)', 'amount': abs(report.taxable_income - report.rebate)})
        tax_consumption.append({'particular': 'Minimum Tax', 'amount': minimum_tax})
        tax_consumption.append({'particular': 'Tax Payable (Higher of 14 and 15)', 'amount': max(minimum_tax,
                                                                                                 abs(report.taxable_income - report.rebate))})
        tax_consumption.append({'particular': '(a) Net Wealth Surcharge (if applicable)', 'amount': float(0)})
        tax_consumption.append({'particular': '(b) Environmental Surcharge (if applicable)', 'amount': float(0)})
        tax_consumption.append(
            {'particular': 'Delay Interest, Penalty or any other amount Under Income Tax Act (if any)',
             'amount': float(0)})
        particulars_of_tax_payment.append(
            {'particular': 'Tax Deducted or Collected at Source (attach proof)', 'amount': float(0)})
        particulars_of_tax_payment.append(
            {'particular': 'Advance Tax paid (attach proof)', 'amount': float(0)})
        particulars_of_tax_payment.append(
            {'particular': 'Adjustment of Tax Refund {mention assessment year(s) of refund}', 'amount': float(0)})
        particulars_of_tax_payment.append(
            {'particular': 'Tax Paid with this Return', 'amount': float(0)})

        return Response({'Basic_Info': basic_info, 'Particulars_f_Income': particulars_of_income,
                         'Tax_Consumption': tax_consumption,
                         'Particulars_of_Tax_Payment': particulars_of_tax_payment}, status=status.HTTP_200_OK)


class CheckAdmin(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.is_staff or request.user.is_superuser:
            return Response(True, status=status.HTTP_200_OK)
        return Response(False, status=status.HTTP_200_OK)


class BusinessReport(APIView):
    permission_classes = [IsAuthenticated]

    def get_transaction(self, user, year, category_name):
        try:
            return Transaction.objects.get(user=user, year=year, category_name=category_name)
        except Transaction.DoesNotExist:
            return None

    def get(self, request):
        personal_details = PersonalDetails.objects.get(user=request.user)
        if not personal_details:
            return Response("No personal details found", status=status.HTTP_400_BAD_REQUEST)

        basic_info = {'Name of the Assess': personal_details.assess_name, 'TIN': personal_details.tin}
        business_transaction = self.get_transaction(user=request.user,
                                                    year=str(datetime.now().year) + '-' + str(
                                                        datetime.now().year + 1)[2:],
                                                    category_name='Business')
        if not business_transaction:
            return Response("Please fill out your business form first", status=status.HTTP_400_BAD_REQUEST)

        basic_info['Name_of_the_Taxpayer'] = business_transaction.assess_name
        basic_info['TIN'] = business_transaction.tin
        basic_info['Name_of_Business'] = business_transaction.business_name
        basic_info['Nature_of_business'] = business_transaction.type_of_business
        basic_info['Business_Address'] = business_transaction.address

        business_details = Details.objects.filter(transaction=business_transaction).order_by('transaction_row')

        summery_of_income = []
        summary_of_balance_sheet = []
        if not business_details:
            summery_of_income.append({'particular': 'Sales / Turnover  / Receipt', 'amount': '-'})
            summery_of_income.append({'particular': 'Gross Profit', 'amount': '-'})
            summery_of_income.append(
                {'particular': 'General, Administrative, Selling and Other Expenses', 'amount': '-'})
            summery_of_income.append({'particular': 'Bad Debt Expense', 'amount': '-'})
            summery_of_income.append({'particular': 'Net Profit ( 2 – 3)', 'amount': '-'})

            summary_of_balance_sheet.append({'particular': 'Cash and Bank Balance', 'amount': '-'})
            summary_of_balance_sheet.append({'particular': 'Inventory', 'amount': '-'})
            summary_of_balance_sheet.append({'particular': 'Fixed Asset', 'amount': '-'})
            summary_of_balance_sheet.append({'particular': 'Other Assets', 'amount': '-'})
            summary_of_balance_sheet.append({'particular': 'Total Assets ( 6 + 7 + 8 + 9)', 'amount': '-'})
            summary_of_balance_sheet.append({'particular': 'Opening Capital', 'amount': '-'})
            summary_of_balance_sheet.append({'particular': 'Net Profit', 'amount': '-'})
            summary_of_balance_sheet.append({'particular': 'Drawing during the Income Year', 'amount': '-'})
            summary_of_balance_sheet.append({'particular': 'Closing Capital (11 + 12 – 13)', 'amount': '-'})
            summary_of_balance_sheet.append({'particular': 'Liabilities', 'amount': '-'})
            summary_of_balance_sheet.append({'particular': 'Total Capital & Liabilities (14 + 15)', 'amount': '-'})

        else:
            summery_of_income.append({'particular': 'Sales / Turnover  / Receipt',
                                      'amount': business_details.get(description='revenue').__dict__.get('amount')})
            summery_of_income.append({'particular': 'Gross Profit',
                                      'amount': business_details.get(description='gross_profit').__dict__.get(
                                          'amount')})
            summery_of_income.append(
                {'particular': 'General, Administrative, Selling and Other Expenses',
                 'amount': business_details.get(description='administrative_expenses').__dict__.get(
                     'amount')})
            summery_of_income.append({'particular': 'Bad Debt Expense',
                                      'amount': business_details.get(description='bad_debt_expense').__dict__.get(
                                          'amount')})
            summery_of_income.append({'particular': 'Net Profit ( 2 – 3)',
                                      'amount': business_details.get(description='gross_profit').__dict__.get(
                                          'amount') - business_details.get(
                                          description='administrative_expenses').__dict__.get(
                                          'amount')})

            summary_of_balance_sheet.append({'particular': 'Cash and Bank Balance',
                                             'amount': business_details.get(description='bank_balance').__dict__.get(
                                                 'amount') + business_details.get(
                                                 description='cash_in_hand').__dict__.get(
                                                 'amount')})
            summary_of_balance_sheet.append({'particular': 'Inventory', 'amount': business_details.get(
                description='closing_balance_inventory').__dict__.get(
                'amount')})
            summary_of_balance_sheet.append({'particular': 'Fixed Asset', 'amount': business_details.get(
                description='property_plant_equipment').__dict__.get(
                'amount')})

            summary_of_balance_sheet.append({'particular': 'Other Assets',
                                             'amount': business_details.get(description='loan_to_others').__dict__.get(
                                                 'amount') + business_details.get(
                                                 description='advances_deposits_receivable').__dict__.get('amount')})
            summary_of_balance_sheet.append({'particular': 'Total Assets ( 6 + 7 + 8 + 9)',
                                             'amount': business_details.get(description='bank_balance').__dict__.get(
                                                 'amount') + business_details.get(
                                                 description='cash_in_hand').__dict__.get(
                                                 'amount') + business_details.get(
                                                 description='closing_balance_inventory').__dict__.get(
                                                 'amount') + business_details.get(
                                                 description='property_plant_equipment').__dict__.get(
                                                 'amount') + business_details.get(
                                                 description='loan_to_others').__dict__.get(
                                                 'amount') + business_details.get(
                                                 description='advances_deposits_receivable').__dict__.get('amount')})

            summary_of_balance_sheet.append({'particular': 'Opening Capital',
                                             'amount': business_details.get(
                                                 description='opening_balance_capital').__dict__.get(
                                                 'amount')})
            summary_of_balance_sheet.append(
                {'particular': 'Net Profit', 'amount': business_details.get(description='net_profit').__dict__.get(
                    'amount')})
            summary_of_balance_sheet.append({'particular': 'Drawing during the Income Year',
                                             'amount': business_details.get(description=
                                                                            'drawing_during_the_income_year').__dict__.get(
                                                 'amount')})
            closing_capital = business_details.get(description='opening_balance_capital').__dict__.get(
                'amount') + business_details.get(
                description='opening_balance_capital').__dict__.get(
                'amount') - business_details.get(
                description='drawing_during_the_income_year').__dict__.get('amount')
            summary_of_balance_sheet.append({'particular': 'Closing Capital (11 + 12 – 13)',
                                             'amount': closing_capital})
            summary_of_balance_sheet.append({'particular': 'Liabilities', 'amount': business_details.get(
                description='liabilities').__dict__.get('amount')})
            summary_of_balance_sheet.append({'particular': 'Total Capital & Liabilities (14 + 15)',
                                             'amount': closing_capital + business_details.get(
                                                 description='liabilities').__dict__.get('amount')})

        rebate_transaction = self.get_transaction(user=request.user,
                                                  year=str(datetime.now().year) + '-' + str(
                                                      datetime.now().year + 1)[2:],
                                                  category_name='Rebate')
        particulars_of_income = []
        if not rebate_transaction:
            particulars_of_income.append(
                {'particular': 'Life insurance premium or Contractual "Deferred Annuity" paid in Bangladesh',
                 'amount': '-'})
            particulars_of_income.append(
                {'particular': 'Contribution to deposit pension/Monthly Saving scheme (not exceeding allowable limit)',
                 'amount': '-'})
            particulars_of_income.append({
                'particular': 'Investment in Govt. securities, Unit certificate, Mutual fund, ETF or Joint investment scheme Unit certificate',
                'amount': '-'})
            particulars_of_income.append(
                {'particular': 'Investment in securities listed with approved Stock Exchange', 'amount': '-'})
            particulars_of_income.append(
                {'particular': 'Contribution to provident fund to which Provident Fund  Act, 1925 applies',
                 'amount': '-'})
            particulars_of_income.append({'particular': 'Contribution to approved Pension Fund', 'amount': '-'})
            particulars_of_income.append(
                {'particular': 'Contribution to Benevolent Fund and Group Insurance Premium', 'amount': '-'})
            particulars_of_income.append({'particular': 'Contribution to Zakat Fund', 'amount': '-'})
            particulars_of_income.append(
                {'particular': 'Others, if any (Show the name of the investment from rebate page)', 'amount': '-'})
            particulars_of_income.append({'particular': 'Total investment (aggregate of 1 to 10)', 'amount': '-'})
            try:
                report = Report.objects.get(user=request.user,
                                            year=str(datetime.now().year) + '-' + str(datetime.now().year + 1)[2:])
            except Report.DoesNotExist:
                return Response("please fill out your rebate form", status=status.HTTP_400_BAD_REQUEST)

            particulars_of_income.append(
                {'particular': 'Amount of Tax Rebate', 'amount': min(report.taxable_income, 0, 1000000)})
            return Response({'basic_info': basic_info, 'summary_of_income': summery_of_income,
                             'summary_of_balance_sheet': summary_of_balance_sheet,
                             'particulars_of_income': particulars_of_income}, status=status.HTTP_200_OK)
        rebate_details = Details.objects.filter(transaction=rebate_transaction).order_by('transaction_row')

        if not rebate_details:
            particulars_of_income.append(
                {'particular': 'Life insurance premium or Contractual "Deferred Annuity" paid in Bangladesh',
                 'amount': '-'})
            particulars_of_income.append(
                {'particular': 'Contribution to deposit pension/Monthly Saving scheme (not exceeding allowable limit)',
                 'amount': '-'})
            particulars_of_income.append({
                'particular': 'Investment in Govt. securities, Unit certificate, Mutual fund, ETF or Joint investment scheme Unit certificate',
                'amount': '-'})
            particulars_of_income.append(
                {'particular': 'Investment in securities listed with approved Stock Exchange', 'amount': '-'})
            particulars_of_income.append(
                {'particular': 'Contribution to provident fund to which Provident Fund  Act, 1925 applies',
                 'amount': '-'})
            particulars_of_income.append({'particular': 'Contribution to approved Pension Fund', 'amount': '-'})
            particulars_of_income.append(
                {'particular': 'Contribution to Benevolent Fund and Group Insurance Premium', 'amount': '-'})
            particulars_of_income.append({'particular': 'Contribution to Zakat Fund', 'amount': '-'})
            particulars_of_income.append(
                {'particular': 'Others, if any (Show the name of the investment from rebate page)', 'amount': '-'})
            particulars_of_income.append({'particular': 'Total investment (aggregate of 1 to 10)', 'amount': '-'})
            try:
                report = Report.objects.get(user=request.user,
                                            year=str(datetime.now().year) + '-' + str(datetime.now().year + 1)[2:])
            except Report.DoesNotExist:
                return Response("please fill out your rebate form", status=status.HTTP_400_BAD_REQUEST)

            particulars_of_income.append(
                {'particular': 'Amount of Tax Rebate', 'amount': min(report.taxable_income, 0, 1000000)})
            return Response({'basic_info': basic_info, 'summary_of_income': summery_of_income,
                             'summary_of_balance_sheet': summary_of_balance_sheet,
                             'particulars_of_income': particulars_of_income}, status=status.HTTP_200_OK)

        particulars_of_income.append({
            'particular': 'Life insurance premium or Contractual "Deferred Annuity" paid in Bangladesh (10% of Policy Value)',
            'amount': rebate_details.get(
                description='Life insurance premium or Contractual Deferred Annuity paid in Bangladesh (10% of Policy Value').__dict__.get(
                'amount')})
        particulars_of_income.append(
            {'particular': 'Contribution to deposit pension/Monthly Saving scheme (not exceeding allowable limit)',
             'amount': rebate_details.get(
                 description='Contribution to deposit pension/Monthly Saving scheme (not exceeding allowable limit)').__dict__.get(
                 'amount')})
        particulars_of_income.append({
            'particular': 'Investment in Govt. securities, Unit certificate, Mutual fund, ETF or Joint investment scheme Unit certificate',
            'amount': rebate_details.get(description=
                                         'Investment in Government securities, Unit certificate, Mutual fund, ETF or Joint investment scheme Unit certificate').__dict__.get(
                'amount')})
        particulars_of_income.append({'particular': 'Investment in securities listed with approved Stock Exchange',
                                      'amount': rebate_details.get(
                                          description='Investment in securities listed with approved Stock Exchange').__dict__.get(
                                          'amount')})
        particulars_of_income.append(
            {'particular': 'Contribution to provident fund to which Provident Fund  Act, 1925 applies',
             'amount': rebate_details.get(
                 description='Personal Contribution to provident fund under Provident Fund Act, 1925').__dict__.get(
                 'amount')})
        particulars_of_income.append(
            {'particular': 'Self contribution and employer’s contribution to Recognized Provident Fund',
             'amount': rebate_details.get(
                 description='Employers contribution with Self contribution to Recognized Provident Fund').__dict__.get(
                 'amount')})
        particulars_of_income.append({'particular': 'Contribution to approved Pension Fund',
                                      'amount': rebate_details.get(
                                          description='Contribution to approved Pension Fund').__dict__.get('amount')})
        particulars_of_income.append(
            {'particular': 'Contribution to Benevolent Fund and Group Insurance Premium',
             'amount': rebate_details.get(
                 description='Contribution to Benevolent Fund and Group Insurance Premium').__dict__.get('amount')})
        particulars_of_income.append({'particular': 'Contribution to Zakat Fund',
                                      'amount': rebate_details.get(
                                          description='Contribution to Zakat Fund').__dict__.get('amount')})
        particulars_of_income.append(
            {'particular': 'Others, if any (Show the name of the investment from rebate page)',
             'amount': rebate_details.get(description='Others Asset management companies').__dict__.get(
                 'amount') + rebate_details.get(description='Others Mutual funds').__dict__.get(
                 'amount') + rebate_details.get(description='Others ETF or joint investment schemes').__dict__.get(
                 'amount')})
        total_amount = rebate_details.get(
            description='Life insurance premium or Contractual Deferred Annuity paid in Bangladesh (10% of Policy Value').__dict__.get(
            'amount') + rebate_details.get(
            description='Contribution to deposit pension/Monthly Saving scheme (not exceeding allowable limit)').__dict__.get(
            'amount') + rebate_details.get(description=
                                           'Investment in Government securities, Unit certificate, Mutual fund, ETF or Joint investment scheme Unit certificate').__dict__.get(
            'amount') + rebate_details.get(description=
                                           'Investment in Government securities, Unit certificate, Mutual fund, ETF or Joint investment scheme Unit certificate').__dict__.get(
            'amount') + rebate_details.get(
            description='Personal Contribution to provident fund under Provident Fund Act, 1925').__dict__.get(
            'amount') + rebate_details.get(
            description='Employers contribution with Self contribution to Recognized Provident Fund').__dict__.get(
            'amount') + rebate_details.get(
            description='Contribution to approved Pension Fund').__dict__.get('amount') + rebate_details.get(
            description='Contribution to Benevolent Fund and Group Insurance Premium').__dict__.get(
            'amount') + rebate_details.get(description='Contribution to Zakat Fund').__dict__.get(
            'amount') + rebate_details.get(description='Others Asset management companies').__dict__.get(
            'amount') + rebate_details.get(description='Others Mutual funds').__dict__.get(
            'amount') + rebate_details.get(description='Others ETF or joint investment schemes').__dict__.get(
            'amount')
        particulars_of_income.append({'particular': 'Total investment (aggregate of 1 to 10)', 'amount': total_amount})
        try:
            report = Report.objects.get(user=request.user,
                                        year=str(datetime.now().year) + '-' + str(datetime.now().year + 1)[2:])
        except Report.DoesNotExist:
            return Response("please fill out your rebate form", status=status.HTTP_400_BAD_REQUEST)
        particulars_of_income.append(
            {'particular': 'Amount of Tax Rebate',
             'amount': min(total_amount * Decimal(0.15), 1000000, report.taxable_income)})
        return Response({'basic_info': basic_info, 'summary_of_income': summery_of_income,
                         'summary_of_balance_sheet': summary_of_balance_sheet,
                         'particulars_of_income': particulars_of_income}, status=status.HTTP_200_OK)
