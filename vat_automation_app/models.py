from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission

from django.utils.translation import gettext_lazy as _


# Create your models here.

class CustomUser(AbstractUser):
    full_name = models.CharField(max_length=220, null=True, blank=True)
    email = models.EmailField(_('email'), unique=True)
    email_verified = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=15, unique=True)

    groups = models.ManyToManyField(Group, blank=True, related_name='custom_users')
    user_permissions = models.ManyToManyField(Permission, blank=True, related_name='custom_users')
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.username


class OTP(models.Model):
    token = models.CharField(max_length=8)
    created_on = models.DateTimeField(auto_now_add=True)
    expire_time = models.DateTimeField(auto_now_add=False)
    reason = models.CharField(max_length=50, blank=True)

    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.user.username


CATEGORY_CHOICE = [
    ('Agriculture', 'Agriculture'),
    ('Salary Government', 'Salary Government'),
    ('Salary Private', 'Salary Private'),
    ('House Income', 'House Income'),
    ('Business', 'Business')
]


class CategorySetup(models.Model):
    category_name = models.CharField(max_length=220, choices=CATEGORY_CHOICE, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    tax_exempted = models.BooleanField(default=False)
    aggregated = models.CharField(max_length=220, null=True, blank=True)
    active = models.BooleanField(default=True)
    sequence = models.IntegerField(default=1)

    def __str__(self):
        if self.description:
            return self.description
        return self.id


NATURE_CHOICE = [
    ('Residential', 'Residential'),
    ('Non-Residential', 'Non-Residential'),
    ('Service', 'Service'),
    ('Product', 'Product')
]


class Transaction(models.Model):
    uuid = models.CharField(max_length=50, null=True, blank=True)
    year = models.CharField(max_length=50, null=True, blank=True)
    category_name = models.CharField(max_length=220, null=True, blank=True)
    nature = models.CharField(max_length=220, choices=NATURE_CHOICE, null=True, blank=True)
    address = models.TextField(null=True, blank=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.category_name if self.category_name else self.id


class Details(models.Model):
    transaction_row = models.IntegerField(default=1)
    description = models.TextField(null=True, blank=True)
    tax_exempted = models.BooleanField(default=False)
    aggregated = models.CharField(max_length=220, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    comment = models.TextField(null=True, blank=True)

    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.description if self.description else self.id


SELECT_ONE_CHOICE = [
    ("General - Individuals & Firms", "General - Individuals & Firms"),
    ("Woman and Senior Citizens (65+)", "Woman and Senior Citizens (65+)"),
    ("Third Gender", "Third Gender"),
    ("Physically challenged persons", "Physically challenged persons"),
    ("War wounded gazetted freedom fighters", "War wounded gazetted freedom fighters")
]


class Slab(models.Model):
    title = models.CharField(max_length=220, null=True, blank=True)
    select_one = models.CharField(max_length=220, choices=SELECT_ONE_CHOICE, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    percentage = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    def __str__(self):
        return self.title


class Report(models.Model):
    year = models.CharField(max_length=50, null=True, blank=True)
    taxable_income = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    income_slab = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    rebate = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    net_tax = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    def __str__(self):
        return self.year


RESIDENT_STATUS_CHOICE = [
    ('Resident', 'Resident'),
    ('Non-Resident', 'Non-Resident')
]

CITY_CHOICE = [
    ('Any Other City Corporation', 'Any Other City Corporation'),
    ('Any Area Other than City Corporation', 'Any Area Other than City Corporation'),
    ('Dhaka or Chattagram City Corporation', 'Dhaka or Chattagram City Corporation')
]


class PersonalDetails(models.Model):
    date = models.DateField(auto_now_add=True)
    income_year_ended_on = models.DateField(auto_now_add=False)
    assessment_year = models.CharField(max_length=50, null=True, blank=True)
    assess_name = models.CharField(max_length=220)
    address = models.TextField()
    date_of_birth = models.DateField(null=True, blank=True)
    nid = models.CharField(max_length=50, null=True, blank=True)
    passport_number = models.CharField(max_length=50, null=True, blank=True)
    phone_number = models.CharField(max_length=15, unique=True)
    email = models.EmailField(unique=True)
    tin = models.CharField(max_length=50)
    circle = models.IntegerField()
    tax_zone = models.CharField(max_length=50)
    resident_status = models.CharField(max_length=50, choices=RESIDENT_STATUS_CHOICE, default='Resident')
    city = models.CharField(max_length=220, choices=CITY_CHOICE, default='Dhaka or Chattagram City Corporation')
    are_you = models.CharField(max_length=220, choices=SELECT_ONE_CHOICE, default='General - Individuals & Firms')
    legal_guardian = models.BooleanField(default=False)

    user = models.OneToOneField(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.user.email
