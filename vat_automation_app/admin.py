from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(CustomUser)
admin.site.register(CategorySetup)
admin.site.register(Transaction)
admin.site.register(Details)
admin.site.register(Slab)
admin.site.register(Report)
admin.site.register(PersonalDetails)
admin.site.register(AssetsAndLiabilities)