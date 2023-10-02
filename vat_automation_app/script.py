from .models import *
from decimal import Decimal


def tax_calculator(user, amount):
    slab_category = PersonalDetails.objects.get(user=user).are_you
    slabs = Slab.objects.filter(select_one=slab_category).order_by('percentage')
    the_amount = Decimal(amount)
    taxable_income = Decimal(0.0)
    for i in range(len(slabs) - 1):
        income_slab = slabs[i].percentage
        if slabs[i].amount is not None:
            if the_amount >= slabs[i].amount:
                taxable_income += slabs[i].amount * (slabs[i].percentage / 100)
                the_amount -= slabs[i].amount
            else:
                taxable_income += the_amount / slabs[i].percentage
                the_amount = Decimal(0.0)

    if the_amount > 0:
        taxable_income += the_amount * (slabs[len(slabs) - 1].percentage / 100)
        income_slab = slabs[len(slabs) - 1].percentage

    return round(taxable_income, 2), income_slab
