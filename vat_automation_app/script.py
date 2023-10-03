from .models import *
from decimal import Decimal


def tax_calculator(user, amount):
    slab_category = PersonalDetails.objects.get(user=user).are_you
    legal_guardian = PersonalDetails.objects.get(user=user).legal_guardian
    slabs = Slab.objects.filter(select_one=slab_category).order_by('percentage')
    the_amount = Decimal(amount)
    taxable_income = Decimal(0.0)
    income_slab = Decimal(0.0)
    for i in range(len(slabs) - 1):
        income_slab = slabs[i].percentage
        if slabs[i].amount is not None:
            # if the legal guardian is true, 50,000 amount will be added on the first slab of user's first slab category
            if i == 0 and legal_guardian:
                if the_amount >= slabs[i].amount + 50000:
                    taxable_income += (slabs[i].amount + 50000) * (slabs[i].percentage / 100)
                    the_amount -= slabs[i].amount
                    income_slab = slabs[i].percentage
                else:
                    taxable_income += the_amount * (slabs[i].percentage / 100)
                    the_amount = Decimal(0.0)
                    income_slab = slabs[i].percentage
                    break
            else:
                if the_amount >= slabs[i].amount:
                    taxable_income += slabs[i].amount * (slabs[i].percentage / 100)
                    the_amount -= slabs[i].amount
                    income_slab = slabs[i].percentage
                else:
                    taxable_income += the_amount * (slabs[i].percentage / 100)
                    the_amount = Decimal(0.0)
                    income_slab = slabs[i].percentage
                    break

    if the_amount > 0:
        taxable_income += the_amount * (slabs[len(slabs) - 1].percentage / 100)
        income_slab = slabs[len(slabs) - 1].percentage

    return round(taxable_income, 2), income_slab


def rebate_handling():
    pass
