from .models import *



def tax_calculator(amount, personal_details):
    slab_category = personal_details.are_you
    legal_guardian = personal_details.legal_guardian
    slabs = Slab.objects.filter(select_one=slab_category).order_by('percentage')
    the_amount = float(amount)
    taxable_income = float(0.0)
    income_slab = float(0.0)
    for i in range(len(slabs) - 1):
        income_slab = slabs[i].percentage
        if slabs[i].amount is not None:
            # if the legal guardian is true, 50,000 amount will be added on the first slab of user's first slab category
            if i == 0 and legal_guardian:
                if the_amount >= float(slabs[i].amount) + 50000.00:
                    taxable_income += float(slabs[i].amount + 50000) * float(slabs[i].percentage / 100)
                    if isinstance(the_amount, float):
                        report.taxable_income = Decimal(the_amount)  # Convert to float
                    the_amount -= slabs[i].amount
                    income_slab = slabs[i].percentage
                else:
                    taxable_income += the_amount * float(slabs[i].percentage / 100)
                    the_amount = float(0.0)
                    income_slab = slabs[i].percentage
                    break
            else:
                if the_amount >= slabs[i].amount:
                    taxable_income += slabs[i].amount * float(slabs[i].percentage / 100)
                    the_amount -= slabs[i].amount
                    income_slab = slabs[i].percentage
                else:
                    taxable_income += the_amount * float(slabs[i].percentage / 100)
                    the_amount = float(0.0)
                    income_slab = slabs[i].percentage
                    break

    if the_amount > 0:
        taxable_income += the_amount * float(slabs[len(slabs) - 1].percentage / 100)
        income_slab = slabs[len(slabs) - 1].percentage

    return round(taxable_income, 2), income_slab


def category_data(category_name):
    category = CategorySetup.objects.filter(category_name=category_name)
    details = []
    for c in category:
        details.append({'id': c.id, 'description': c.description, 'amount': 0, 'aggregated': c.aggregated,
                        'tax_exempted': c.tax_exempted, 'comment': ""})

    return details
