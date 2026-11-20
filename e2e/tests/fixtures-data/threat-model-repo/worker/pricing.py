# Pricing rules (test fixture for pathos-graph).


def price_for(product_id):
    return base_price(product_id) * 1.2


def base_price(product_id):
    return 10.0 + product_id


class Discounts:
    def apply(self, value):
        return self.round(value * 0.9)

    def round(self, value):
        return round(value, 2)
