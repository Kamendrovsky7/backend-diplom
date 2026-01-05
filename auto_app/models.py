from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.utils import timezone


class Supplier(models.Model):
    name = models.CharField(max_length=255, verbose_name=_("Supplier Name"))
    contact_person = models.CharField(
        max_length=255, blank=True, null=True, verbose_name=_("Contact Person")
    )
    phone = models.CharField(
        max_length=20, blank=True, null=True, verbose_name=_("Phone")
    )
    email = models.EmailField(blank=True, null=True, verbose_name=_("Email"))
    address = models.TextField(blank=True, null=True, verbose_name=_("Address"))

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = _("Supplier")
        verbose_name_plural = _("Suppliers")


class Category(models.Model):
    external_id = models.IntegerField(unique=True, verbose_name=_("External ID"))
    name = models.CharField(max_length=255, verbose_name=_("Name"))

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = _("Category")
        verbose_name_plural = _("Categories")


class Product(models.Model):
    name = models.CharField(max_length=255, verbose_name=_("Product Name"))
    description = models.TextField(blank=True, null=True, verbose_name=_("Description"))
    price = models.DecimalField(
        max_digits=10, decimal_places=2, verbose_name=_("Price")
    )
    supplier = models.ForeignKey(
        Supplier,
        on_delete=models.SET_NULL,
        null=True,
        related_name="products",
        verbose_name=_("Supplier"),
    )
    category = models.ForeignKey(
        Category,
        on_delete=models.SET_NULL,
        null=True,
        related_name="products",
        verbose_name=_("Category"),
    )
    sku = models.CharField(max_length=255, verbose_name=_("SKU"), blank=True, null=True)
    stock_quantity = models.PositiveIntegerField(
        default=0, verbose_name=_("Stock Quantity")
    )

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = _("Product")
        verbose_name_plural = _("Products")


class ProductAttribute(models.Model):
    name = models.CharField(
        max_length=100, unique=True, verbose_name=_("Attribute Name")
    )

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = _("Product Attribute")
        verbose_name_plural = _("Product Attributes")


class ProductAttributeValue(models.Model):
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, related_name="attribute_values"
    )
    attribute = models.ForeignKey(
        ProductAttribute, on_delete=models.CASCADE, related_name="values"
    )
    value = models.CharField(max_length=255, verbose_name=_("Value"))

    def __str__(self):
        return f"{self.product.name} - {self.attribute.name}: {self.value}"

    class Meta:
        verbose_name = _("Product Attribute Value")
        verbose_name_plural = _("Product Attribute Values")
        unique_together = ("product", "attribute")


class Customer(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="customer",
        verbose_name=_("User"),
    )
    phone_number = models.CharField(
        max_length=20, blank=True, null=True, verbose_name=_("Phone Number")
    )
    address = models.TextField(
        blank=True, null=True, verbose_name=_("Delivery Address")
    )

    def __str__(self):
        return f"{self.user.get_full_name() or self.user.username}"

    class Meta:
        verbose_name = _("Customer")
        verbose_name_plural = _("Customers")


class Order(models.Model):
    STATUS_CHOICES = [
        ("new", _("New")),
        ("confirmed", _("Confirmed")),
        ("processing", _("Processing")),
        ("shipped", _("Shipped")),
        ("delivered", _("Delivered")),
        ("cancelled", _("Cancelled")),
        ("returned", _("Returned")),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="orders",
        verbose_name=_("User"),
    )
    customer = models.ForeignKey(
        Customer,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="orders",
        verbose_name=_("Customer"),
    )
    created_at = models.DateTimeField(
        default=timezone.now, verbose_name=_("Created At")
    )
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated At"))
    total_amount = models.DecimalField(
        max_digits=10, decimal_places=2, default=0.00, verbose_name=_("Total Amount")
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="new", verbose_name=_("Status")
    )
    shipping_address = models.TextField(
        blank=True, null=True, verbose_name=_("Shipping Address")
    )
    phone_number = models.CharField(
        max_length=20, blank=True, null=True, verbose_name=_("Phone Number")
    )

    def __str__(self):
        return f"Order #{self.id} - {self.get_status_display()} ({self.created_at.strftime('%Y-%m-%d')})"

    class Meta:
        verbose_name = _("Order")
        verbose_name_plural = _("Orders")
        ordering = ["-created_at"]


class OrderItem(models.Model):
    order = models.ForeignKey(
        Order, on_delete=models.CASCADE, related_name="items", verbose_name=_("Order")
    )
    product = models.ForeignKey(
        Product,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="order_items",
        verbose_name=_("Product"),
    )
    product_name = models.CharField(
        max_length=255, verbose_name=_("Product Name"), default="Unknown Product"
    )
    supplier_name = models.CharField(
        max_length=255, verbose_name=_("Supplier Name"), default="Unknown Supplier"
    )
    price = models.DecimalField(
        max_digits=10, decimal_places=2, verbose_name=_("Price"), default=0.00
    )
    quantity = models.PositiveIntegerField(default=1, verbose_name=_("Quantity"))

    def __str__(self):
        return f"{self.quantity} x {self.product_name} (Order #{self.order.id})"

    class Meta:
        verbose_name = _("Order Item")
        verbose_name_plural = _("Order Items")

    def get_item_total(self):
        return self.price * self.quantity


class Cart(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="cart",
        verbose_name=_("User"),
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("Date Created"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Last Updated"))

    def __str__(self):
        return f"Cart of {self.user.email}"

    class Meta:
        verbose_name = _("Cart")
        verbose_name_plural = _("Carts")

    def get_total_price(self):
        total = sum(item.get_item_total() for item in self.items.all())
        return total


class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name="items")
    product = models.ForeignKey(
        Product, on_delete=models.CASCADE, related_name="cart_items"
    )
    quantity = models.PositiveIntegerField(default=1, verbose_name=_("Quantity"))

    def __str__(self):
        return f"{self.quantity} x {self.product.name} (Cart ID: {self.cart.pk})"

    class Meta:
        verbose_name = _("Cart Item")
        verbose_name_plural = _("Cart Items")
        unique_together = ("cart", "product")

    def get_item_total(self):
        return self.quantity * self.product.price
