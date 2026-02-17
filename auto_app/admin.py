from django.contrib import admin
from .models import (
    Product,
    Supplier,
    Category,
    Cart,
    CartItem,
    Customer,
    Order,
    OrderItem,
    SupplierOrder,
)

admin.site.register(Product)
admin.site.register(Supplier)
admin.site.register(Category)
admin.site.register(Cart)
admin.site.register(CartItem)
admin.site.register(Customer)
admin.site.register(Order)
admin.site.register(OrderItem)


@admin.register(SupplierOrder)
class SupplierOrderAdmin(admin.ModelAdmin):
    list_display = ("id", "order", "supplier", "status")
    list_filter = ("supplier", "status")
