from rest_framework import serializers
from auto_app.models import (
    Product,
    Supplier,
    Category,
    Cart,
    CartItem,
    Customer,
    Order,
    OrderItem,
)
from django.contrib.auth import get_user_model
from django.db import transaction
from auto_app.utils import send_order_confirmation

User = get_user_model()


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = "__all__"


class SupplierSerializer(serializers.ModelSerializer):
    class Meta:
        model = Supplier
        fields = "__all__"


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("id", "username", "email", "password", "first_name", "last_name")

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
        )
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "first_name", "last_name")


class CartItemSerializer(serializers.ModelSerializer):
    product_id = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(), write_only=True, source="product"
    )

    class Meta:
        model = CartItem
        fields = ["id", "cart", "product_id", "quantity"]
        read_only_fields = ["cart"]

    def create(self, validated_data):
        cart = validated_data.get("cart")
        product = validated_data.get("product")
        quantity = validated_data.get("quantity", 1)

        if quantity <= 0:
            raise serializers.ValidationError(
                {"quantity": "Quantity must be positive."}
            )

        cart_item, created = CartItem.objects.get_or_create(cart=cart, product=product)

        if not created:
            cart_item.quantity += quantity
        else:
            cart_item.quantity = quantity
        cart_item.save()
        return cart_item

    def update(self, instance, validated_data):
        quantity = validated_data.get("quantity", instance.quantity)
        if quantity <= 0:
            instance.delete()
            return None
        instance.quantity = quantity
        instance.save()
        return instance


class CartSerializer(serializers.ModelSerializer):
    items = serializers.SerializerMethodField()
    total_amount = serializers.DecimalField(
        max_digits=10, decimal_places=2, read_only=True
    )

    class Meta:
        model = Cart
        fields = ["id", "user", "created_at", "updated_at", "items", "total_amount"]
        read_only_fields = ["user", "created_at", "updated_at"]

    def get_items(self, obj):
        items_data = []
        for item in obj.items.all():
            if item.product:
                item_data = {
                    "id": item.id,
                    "quantity": item.quantity,
                    "product": ProductSerializer(item.product).data,
                    "item_total": item.get_item_total(),
                }
                items_data.append(item_data)
            else:
                pass
        return items_data

    def get_total_amount(self, obj):
        total = sum(
            item.quantity * item.product.price
            for item in obj.items.all()
            if item.product
        )
        return total

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation["total_amount"] = self.get_total_amount(instance)
        return representation


class OrderItemSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(read_only=True, required=False)
    supplier_name = serializers.CharField(read_only=True, required=False)
    price = serializers.DecimalField(
        max_digits=10, decimal_places=2, read_only=True, required=False
    )
    quantity = serializers.IntegerField(read_only=True, required=False)

    class Meta:
        model = OrderItem
        fields = [
            "id",
            "product_name",
            "supplier_name",
            "price",
            "quantity",
        ]


class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)
    cart_id = serializers.IntegerField(write_only=True, required=True)

    class Meta:
        model = Order
        fields = [
            "id",
            "user",
            "customer",
            "created_at",
            "updated_at",
            "total_amount",
            "status",
            "shipping_address",
            "phone_number",
            "items",
            "cart_id",
        ]
        read_only_fields = [
            "user",
            "customer",
            "created_at",
            "updated_at",
            "total_amount",
            "status",
            "items",
        ]

    @transaction.atomic
    def create(self, validated_data):
        request = self.context.get("request")
        cart_id_for_lookup = validated_data.pop("cart_id", None)

        if not request or not request.user.is_authenticated:
            raise serializers.ValidationError(
                {"detail": "Authentication credentials were not provided."}
            )

        if not cart_id_for_lookup:
            raise serializers.ValidationError({"cart_id": "ID корзины обязателен."})

        try:
            cart = Cart.objects.get(id=cart_id_for_lookup, user=request.user)
        except Cart.DoesNotExist:
            raise serializers.ValidationError(
                {"detail": "Cart not found or does not belong to the user."}
            )

        try:
            customer = Customer.objects.get(user=request.user)
        except Customer.DoesNotExist:
            transaction.set_rollback(True)
            raise serializers.ValidationError(
                {"detail": "Customer profile not found for this user."}
            )

        shipping_address = validated_data.get("shipping_address", customer.address)
        phone_number = validated_data.get("phone_number", customer.phone_number)

        order = Order.objects.create(
            user=request.user,
            customer=customer,
            shipping_address=shipping_address,
            phone_number=phone_number,
            status="new",
        )

        total_order_amount = 0
        cart_items = CartItem.objects.filter(cart=cart)
        if not cart_items:
            transaction.set_rollback(True)
            raise serializers.ValidationError(
                {"detail": "Cannot create order from an empty cart."}
            )

        for item in cart_items:
            if item.product:
                order_item = OrderItem.objects.create(
                    order=order,
                    product=item.product,
                    product_name=item.product.name,
                    supplier_name=(
                        item.product.supplier.name
                        if item.product.supplier
                        else "Unknown Supplier"
                    ),
                    price=item.product.price,
                    quantity=item.quantity,
                )
                total_order_amount += order_item.get_item_total()
            else:
                transaction.set_rollback(True)
                raise serializers.ValidationError(
                    {
                        "detail": f"Cart item {item.id} refers to a product that no longer exists."
                    }
                )

        order.total_amount = total_order_amount
        order.save()

        cart_items.delete()
        cart.delete()

        try:
            send_order_confirmation(order)
        except Exception as e:
            pass

        return order
