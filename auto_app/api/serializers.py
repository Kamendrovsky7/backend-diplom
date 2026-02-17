from rest_framework import serializers
from auto_app.models import (
    Product,
    Supplier,
    Category,
    Cart,
    CartItem,
    Order,
    OrderItem,
    SupplierOrder,
    ProductAttributeValue,
)
from django.contrib.auth import get_user_model
from django.db import transaction
from collections import defaultdict


User = get_user_model()


class ProductAttributeValueSerializer(serializers.ModelSerializer):
    attribute_name = serializers.CharField(source="attribute.name", read_only=True)

    class Meta:
        model = ProductAttributeValue
        fields = ["attribute_name", "value"]


class ProductSerializer(serializers.ModelSerializer):
    attributes = ProductAttributeValueSerializer(
        source="attribute_values",
        many=True,
        read_only=True
    )

    class Meta:
        model = Product
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
    class Meta:
        model = OrderItem
        fields = "__all__"


class SupplierOrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)

    class Meta:
        model = SupplierOrder
        fields = "__all__"


class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True)
    supplier_orders = SupplierOrderSerializer(many=True, read_only=True)

    class Meta:
        model = SupplierOrder
        fields = "__all__"

    @transaction.atomic
    def create(self, validated_data):
        items_data = validated_data.pop("items")
        user = self.context["request"].user

        order = Order.objects.create(user=user, **validated_data)

        supplier_groups = defaultdict(list)

        for item in items_data:
            product = item["product"]
            supplier = product.supplier

            supplier_groups[supplier].append(item)

        for supplier, items in supplier_groups.items():
            supplier_order = SupplierOrder.objects.create(
                order=order,
                supplier=supplier,
                status="created"
            )

            for item in items:
                OrderItem.objects.create(
                    supplier_order=supplier_order,
                    product=item["product"],
                    quantity=item["quantity"],
                    price=item["product"].price
                )

        return order


class SupplierSerializer(serializers.ModelSerializer):
    class Meta:
        model = Supplier
        fields = "__all__"


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.UUIDField()
    new_password = serializers.CharField(min_length=6)
