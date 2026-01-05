from rest_framework import generics, permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from rest_framework import serializers
from django.db import transaction

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

from .serializers import (
    ProductSerializer,
    SupplierSerializer,
    CategorySerializer,
    RegisterSerializer,
    UserSerializer,
    CartSerializer,
    CartItemSerializer,
    OrderSerializer,
    OrderItemSerializer,
)

from auto_app.utils import send_registration_confirmation, send_order_confirmation

User = get_user_model()


class ProductListView(generics.ListAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]


class ProductDetailView(generics.RetrieveAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        Customer.objects.get_or_create(user=user)
        send_registration_confirmation(user)
        token, created = Token.objects.get_or_create(user=user)
        headers = self.get_success_headers(serializer.data)
        response_data = {
            "message": "Пользователь успешно зарегистрирован.",
            "user": UserSerializer(user).data,
            "token": token.key,
        }
        return Response(response_data, status=status.HTTP_201_CREATED, headers=headers)


class LoginView(ObtainAuthToken):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        token, created = Token.objects.get_or_create(user=user)
        response_data = {
            "message": "Пользователь успешно вошел.",
            "user": UserSerializer(user).data,
            "token": token.key,
        }
        return Response(response_data)


class CartDetailView(generics.RetrieveAPIView):
    serializer_class = CartSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        try:
            cart = Cart.objects.get(user=self.request.user)
            return cart
        except Cart.DoesNotExist:
            return None

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance is None:
            return Response(
                {
                    "id": None,
                    "user": UserSerializer(request.user).data,
                    "created_at": None,
                    "updated_at": None,
                    "items": [],
                    "total_amount": "0.00",
                },
                status=status.HTTP_200_OK,
            )
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class CartItemViewSet(viewsets.ModelViewSet):
    queryset = CartItem.objects.all()
    serializer_class = CartItemSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return CartItem.objects.filter(cart__user=self.request.user)

    def perform_create(self, serializer):
        cart, created = Cart.objects.get_or_create(user=self.request.user)
        product = serializer.validated_data.get("product")
        quantity = serializer.validated_data.get("quantity", 1)

        if not product:
            raise serializers.ValidationError({"product": "Требуется товар."})
        if quantity <= 0:
            raise serializers.ValidationError(
                {"quantity": "Количество не может быть отрицательным."}
            )

        cart_item, item_created = CartItem.objects.get_or_create(
            cart=cart, product=product
        )

        if not item_created:
            cart_item.quantity += quantity
        else:
            cart_item.quantity = quantity
        cart_item.save()
        serializer.instance = cart_item
        cart.save()

    def perform_update(self, serializer):
        instance = serializer.instance
        quantity = serializer.validated_data.get("quantity", instance.quantity)

        if quantity <= 0:
            instance.delete()
            return None
        else:
            instance.quantity = quantity
            instance.save()
            instance.cart.save()
            return instance

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(
            CartItemSerializer(serializer.instance).data, status=status.HTTP_201_CREATED
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        updated_instance = self.perform_update(serializer)

        if updated_instance is None:
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(CartItemSerializer(updated_instance).data)


class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.none()
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated:
            return Order.objects.filter(user=user).select_related("user", "customer")
        return Order.objects.none()

    def retrieve(self, request, *args, **kwargs):
        order_id = kwargs.get("pk")
        order = get_object_or_404(self.get_queryset(), pk=order_id)
        serializer = self.get_serializer(order)
        return Response(serializer.data)

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        order = serializer.save()
        response_data = self.get_serializer(order).data
        return Response(response_data, status=status.HTTP_201_CREATED)

    @action(
        detail=True, methods=["patch"], permission_classes=[permissions.IsAdminUser]
    )
    def confirm_order(self, request, pk=None):
        order = self.get_object()
        new_status = request.data.get("status")

        if not new_status:
            return Response(
                {"detail": "Статус должен быть предусмотрен."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        valid_statuses = [choice[0] for choice in Order.STATUS_CHOICES]
        if new_status not in valid_statuses:
            return Response(
                {
                    "detail": f"Неверный статус. Разрешенные статусы {', '.join(valid_statuses)}."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        order.status = new_status
        order.save()

        if order.status == "Потвержден":
            try:
                send_order_confirmation(order)
            except Exception as e:
                self.stderr.write(
                    self.style.ERROR(
                        f"Ошика отправки письма потверждения заказа {order.id} после смены статуса: {e}"
                    )
                )

        serializer = self.get_serializer(order)
        return Response(serializer.data)


class ProductViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]


class CategoryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]


class SupplierViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Supplier.objects.all()
    serializer_class = SupplierSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
