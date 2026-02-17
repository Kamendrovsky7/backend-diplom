import pytest
from decimal import Decimal
from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APITestCase, APIClient
from django.urls import reverse
from auto_app.models import Product, Category, Cart, CartItem, Order, Customer


@pytest.mark.django_db
class ModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser_model",
            password="password_model",
            email="model@example.com",
        )
        self.category = Category.objects.create(name="Test Category", external_id=123)
        self.product = Product.objects.create(
            name="Test Product",
            category=self.category,
            price=Decimal("100.00"),
            stock_quantity=10,
        )
        self.customer = Customer.objects.create(user=self.user)
        self.cart = Cart.objects.create(user=self.user)
        self.cart_item = CartItem.objects.create(
            cart=self.cart, product=self.product, quantity=2
        )
        self.order = Order.objects.create(
            user=self.user,
            customer=self.customer,
            total_amount=Decimal("200.00"),
            status="new",
        )

    def test_models_creation(self):
        self.assertEqual(str(self.category), "Test Category")
        self.assertEqual(str(self.product), "Test Product")
        self.assertIsInstance(self.cart, Cart)
        self.assertIsInstance(self.cart_item, CartItem)
        self.assertIsInstance(self.order, Order)

    def test_cart_total_price(self):
        expected_total = self.cart_item.quantity * self.product.price
        self.assertAlmostEqual(self.cart.get_total(), expected_total)

    def test_order_total_price(self):
        self.assertAlmostEqual(self.order.total_amount, Decimal("200.00"))


@pytest.mark.django_db
class APITests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="testuser_api",
            email="api_test@example.com",
            password="password_api",
        )
#  token_response = self.client.post(
#     reverse("login"), {"username": "testuser_api", "password": "password_api"}
#  )
        self.client.force_authenticate(user=self.user)
        self.category = Category.objects.create(
            name="Test API Category", external_id=456
        )
        self.product1 = Product.objects.create(
            name="Test Product API 1",
            category=self.category,
            price=Decimal("150.50"),
            stock_quantity=5,
        )
        self.product2 = Product.objects.create(
            name="Test Product API 2",
            category=self.category,
            price=Decimal("200.00"),
            stock_quantity=3,
        )
        self.customer = Customer.objects.create(user=self.user)

    def test_register_new_user(self):
        new_user_data = {
            "username": "newapiuser",
            "email": "newapi@example.com",
            "password": "password_api_new",
            "first_name": "API",
            "last_name": "User",
        }
        register_url = reverse("register")
        response = self.client.post(register_url, new_user_data)
        self.assertEqual(response.status_code, 201)
        self.assertIn("token", response.data)

    def test_login_user(self):
        auth_data = {"username": "testuser_api", "password": "password_api"}
        login_url = reverse("login")
        response = self.client.post(login_url, auth_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.data)

    def test_get_products_list(self):
        products_url = "/api/products/"
        response = self.client.get(products_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 2)

    def test_add_item_to_cart(self):
        cart_items_url = reverse("cart-item-list")
        payload = {"product_id": self.product1.pk, "quantity": 2}
        response = self.client.post(cart_items_url, payload)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["quantity"], 2)
        self.assertEqual(response.data["product"]["id"], self.product1.pk)

    def test_update_cart_item_quantity(self):
        add_payload = {"product_id": self.product1.pk, "quantity": 1}
        self.client.post(reverse("cart-item-list"), add_payload)
        cart_response = self.client.get(reverse("cart-detail"))
        cart_item_id = cart_response.data["items"][0]["id"]
        update_url = reverse("cart-item-detail", kwargs={"pk": cart_item_id})
        update_payload = {"quantity": 5}
        response = self.client.put(update_url, update_payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["quantity"], 5)

    def test_delete_cart_item(self):
        add_payload = {"product_id": self.product1.pk, "quantity": 1}
        self.client.post(reverse("cart-item-list"), add_payload)
        cart_response = self.client.get(reverse("cart-detail"))
        cart_item_id = cart_response.data["items"][0]["id"]
        delete_url = reverse("cart-item-detail", kwargs={"pk": cart_item_id})
        response = self.client.delete(delete_url)
        self.assertEqual(response.status_code, 204)
        cart_response_after_delete = self.client.get(reverse("cart-detail"))
        self.assertEqual(len(cart_response_after_delete.data["items"]), 0)

    def test_create_order(self):
        add_payload1 = {"product_id": self.product1.pk, "quantity": 1}
        self.client.post(reverse("cart-item-list"), add_payload1)
        add_payload2 = {"product_id": self.product2.pk, "quantity": 2}
        self.client.post(reverse("cart-item-list"), add_payload2)
        cart_response = self.client.get(reverse("cart-detail"))
        cart_id = cart_response.data["id"]
        order_url = reverse("order-list")
        order_payload = {
            "cart_id": cart_id,
            "shipping_address": "Test Address",
            "phone_number": "+1234567890",
        }
        response = self.client.post(order_url, order_payload)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["status"], "new")
        self.assertIsNotNone(response.data["id"])
        self.assertIn("items", response.data)
        self.assertEqual(len(response.data["items"]), 2)
        cart_response_after_order = self.client.get(reverse("cart-detail"))
        self.assertEqual(len(cart_response_after_order.data["items"]), 0)

    def test_view_order_history(self):
        add_payload1 = {"product_id": self.product1.pk, "quantity": 1}
        self.client.post(reverse("cart-item-list"), add_payload1)
        cart_response = self.client.get(reverse("cart-detail"))
        cart_id = cart_response.data["id"]
        order_payload = {
            "cart_id": cart_id,
            "shipping_address": "Test Address",
            "phone_number": "+1234567890",
        }
        self.client.post(reverse("order-list"), order_payload)
        orders_url = reverse("order-list")
        response = self.client.get(orders_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["status"], "new")

    def test_view_order_detail(self):
        add_payload1 = {"product_id": self.product1.pk, "quantity": 1}
        self.client.post(reverse("cart-item-list"), add_payload1)
        cart_response = self.client.get(reverse("cart-detail"))
        cart_id = cart_response.data["id"]
        order_payload = {
            "cart_id": cart_id,
            "shipping_address": "Test Address",
            "phone_number": "+1234567890",
        }
        create_order_response = self.client.post(reverse("order-list"), order_payload)
        order_id = create_order_response.data["id"]
        order_detail_url = reverse("order-detail", kwargs={"pk": order_id})
        response = self.client.get(order_detail_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["id"], order_id)
        self.assertEqual(response.data["status"], "new")

    def test_confirm_order_permission_denied(self):
        add_payload1 = {"product_id": self.product1.pk, "quantity": 1}
        self.client.post(reverse("cart-item-list"), add_payload1)
        cart_response = self.client.get(reverse("cart-detail"))
        cart_id = cart_response.data["id"]
        order_payload = {
            "cart_id": cart_id,
            "shipping_address": "Test Address",
            "phone_number": "+1234567890",
        }
        create_order_response = self.client.post(reverse("order-list"), order_payload)
        order_id = create_order_response.data["id"]
        confirm_url = reverse("order-confirm-order", kwargs={"pk": order_id})
        response = self.client.patch(confirm_url, {"status": "confirmed"})
        self.assertEqual(response.status_code, 403)
