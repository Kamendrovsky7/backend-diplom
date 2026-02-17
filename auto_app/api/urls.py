from rest_framework.routers import DefaultRouter
from django.urls import path, include

from . import views

router = DefaultRouter()

router.register(r"products", views.ProductViewSet, basename="product")
router.register(r"categories", views.CategoryViewSet, basename="category")
router.register(r"suppliers", views.SupplierViewSet, basename="supplier")
router.register(r"cart/items", views.CartItemViewSet, basename="cart-item")
router.register(r"orders", views.OrderViewSet, basename="order")

urlpatterns = [
    path("", include(router.urls)),
    path("register/", views.RegisterView.as_view(), name="register"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("cart/", views.CartDetailView.as_view(), name="cart-detail"),
    path("auth/password-reset/", views.PasswordResetRequestView.as_view(), name="password-reset"),
    path("auth/email-confirm/", views.ConfirmEmailView.as_view(), name='email-confirmation'),
    path("auth/password-reset-confirm/", views.PasswordResetConfirmView.as_view(), name='password-confirm'),
    path("products/bulk-update/", views.BulkPriceUpdateView.as_view(), name='bulk-update'),
]
