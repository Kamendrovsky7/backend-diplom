from django.core.mail import send_mail
from django.conf import settings


def send_registration_confirmation(user):
    subject = "Вас приветствует AutoBuyApp!"
    message = f"Рады Вас видетЬ, {user.username}! Вы успешно зарегистрировались!."
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [user.email]

    send_mail(subject, message, email_from, recipient_list)


def send_order_confirmation(order):
    subject = f"Ваш заказ #{order.id} обработан!"
    message = (
        f"Приветствуем, {order.user.username}!\n\n"
        f"Заказ №{order.id} суммой {order.total_amount} был успешно подтвержден. "
        f"Адрес доставки: {order.shipping_address}"
    )
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [order.user.email]

    send_mail(subject, message, email_from, recipient_list)
