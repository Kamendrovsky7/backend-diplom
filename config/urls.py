from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("auto_app.api.urls")),
    path('', lambda request: HttpResponse("<h1> Приветствую в Auto_App!</h1>")),
]
