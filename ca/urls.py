from django.urls import path

from . import views

urlpatterns = [
        path('', views.certificates, name='certificates'),
        path('certificates/<int:pk>.pub', views.export_certificate, name='export_certificate'),
        ]
