from django.urls import path

from apis.main import views


app_name = 'main'

urlpatterns = [
    path('auth/login', views.login_request, name='login'),
    path('', views.index, name='index')
]
