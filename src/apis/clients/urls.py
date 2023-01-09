from django.urls import path

from . import views


app_name = "clients"

urlpatterns = [
    path('authorize', views.AuthorizeAPIView.as_view(), name='authorize'),
    path('token', views.TokenAPIView.as_view(), name='token'),
    path('introspect', views.TokenIntrospectionAPIView.as_view(), name='introspect'),
    path('userinfo', views.UserInfoAPIView.as_view(), name='userinfo'),
]
