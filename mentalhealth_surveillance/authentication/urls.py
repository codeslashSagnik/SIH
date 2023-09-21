from django.urls import path
from .views import RegistrationView,UsernameValidateView,EmailValidateView,VerificationView,LoginView,LogoutView
from django.views.decorators.csrf import csrf_exempt
urlpatterns = [
    path('register', RegistrationView.as_view(), name='register'),
    path('login', LoginView.as_view(), name='login'),
    path('username-validate', csrf_exempt(UsernameValidateView.as_view()), name='username-validate'),
    path('email-validate',csrf_exempt(EmailValidateView.as_view()), name='email-validate'),
    path('logout', LogoutView.as_view(), name="logout"),
    path('activate/<uidb64>/<token>',VerificationView.as_view(), name='activate')
]