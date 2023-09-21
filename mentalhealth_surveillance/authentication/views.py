from django.shortcuts import render,redirect
from django.http import JsonResponse
import json
from django.contrib.auth.models import User
from django.views import View
from validate_email import validate_email 
from django.contrib import messages
import re
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.template.loader import render_to_string
from .utils import token_generator
from django.urls import reverse
from django.contrib import auth
from django.conf import settings
import smtplib
from django.core.mail import send_mail
import traceback
import logging

def send_email_using_smtp(subject, body, to_email):
    
    print("Trying to send email...")  # Debug statement


    from_email = settings.EMAIL_HOST_USER
    app_password = settings.EMAIL_HOST_PASSWORD
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        print("Starting tls...")
        response=server.login(from_email, app_password)
        print(f"SMTP Server Response after Login: {response}")
        server.sendmail(from_email, to_email, f"Subject: {subject}\n\n{body}")
        print("send email...")
        server.quit()
    except Exception as e:
        print("Exception while sending email:")
        traceback.print_exc()

class UsernameValidateView(View):
    def post(self,request):
        data=json.loads(request.body)
        username=data['username']
        if not str(username).isalnum():
            return JsonResponse({'username_error':'username can only be submitted using alpha-numeric values '}, status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({'username_error':'username is already in use , please choose some other username '}, status=400)
        return JsonResponse({'username_valid':True})
    
class RegistrationView(View):
    
    def get(self, request):
        return render(request, 'authentication/register.html')

    def post(self, request):
        username = request.POST['username']
        recipient_email = request.POST['email']  
        password = request.POST['password']

        context = {
            'fieldValues': request.POST
        }

        if not User.objects.filter(username=username).exists():
            if not User.objects.filter(email=recipient_email).exists():
                if len(password) < 6:
                    messages.error(request, "Password too short")
                    return render(request, 'authentication/register.html', context)
                elif not re.search("[A-Z]", password):  # Check for uppercase letter
                    messages.error(request, "Password should have at least one uppercase letter.")
                    return render(request, 'authentication/register.html', context)
                elif not re.search("[!@#$%^&*(),.?\":{}|<>]", password):  # Check for special character
                    messages.error(request, "Password should have at least one special character.")
                    return render(request, 'authentication/register.html', context)
                
                # Create the user and set is_active to False
                user = User.objects.create_user(username=username, email=recipient_email, password=password, is_active=False)

                uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                domain = get_current_site(request).domain
                link = reverse('activate', kwargs={
                    'uidb64': uidb64, 'token': token_generator.make_token(user)})
                activate_url = 'http://' + domain + link

                email_body = 'Hi ' + user.username + ', Please use this link to verify your account\n' + activate_url
                email_subject = 'Activate your account'

                try:
                    send_mail(
                        email_subject,
                        email_body,
                        settings.EMAIL_HOST_USER,
                        [recipient_email],
                        fail_silently=False,
                    )
                    messages.success(request, "Account created successfully, please check your email to verify.")
                except Exception as e:
                    print(f"Error sending email: {e}")
                    messages.error(request, "Error sending verification email. Please try again.")

                return redirect('login')
        return render(request, 'authentication/register.html')
class EmailValidateView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            email = data.get('email')

            if not email:
                return JsonResponse({'error': 'Email not provided'}, status=400)

            if not validate_email(email):
                return JsonResponse({'email_error': 'Email is invalid'}, status=400)

            if User.objects.filter(email=email).exists():
                return JsonResponse({'email_error': 'Email is already in use'}, status=400)

            return JsonResponse({'email_valid': True})

        except Exception as e:
            # This will return any exception that arises in the view, helping you pinpoint the exact issue.
            return JsonResponse({'error': str(e)}, status=500)
logger = logging.getLogger(__name__)
       
class VerificationView(View):

    def get(self, request, uidb64, token):
        try:
            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=id)

            if not token_generator.check_token(user, token):
                logger.error("Token verification failed for user %s", user.username)
                messages.error(request, 'Invalid verification link or the link has expired.')
                return redirect('login')

            user.is_active = True
            user.save()

            auth.login(request, user)
            messages.success(request, 'Account activated successfully, you are now logged in.')
            return redirect('home')

        except Exception as ex:
            logger.error("Error during account verification: %s", ex)
            messages.error(request, 'Error activating account, please try again.')
            return redirect('login')
class LoginView(View):
    def get(self, request):  
        return render(request, 'authentication/login.html')

    def post(self, request):
        user_input = request.POST['username']
        pass_input = request.POST['password']

        if user_input and pass_input:
            user = auth.authenticate(username=user_input, password=pass_input)
            

            if user:
                if user.is_active:
                    auth.login(request, user)
                    messages.success(request, 'Welcome, ' + user.username + ', you are now logged in')
                    return redirect('home')
                    # TODO: Consider redirecting to a dashboard or another page after successful login.
                else:
                    messages.error(request, 'Account is not active, please check your email')
                    return render(request, 'authentication/login.html')
            else:
                messages.error(request, 'Invalid credentials, try again')
                return render(request, 'authentication/login.html')
        else:
            messages.error(request, 'Please fill all the fields')
            return render(request, 'authentication/login.html')
class LogoutView(View):
    def post(self, request):
        auth.logout(request)
        messages.success(request, 'You have been logged out')
        return redirect('login')     
