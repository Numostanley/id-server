from django.shortcuts import render, redirect, reverse
from django.contrib import messages

from apis.users.models import User


def index(request):
    return render(request, 'base.html')

def login_request(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        if not User.get_user_by_email(email):
            return render(request, '404.html')
        user = User.get_user_by_email(email)
        if user.validate_password(password):
            messages.success(request, 'Login successful!')
            return redirect(reverse('main:login'))
        messages.error(request, f'Login failed!')
        return redirect(reverse('main:login'))
    else:
        return render(request, 'login.html')
