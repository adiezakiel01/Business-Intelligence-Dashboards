#views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect
from django.urls import reverse, NoReverseMatch
from functools import wraps
import secrets
from django.db import IntegrityError, transaction
import logging
import re
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import json
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.db.models import Q
from django.core.paginator import Paginator
import uuid, boto3
from django.conf import settings
from botocore.exceptions import ClientError
import os

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
#from .services import send_invitation_email # Import the new service

import pandas as pd
import numpy as np
import json
#from .services import list_dashboard_files, load_excel_from_key

logger = logging.getLogger(__name__)
User = get_user_model()
MAX_RECENT = 5

# ==================== Helper Functions ====================
def clear_messages(request):
    """Clear all messages from the request."""
    storage = messages.get_messages(request)
    storage.used = True


def validate_password_strength(password: str, user=None):
    """
    Enforce password policy:
    - 12–16 chars
    - at least 1 uppercase
    - at least 1 lowercase
    - at least 1 digit
    - at least 1 symbol
    Also runs Django's configured AUTH_PASSWORD_VALIDATORS.
    Returns: (is_valid: bool, errors: list[str])
    """
    errors = []

    if not password:
        return False, ["Password cannot be empty."]

    if len(password) < 8 or len(password) > 16:
        errors.append("Password must be 8–16 characters long.")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least 1 uppercase letter (A–Z).")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least 1 lowercase letter (a–z).")

    if not re.search(r"\d", password):
        errors.append("Password must contain at least 1 number (0–9).")

    # symbol = any character not letter or digit
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password must contain at least 1 symbol (e.g. !@#$%).")

    # Django built-in validators from settings.py
    try:
        validate_password(password, user=user)
    except ValidationError as e:
        errors.extend(e.messages)

    return (len(errors) == 0), errors

# ==================== decorator ====================

def token_required(required_role=None):
    """
    Custom decorator to check:
    - user is authenticated
    - session has auth_token
    - optional role match on request.user.role
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')

            if 'auth_token' not in request.session:
                messages.error(request, 'Session expired. Please login again')
                return redirect('login')

            if required_role is not None:
                user_role = getattr(request.user, "role", None)
                if user_role != required_role:
                    messages.error(request, 'You do not have permission to access this page')
                    return redirect('main_page')

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

# ==================== authentication ====================

def authView(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST or None)
        if form.is_valid():
            form.save()
            messages.success(request, 'Account created successfully! Please login.')
            return redirect('login')
    else:
        form = UserCreationForm()
    return render(request, "registration/create_account.html", {"form": form})


@csrf_protect
def login(request):
    if request.method == 'GET':
        if request.GET.get('from') != 'signup':
            clear_messages(request)

    if request.method == 'POST':
        staff_id = request.POST.get('staff_id')
        password = request.POST.get('pw')

        logger.debug("Login attempt - Staff ID: %s", staff_id)

        if not staff_id or not password:
            messages.error(request, 'Please provide both Staff ID and Password')
            return render(request, 'login.html')

        user = authenticate(request, username=staff_id, password=password)
        logger.debug("Authentication result: %s", user)

        if user is not None:
            auth_login(request, user)

            token = secrets.token_urlsafe(32)
            request.session['auth_token'] = token
            request.session['staff_id'] = staff_id
            request.session.set_expiry(3600)
            request.session.modified = True

            logger.info("Login successful for %s", staff_id)
            return redirect('main_page')
        else:
            messages.error(request, 'Invalid Staff ID or Password')
            return render(request, 'login.html')

    return render(request, "login.html")


def logout(request):
    """Logout view to clear session"""
    auth_logout(request)
    messages.success(request, 'You have been logged out successfully')
    return redirect('login')

@csrf_protect
def create_account(request):
    if request.method == 'GET':
        clear_messages(request)

    if request.method == 'POST':
        staff_id = request.POST.get('staff_id', '').strip()
        password = request.POST.get('pw', '')
        password_confirm = request.POST.get('pw_confirm', '')

        if not staff_id or not password or not password_confirm:
            messages.error(request, 'All fields are required.')
            return render(request, 'create_account.html')

        if password != password_confirm:
            messages.error(request, 'Passwords do not match. Please try again.')
            return render(request, 'create_account.html')

        #enforce password strength here
        is_valid, pw_errors = validate_password_strength(password)
        if not is_valid:
            for err in pw_errors:
                messages.error(request, err)
            return render(request, 'create_account.html')

        existing_user = User.objects.filter(username=staff_id).first()
        if existing_user:
            logger.error(f"User already exists: ID={existing_user.id}, username={existing_user.username}")
            messages.error(request, f'Staff ID {staff_id} already exists. Please choose another.')
            return render(request, 'create_account.html')

        try:
            with transaction.atomic():
                new_user = User.objects.create_user(username=staff_id, password=password)
                logger.info(f"Successfully created user: ID={new_user.id}, username={new_user.username}")

            messages.success(request, 'Account created successfully! You can now log in.')
            return redirect(reverse('login'))

        except IntegrityError as e:
            logger.exception(f"IntegrityError while creating user {staff_id}: {str(e)}")
            messages.error(request, 'An account with that Staff ID already exists.')
            return render(request, 'create_account.html')

    return render(request, 'create_account.html')


def _add_recent_dashboard(request, name, url_name):
    recent = request.session.get("recent_dashboards", [])
    try:
        url = reverse(url_name)
    except NoReverseMatch:
        logger.warning("reverse() failed for url_name=%s", url_name)
        return

    recent = [d for d in recent if d.get("url") != url]
    recent.insert(0, {"name": name, "url": url})
    request.session["recent_dashboards"] = recent[:MAX_RECENT]
    request.session.modified = True

    # ==================== Account Management Views ====================

@token_required(required_role='admin')
def list_accounts(request):
    """List all user accounts with links to edit/delete."""
    if 'search' not in request.GET:
        clear_messages(request)

    search_query = request.GET.get('search', '').strip()
    sort_query = request.GET.get('sorting', '').strip()
    sort_order = request.GET.get('order', 'asc').strip()
    role = request.GET.get('role', '').strip()
    page_number = request.GET.get('page', 1)

    users = User.objects.all()

    if search_query:
        users = users.filter(
            Q(username__icontains=search_query)|
            Q(first_name__icontains=search_query)|
            Q(last_name__icontains=search_query)|
            Q(email__icontains=search_query)
        )


    if sort_query:
        order_prefix = '-' if sort_order == 'desc' else ''
        users = users.order_by(f'{order_prefix}{sort_query}')
    else:
        users = users.order_by('username')


    #Pagination
    paginator = Paginator(users, 10)  # Show x users per page
    page_obj = paginator.get_page(page_number)

    return render(request, 'accounts_list.html', {
        'users': page_obj,
        'search_query': search_query,
        'sort_query': sort_query,
        'sort_order': sort_order,
        'role': role,
        'page_obj': page_obj,
    })

@token_required(required_role='admin')
@csrf_protect
def edit_account(request, user_id):
    """Edit user details; password change is optional."""
    user_obj = get_object_or_404(User, pk=user_id)

    if request.method == 'GET':
        clear_messages(request)

    if request.method == 'POST':
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()
        role = request.POST.get('role', '').strip()
        password = request.POST.get('password', '')
        password_confirm = request.POST.get('password_confirm', '')
        is_active = True if request.POST.get('is_active') == 'on' else False

        user_obj.first_name = first_name
        user_obj.last_name = last_name
        user_obj.email = email
        setattr(user_obj, 'role', role)
        user_obj.is_active = is_active

        if password or password_confirm:
            if password != password_confirm:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'edit_account.html', {'user_obj': user_obj})

            #enforce password strength here
            is_valid, pw_errors = validate_password_strength(password, user=user_obj)
            if not is_valid:
                for err in pw_errors:
                    messages.error(request, err)
                return render(request, 'edit_account.html', {'user_obj': user_obj})

            user_obj.set_password(password)

        user_obj.save()
        messages.success(request, 'Account updated successfully.')
        return redirect('accounts_list')

    return render(request, 'edit_account.html', {'user_obj': user_obj})


@token_required(required_role='admin')
@csrf_protect
def delete_account(request, user_id):
    """Show confirmation and delete the user on POST."""
    user_obj = get_object_or_404(User, pk=user_id)

    if request.method == 'GET':
        clear_messages(request)

    if request.method == 'POST':
        username = user_obj.username
        user_obj.delete()
        messages.success(request, f'Account "{username}" deleted successfully.')
        return redirect('accounts_list')

    return render(request, 'confirm_delete.html', {'user_obj': user_obj})

@token_required(required_role="admin")
def upload_dashboard_file(request):
    if request.method != "POST":
        return redirect("home")

    dashboard_key = request.POST.get("dashboard_key")
    excel_file = request.FILES.get("excel_file")

    if not dashboard_key or not excel_file:
        messages.error(request, "Please select a dashboard and choose a file.")
        return redirect("home")

    #folder = DASHBOARD_FOLDER_MAP.get(dashboard_key)
    #if not folder:
    #    messages.error(request, "Invalid dashboard selection.")
    #    return redirect("main_page")

    #ext = excel_file.name.split(".")[-1]
    #object_key = f"{folder}{dashboard_key}_{uuid.uuid4()}.{ext}"

    #s3.upload_fileobj(
    #    excel_file,
    #    settings.AWS_STORAGE_BUCKET_NAME,
    #    object_key,
    #    ExtraArgs={"ContentType": excel_file.content_type,"ACL": "public-read",},
    #)

    messages.success(request, "File uploaded successfully for this dashboard.")
    return redirect("home")
# ==================== Protected Views ====================

@token_required()
def home(request):
    if request.method == 'GET':
        clear_messages(request)

    context = {
        'staff_id': request.session.get('staff_id'),
        'user': request.user,
        'recent_dashboards': request.session.get('recent_dashboards', []),
    }
    return render(request, "home.html", context)