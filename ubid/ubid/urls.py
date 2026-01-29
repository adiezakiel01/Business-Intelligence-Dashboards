"""
URL configuration for ubid project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from bid import views  # Import views from the bid app
from django.conf import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    # Include all URLs from the dashboards app
    path('', include('bid.urls')),
    path('login/', views.login, name='login'),  # URL for the login page
    path('create/', views.create_account, name='create_account'),
    #path('erp/', views.dashboard1, name='dashboard1'),
    #path('crm/', views.dashboard2, name='dashboard2'),
    #path('dashboard3/', views.dashboard3, name='dashboard3'),
    #path('dashboard4/', views.dashboard4, name='dashboard4'),
    #path('dashboard5/', views.dashboard5, name='dashboard5'),
    #path('dashboard6/', views.dashboard6, name='dashboard6'),
    #path('dashboard7/', views.dashboard7, name='dashboard7'),
    #path('dashboard8/', views.dashboard8, name='dashboard8'),
    #path('profile/', views.profile, name='profile'),

]
