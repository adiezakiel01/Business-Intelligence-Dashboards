#dashboards/urls.py
from django.urls import path
from django.views.generic import RedirectView
from . import views

urlpatterns = [
    # Redirect accounts/login/ to login/ (for Django's default auth redirects)
    path("accounts/login/", RedirectView.as_view(pattern_name='login', permanent=False)),
    
    # Authentication URLs
    path("login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("create/", views.create_account, name="create_account"),

    # Account management
    path("accounts/", views.list_accounts, name="accounts_list"),
    path("accounts/<int:user_id>/edit/", views.edit_account, name="edit_account"),
    path("accounts/<int:user_id>/delete/", views.delete_account, name="delete_account"),
    #path('accounts/create-ajax/', views.create_account_ajax, name='create_account_ajax'),
    #path("accounts/<int:user_id>/save/",views.profile, name="profile"),

    # Main application URLs
    path("", views.home, name="home"),
    path(
        'upload-dashboard-file/',
        views.upload_dashboard_file,
        name='upload_dashboard_file',

        
    ),
    #path('download-dashboard-file/', views.download_dashboard_file, name='download_dashboard_file'),


    # User profile
    #path("profile/", views.profile, name="profile"),
    
    # Dashboard URLs
    #path("dashboard1/", views.dashboard1, name="dashboard1"),
    #path("dashboard2/", views.dashboard2, name="dashboard2"),
    #path("dashboard3/", views.dashboard3, name="dashboard3"),
    #path("dashboard4/", views.dashboard4, name="dashboard4"),
    #path("dashboard5/", views.dashboard5, name="dashboard5"),
    #path("dashboard6/", views.dashboard6, name="dashboard6"),
    #path("dashboard7/", views.dashboard7, name="dashboard7"),
    #path("dashboard8/", views.dashboard8, name="dashboard8"),

    #path("accounts/invite/", views.invite_user, name="invite_user"),
    #path("accept-invitation/<uidb64>/<token>/", views.accept_invitation, name="accept_invitation"),


]