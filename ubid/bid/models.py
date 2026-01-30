#bid/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('management', 'Management'),
        ('hr', 'HR'),
        ('finance', 'Finance'),
        ('operations', 'Operations'),
        ('sales', 'Sales'),
        ('marketing', 'Marketing'),
    ]
    
    role = models.CharField(
        max_length=50, 
        choices=ROLE_CHOICES,
        blank=True, 
        default='admin'
    )
    contact = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    
    def __str__(self):
        return self.username
    
    def get_allowed_dashboards(self):
        """Return list of dashboard numbers this user can access"""
        ROLE_DASHBOARD_MAP = {
            'admin': [1, 2, 3, 4, 5, 6, 7, 8],
            'management': [1, 2, 3, 4, 5, 6, 7, 8],
            'hr': [5, 7, 8],
            'finance': [5, 8],
            'operations': [2, 3, 4, 7],
            'sales': [1, 2, 3, 4, 5, 7],
            'marketing': [1, 6],
        }
        return ROLE_DASHBOARD_MAP.get(self.role, [])