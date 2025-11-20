"""
Django Framework Security Test Case
Expected Issues: 4 high-severity Django-specific vulnerabilities
Tests framework-specific prompt effectiveness
"""
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt
from .models import User


def user_profile_vulnerable(request):
    """VULNERABLE: Django template injection via mark_safe."""
    user_input = request.GET.get('bio', '')
    # Line 17: HIGH - Template injection via mark_safe on user input
    safe_bio = mark_safe(user_input)
    return render(request, 'profile.html', {'bio': safe_bio})


@csrf_exempt
def update_profile_vulnerable(request):
    """VULNERABLE: CSRF protection disabled."""
    # Line 24: HIGH - @csrf_exempt on state-changing view
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        User.objects.filter(id=user_id).update(bio=request.POST.get('bio'))
    return HttpResponse('Updated')


def search_users_vulnerable(request):
    """VULNERABLE: Django ORM injection via .raw()."""
    search_term = request.GET.get('q', '')
    # Line 34: HIGH - SQL injection in Django .raw() query
    users = User.objects.raw(f"SELECT * FROM users WHERE username = '{search_term}'")
    return render(request, 'search.html', {'users': users})


def mass_assignment_vulnerable(request):
    """VULNERABLE: Mass assignment via **request.POST."""
    # Line 41: HIGH - Mass assignment vulnerability
    user = User.objects.create(**request.POST)
    return HttpResponse(f'User created: {user.id}')


# Secure versions for comparison
def user_profile_secure(request):
    """SECURE: Auto-escaping handles user input."""
    user_input = request.GET.get('bio', '')
    return render(request, 'profile.html', {'bio': user_input})


def search_users_secure(request):
    """SECURE: Uses Django ORM parameterized query."""
    search_term = request.GET.get('q', '')
    users = User.objects.filter(username=search_term)
    return render(request, 'search.html', {'users': users})
