# Test fixture for the PATHOS graph rules (example code, not executed).
from django.urls import path
from . import views

urlpatterns = [
    # ruleid: pathos-graph-python-route-django
    path("articles/<int:year>/", views.year_archive),
]


def latest():
    # ruleid: pathos-graph-python-db-django-orm
    return Article.objects.filter(published=True)
