from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

DEBUG = True  # not a settings module: the settings rules do not apply


# ruleid: pathos.misconfig.django.csrf-exempt
@csrf_exempt
def webhook(request):
    return JsonResponse({"ok": True})


# ok: pathos.misconfig.django.csrf-exempt
def profile(request):
    return JsonResponse({"user": request.user.username})
