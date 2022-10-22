from typing import Any, Dict, List, Optional

from django.conf import settings
from django.contrib.auth import authenticate
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_exempt

from zerver.context_processors import get_realm_from_request
from zerver.decorator import do_login, require_post
from zerver.lib.exceptions import (
    AuthenticationFailedError,
    InvalidSubdomainError,
    JsonableError,
    RealmDeactivatedError,
    UserDeactivatedError,
)
from zerver.lib.request import REQ, has_request_variables
from zerver.lib.response import json_success
from zerver.lib.subdomains import get_subdomain
from zerver.lib.users import get_api_key
from zerver.lib.validator import validate_login_email
from zerver.models import Realm, UserProfile, get_realm
from zerver.views.auth import config_error, get_safe_redirect_to
from zproject.backends import dev_auth_enabled

import pdb
import requests
import traceback

@csrf_exempt
@has_request_variables
def hashrem_direct_login(
    request: HttpRequest,
    next: str = REQ(default="/"),
) -> HttpResponse:

    # pdb.set_trace()
    subdomain = get_subdomain(request)
    realm = get_realm(subdomain)

    if request.POST.get("prefers_web_public_view") == "Anonymous login":
        request.session["prefers_web_public_view"] = True
        redirect_to = get_safe_redirect_to(next, realm.uri)
        return HttpResponseRedirect(redirect_to)

    hashrem_login_page = settings.HOME_NOT_LOGGED_IN
    hashrem_api_url = settings.HASHREM_API_URL
    hashrem_token_name = 'HTTP_ACCESS_TOKEN'
    access_token = request.META.get(hashrem_token_name)
    if not access_token:
        print('no hashrem access token found in request. redirecting to login page')
        redirect_to = get_safe_redirect_to(next, hashrem_login_page)
        return HttpResponseRedirect(redirect_to)

    response = requests.get(hashrem_api_url, headers={'ACCESS-TOKEN': access_token})
    if response.status_code == 400:
        return None
    result = response.json()
    print("response from api ", result)
    if 'email' not in result:
        print('user email not found in hashrem api response. redirecting to login page')
        redirect_to = get_safe_redirect_to(next, hashrem_login_page)
        return HttpResponseRedirect(redirect_to)

    email = result['email']
    # email = 'AARON@zulip.com'

    print("realm",realm)
    user_profile = authenticate(dev_auth_username=email, realm=realm)
    if user_profile is None:
        return config_error(request, "dev")
    do_login(request, user_profile)

    redirect_to = get_safe_redirect_to(next, user_profile.realm.uri)
    return HttpResponseRedirect(redirect_to)
