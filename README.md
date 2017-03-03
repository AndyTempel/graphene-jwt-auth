# Graphene JWT Auth

## Overview
This package provides [JSON Web Token Authentication](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token) support for Django and Graphene.

Based on the :
* [Django JWT Auth](https://github.com/jpadilla/django-jwt-auth) package. (this project forked from this package)
* [REST framework JWT Auth](https://github.com/GetBlimp/django-rest-framework-jwt) package.
* [Django REST framework](https://github.com/tomchristie/django-rest-framework) package.

This package includes blacklist, long running token, middleware for django and graphene for auth with JWT token header, custom error handling.

## Installation
Install using `pip`...
```
$ pip install graphene-jwt-auth
```


## Usage

### Set Middleware
### Login
### Logout
### Refresh Token
### Verify Token
### Long Running Token
### Delete Long Running Token
### Obtain New Token

## Additional Settings
 Here are all the available defaults.

```python
GRAPHENE_JWT_AUTH = {
    'JWT_ENCODE_HANDLER': 'graphene_jwt_auth.payload.jwt_encode_handler',
    'JWT_DECODE_HANDLER': 'graphene_jwt_auth.payload.jwt_decode_handler',
    'JWT_PAYLOAD_HANDLER': 'graphene_jwt_auth.payload.jwt_payload_handler',
    'JWT_PAYLOAD_GET_USERNAME_HANDLER':
        'graphene_jwt_auth.payload.jwt_get_username_from_payload_handler',
    'JWT_SECRET_KEY': settings.SECRET_KEY,
    'JWT_PRIVATE_KEY': None,
    'JWT_PUBLIC_KEY': None,
    'JWT_ALGORITHM': 'HS256',
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_LEEWAY': 0,
    'JWT_EXPIRATION_DELTA': datetime.timedelta(seconds=300),
    'JWT_AUDIENCE': None,
    'JWT_ISSUER': None,
    'JWT_ALLOW_REFRESH': False,
    'JWT_REFRESH_EXPIRATION_DELTA': datetime.timedelta(days=7),
    'JWT_AUTH_HEADER_PREFIX': 'Bearer',

    'JWT_BLACKLIST_GET_HANDLER': 'graphene_jwt_auth.blacklist.utils.jwt_blacklist_get_handler',
    'JWT_BLACKLIST_SET_HANDLER': 'graphene_jwt_auth.blacklist.utils.jwt_blacklist_set_handler',


    'JWT_LONG_RUNNING_TOKEN_GET_HANDLER':
        'graphene_jwt_auth.longrunningtoken.utils.jwt_long_running_token_get_handler',
    'JWT_LONG_RUNNING_TOKEN_SET_HANDLER':
        'graphene_jwt_auth.longrunningtoken.utils.jwt_long_running_token_set_handler',
    'JWT_LONG_RUNNING_TOKEN_APP_NAME': 'app',

    # Utils
    'JWT_DELETE_LONG_RUNNING_TOKEN_WHEN_LOGOUT': False,
    'CHANGED_PASSWORD_INVALIDATED_OLD_TOKEN': False,

    # Graphene
    'QUERIES_USER_NODE':
        'graphene_jwt_auth.graphene.queries.UserNode'
}
```
## Warning
* Not tested yet.
* Document is not available yet.
* Still on development.
* My english is realllyyyy bad (still learning).
* Pull request is welcome.
