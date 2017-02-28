from django.core import exceptions

from graphene_jwt_auth.exceptions import APIException


def format_error(error):
    """
    change messages error
    """
    data = {
        'code': 'unhandled_exception',
        'message': error.message,
        'status_code': 500,
    }

    if hasattr(error, 'original_error'):
        original_error = error.original_error

        if isinstance(original_error, APIException):
            data['code'] = original_error.get_codes()
            data['message'] = original_error.detail
            data['status_code'] = original_error.status_code

        if isinstance(original_error, exceptions.ValidationError):
            data['code'] = 'invalid'
            data['status_code'] = 400
            if hasattr(original_error, 'error_dict'):
                data['message'] = original_error.message_dict

    if error.locations is not None:
        data['locations'] = [
            {'line': loc.line, 'column': loc.column}
            for loc in error.locations
            ]

    return data
