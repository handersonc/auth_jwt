import jwt
import logging
import os
from datetime import datetime, timedelta
from flask_restful import Resource, abort
from flask import request
from helpers import get_client_info_from_token


def verify_jwt_flask(token, secret):
    """Verify if token is valid."""
    options = {
        'verify_signature': True,
        'verify_exp': True
    }
    try:
        decoded_token = jwt.decode(token, secret, options=options)
        return decoded_token
    except jwt.exceptions.ExpiredSignatureError, e:
        msg = "Error: %s - %s" % (e.__class__, e.message)
        logging.warning(msg)
        abort(403, message=e.message)

    except jwt.InvalidTokenError, e:
        logging.warning("Error in JWT token: %s" % e)
        return False


def create_jwt():
    """Create a new token."""
    if 'SECRET_TOKEN' in os.environ and 'APP_CLIENT_ID' in os.environ:
        token = jwt.encode(
            {
                'client_id': os.environ['APP_CLIENT_ID'],
                'exp': datetime.utcnow() + timedelta(minutes=60)
            },
            os.environ['SECRET_TOKEN'],
            algorithm='HS256'
        )

        return token
    else:
        raise 'Missing SECRET_TOKEN or/and APP_CLIENT_ID valiables.'


def verify_client_request(client):
    """Verify requests from web clients."""
    def func(origin):
        """Inner."""
        def inner(self, *args, **kwargs):
            """Inner."""
            if self:
                if issubclass(self.__class__, Resource):
                    if 'HTTP_INBOUND_APPID' in request.headers:
                        inbound_app_id = request.headers.get('HTTP_INBOUND_APPID')
                        client_info = get_client_info_from_token(inbound_app_id)
                        if 'client_id' in client_info:
                            client_id = client_info['client_id']
                            obj_client = client.query(client.client_id == client_id).get()
                            logging.warning("Client: %s" % obj_client)

                            if obj_client:
                                decoded_token = verify_jwt_flask(inbound_app_id, obj_client.client_secret)
                                if decoded_token:
                                    logging.warning(request.headers)
                                    if 'HOST' in request.headers:
                                        if obj_client.urls_white_list:
                                            if request.headers.get('HOST') in obj_client.urls_white_list:
                                                return origin(self, *args, **kwargs)
                                            else:
                                                abort(403, message='Forbbiden: origin is not allowed')
                                        else:
                                            abort(403, message='Forbbiden: client does not have configured origin hosts')
                                    else:
                                        abort(403, message='Forbbiden: unknow host')
                                else:
                                    abort(403, message='Forbbiden: invalid token')
                            else:
                                abort(401, message='Unauthorized')
                        else:
                            abort(401, message='Unauthorized')
                    else:
                        abort(401, message='Unauthorized')
                else:
                    raise Exception('Unsupported class')

            else:
                raise
        return inner
    return func
