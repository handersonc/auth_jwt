import jwt
import logging
import os
import json
from datetime import datetime, timedelta
from helpers import get_client_info_from_token, get_configuration_from_file

try:
    import webapp2
    from flask_restful import Resource, abort
    from flask import request
except:
    pass


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
        raise Exception('Missing SECRET_TOKEN or/and APP_CLIENT_ID valiables.')


def create_jwt_with(payload, secret):
    """Create a new token."""
    token = jwt.encode(
        payload,
        secret,
        algorithm='HS256'
    )

    return token


def verify_client_request(client):
    """Verify requests from web clients."""
    def func(origin):
        """Inner."""
        def inner(self, *args, **kwargs):
            """Inner."""
            if self:
                if issubclass(self.__class__, Resource):
                    if 'Authorization' in request.headers:
                        authorization_header = request.headers.get('Authorization')
                        inbound_app_id = authorization_header.split(' ')[1]
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
                                                setattr(self, 'client', obj_client)
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


def verify_user_request(user):
    """Verify requests from web clients."""
    def func(origin):
        """Inner."""
        def inner(self, *args, **kwargs):
            """Inner."""
            if self:
                if issubclass(self.__class__, Resource):
                    if 'Authorization' in request.headers:
                        authorization_header = request.headers.get('Authorization')
                        inbound_app_id = authorization_header.split(' ')[1]
                        client_info = get_client_info_from_token(inbound_app_id)
                        if 'user' in client_info and 'profile_id' in client_info['user']:
                            settings = get_configuration_from_file()
                            user_settings = settings['User']['Fields']
                            profile_id = client_info['user'][user_settings['UserId']]

                            obj_user = user.query(getattr(user, user_settings['UserId']) == profile_id).get()
                            if obj_user:
                                setattr(self, 'user', obj_user)
                                return origin(self, *args, **kwargs)

                    abort(401, message='Unauthorized')
                else:
                    raise Exception('Unsupported class')
            else:
                raise
            return origin(self, *args, **kwargs)
        return inner
    return func


def limit_access(func):
    """Limit access to fronted application."""
    def inner(self, *args, **kwargs):
        if issubclass(self.__class__, webapp2.RequestHandler):
            if 'HOST' in self.request.headers:
                if 'ALLOWED_HOSTS' in os.environ:
                    if self.request.headers.get('HOST') in os.environ['ALLOWED_HOSTS']:
                        print self.request.headers.get('HOST'), os.environ['ALLOWED_HOSTS']
                        return func(self)
                    else:
                        self.response.out.write(json.dumps({'status': 401, 'message': 'Unauthorized'}))
                        self.response.set_status(401)
                else:
                    self.response.out.write(json.dumps({'status': 401, 'message': 'Unauthorized: Please set ALLOWED_HOSTS environment variable'}))
                    self.response.set_status(401)
            else:
                self.response.out.write(json.dumps({'status': 401, 'message': 'Unauthorized'}))
                self.response.set_status(401)
    return inner
