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


def verify_client(self, client):
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
                        decoded_token = verify_jwt_flask(
                            inbound_app_id,
                            obj_client.client_secret,
                            obj_client.verify_expiration\
                            if hasattr(obj_client, 'verify_expiration') else True)
                        if decoded_token:
                            if 'Origin' in request.headers:
                                if (
                                    request.remote_addr == '127.0.0.1' and
                                    'localhost' in request.headers.get('Origin')
                                ) or request.remote_addr != '127.0.0.1':
                                    if obj_client.urls_white_list:
                                        if request.headers.get('Origin') in obj_client.urls_white_list:
                                            return obj_client
                                        else:
                                            abort(403, message='Forbbiden: origin is not allowed')
                                    else:
                                        abort(403, message='Forbbiden: client does not have configured origin hosts')
                                else:
                                    abort(401, message='Unauthorized')
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


def verify_user(self, user):
    if self:
        if issubclass(self.__class__, Resource):
            logging.warning('verifying user requests')
            if 'Authorization' in request.headers:
                authorization_header = request.headers.get('Authorization')
                inbound_app_id = authorization_header.split(' ')[1]
                client_info = get_client_info_from_token(inbound_app_id)
                settings = get_configuration_from_file()
                user_settings = settings['User']['Fields']
                profile_id = client_info.get('user', {}).get(user_settings['UserId'])
                email = client_info.get('user', {}).get(user_settings['Email'], '')

                if profile_id:
                    obj_user = user.query(getattr(user, user_settings['UserId']) == profile_id).get()
                    if obj_user:
                        logging.debug(
                            'user in decorator: id:%s, email:%s, incomming_email:%s',
                            obj_user.profile_id, 
                            obj_user.email, email)
                        if email.lower() != obj_user.email.lower():
                            abort(498, message='Invalid email')
                        return(obj_user)
                    else:
                        abort(401, message='User not found')
                else:
                    abort(401, message='Configuration issue')
            else:
                abort(401, message='Unauthorized')
        else:
            raise Exception('Unsupported class')
    else:
        raise
    return ''


def verify_jwt_flask(token, secret, verify_exp=True):
    """Verify if token is valid."""
    options = {
        'verify_signature': True,
        'verify_exp': verify_exp
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
            obj_client = verify_client(self, client)
            setattr(self, 'client', obj_client)
            return origin(self, *args, **kwargs)
        return inner
    return func


def verify_user_request(user):
    """Verify requests from web clients."""
    def func(origin):
        """Inner."""
        def inner(self, *args, **kwargs):
            """Inner."""
            obj_user = verify_user(self, user)
            if obj_user != '':
                setattr(self, 'user', obj_user)
            return origin(self, *args, **kwargs)
        return inner
    return func


def verify_client_and_user_request(user, client):
    """Verify requests from web clients."""
    def func(origin):
        """Inner."""
        def inner(*args, **kwargs):
            self = origin.__self__
            obj_client = verify_client(self, client)
            setattr(origin.__self__, 'client', obj_client)
            obj_user = verify_user(self, user)
            if obj_user != '':
                setattr(origin.__self__, 'user', obj_user)
            return origin(*args, **kwargs)
        return inner

    return func


def limit_access(func):
    """Limit access to fronted application."""
    def inner(self, *args, **kwargs):
        if issubclass(self.__class__, webapp2.RequestHandler):
            if 'Origin' in self.request.headers:
                if 'ALLOWED_HOSTS' in os.environ:
                    if self.request.headers.get('Origin') in os.environ['ALLOWED_HOSTS']:
                        print self.request.headers.get('Origin'), os.environ['ALLOWED_HOSTS']
                        return func(self,*args, **kwargs)
                    else:
                        self.response.out.write(json.dumps({'status': 401, 'message': 'Unauthorized'}))
                        self.response.set_status(401)
                else:
                    self.response.out.write(json.dumps({'status': 401, 'message': 'Unauthorized: Please set ALLOWED_HOSTS environment variable'}))
                    self.response.set_status(401)
            else:
                self.response.out.write(json.dumps({'status': 401, 'message': 'Unauthorized'}))
                self.response.set_status(401)
        elif issubclass(self.__class__, Resource):
            if 'Origin' in request.headers:
                if 'ALLOWED_HOSTS' in os.environ:
                    if request.headers.get('Origin') in os.environ['ALLOWED_HOSTS']:
                        print request.headers.get('Origin'), os.environ['ALLOWED_HOSTS']
                        return func(self,*args, **kwargs)
                    else:
                        abort(401, message="Unauthorized no allowed_host")
                else:
                    abort(401, message="Unauthorized: Please set ALLOWED_HOSTS environment variable")
            else:
                abort(401, message="Unauthorized no origin")
    return inner