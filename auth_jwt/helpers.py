import json
import base64

CONFIG_FILE_PATH = 'auth_jwt_settings.json'


def get_client_info_from_token(token):
    """get_user_info_from_token."""
    # JWT is in three parts, header, token, and signature
    # separated by '.'.
    token_parts = token.split('.')
    encoded_token = token_parts[1]

    # Base64 strings should have a length divisible by 4.
    # If this one doesn't, add the '=' padding to fix it.
    leftovers = len(encoded_token) % 4
    if leftovers == 2:
        encoded_token += '=='
    elif leftovers == 3:
        encoded_token += '='

    # URL-safe base64 decode the token parts.
    decoded = base64.urlsafe_b64decode(
        encoded_token.encode('utf-8')).decode('utf-8')

    # Load decoded token into a JSON object.
    jwt = json.loads(decoded)

    return jwt


def get_configuration_from_file():
    """Get configuration from configuration file."""
    with open(CONFIG_FILE_PATH) as data_file:
        settings = json.load(data_file)
        data_file.close()

        return settings
