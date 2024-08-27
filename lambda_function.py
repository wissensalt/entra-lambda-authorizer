import jwt
import requests
import os
import logging

logger = logging.getLogger()
logger.setLevel("DEBUG")

TENANT_ID = os.environ.get("TENANT_ID")
if TENANT_ID is None:
    exit(1)

CLIENT_IDS = os.environ.get("CLIENT_IDS").split(",")
if CLIENT_IDS is None:
    exit(1)


class JwtData:
    def __init__(self, iss, client_id, x5t, kid):
        self.iss = iss
        self.client_id = client_id
        self.x5t = x5t
        self.kid = kid


class DecodedJwt:
    def __init__(self, token_value):
        self.token = token_value

    def decode(self):
        try:
            result = jwt.decode(self.token, options={"verify_signature": False})
            headers = jwt.get_unverified_header(self.token)
            return JwtData(iss=result["iss"], client_id=result["appid"], x5t=headers["x5t"], kid=headers["kid"])
        except Exception as e:
            logger.error("An error occurred during decode JWT: %s", e)
            return None


def check_issuer(decoded_jwt_data):
    tenant_id = decoded_jwt_data.iss.split("/")[-2]
    if tenant_id != TENANT_ID:
        return False
    return True


def check_client_id(decoded_jwt_data):
    if decoded_jwt_data.client_id not in CLIENT_IDS:
        return False
    return True


def check_signature(decoded_jwt_data):
    open_id_url = "https://login.microsoftonline.com/" + TENANT_ID + "/.well-known/openid-configuration?appid=" + decoded_jwt_data.client_id
    try:
        open_id_configuration = requests.get(open_id_url)
        jwks_uri = open_id_configuration.json()["jwks_uri"]
        keys = requests.get(jwks_uri).json()["keys"]
        for key in keys:
            if key["kid"] == decoded_jwt_data.kid and key["x5t"] == decoded_jwt_data.x5t:
                return True
    except Exception as e:
        logger.error("An error occurred during check signature: %s", e)
    return False


def extract_token_from_header(header):
    # check if header contains Bearer
    if "Bearer" not in header:
        return None
    # check if header contains token
    if len(header.split(" ")) < 2:
        return None
    # check if header contains . which is a separator for JWT
    result = header.split(" ")[1]
    if "." not in result:
        return None
    return result


# add padding to encoded string
def add_padding(encoded_str):
    return encoded_str + '=' * (-len(encoded_str) % 4)


def generate_response(is_allowed):
    auth = 'Deny'
    if is_allowed:
        auth = 'Allow'

    return {
        "principalId": "user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement":
                [
                    {
                        "Action": "execute-api:Invoke",
                        "Resource": [
                            "arn:aws:execute-api:{REGION}:{API}/{STAGE}/{METHOD}/{RESOURCE}"
                        ],
                        "Effect": auth
                    }
                ]
        }
    }


def lambda_handler(event, context):
    is_allowed = False
    header_token = event['authorizationToken']
    logger.debug("Header Token: " + header_token)
    if header_token is None:
        return generate_response(is_allowed)

    logger.debug("TENANT_ID: " + TENANT_ID)
    logger.debug("CLIENT_IDS: " + str(CLIENT_IDS))
    token = extract_token_from_header(header_token)
    logger.debug("Token: " + token)
    if token is None:
        return generate_response(is_allowed)
    decoded_jwt = DecodedJwt(add_padding(token))
    decoded = decoded_jwt.decode()
    if decoded is None:
        return generate_response(is_allowed)
    is_valid_issuer = check_issuer(decoded)
    logger.debug("Is valid issuer: " + str(is_valid_issuer))
    is_valid_client_id = check_client_id(decoded)
    logger.debug("Is valid client id: " + str(is_valid_client_id))
    is_valid_signature = check_signature(decoded)
    logger.debug("Is valid signature: " + str(is_valid_signature))

    if is_valid_issuer and is_valid_client_id and is_valid_signature:
        is_allowed = True

    return generate_response(is_allowed)
