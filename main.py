import os
import logging
import logging.handlers
import sys
import jwt
import requests

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    filename="./app.log",
    encoding="utf-8",
    format="{levelname}:{asctime}:{message}",
    level=logging.DEBUG,
    style="{",
    datefmt="%Y-%m-%d %H:%M"
)

TENANT_ID = os.environ.get("TENANT_ID")
if TENANT_ID is None:
    logging.error("TENANT_ID environment variable is not set")
    exit(1)
else:
    # check if TENANT_ID contains double quotes
    if TENANT_ID[0] == '"' or TENANT_ID[-1] == '"':
        TENANT_ID = eval(TENANT_ID)

CLIENT_IDS = os.environ.get("CLIENT_IDS")
if CLIENT_IDS is None:
    logging.error("CLIENT_IDS environment variable is not set")
    exit(1)
else:
    CLIENT_IDS = CLIENT_IDS.split(",")
    # check if CLIENT_IDS contains double quotes
    for i in range(len(CLIENT_IDS)):
        if CLIENT_IDS[i][0] == '"' or CLIENT_IDS[i][-1] == '"':
            CLIENT_IDS[i] = eval(CLIENT_IDS[i])


class JwtData:
    def __init__(self, iss, client_id, x5t, kid, ):
        self.iss = iss
        self.client_id = client_id
        self.x5t = x5t
        self.kid = kid


class DecodedJwt:
    def __init__(self, token_value):
        self.token = token_value

    def decode(self):
        result = jwt.decode(self.token, options={"verify_signature": False})
        headers = jwt.get_unverified_header(self.token)
        return JwtData(iss=result["iss"], client_id=result["appid"], x5t=headers["x5t"], kid=headers["kid"])


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
        logging.debug(open_id_configuration.json())
        jwks_uri = open_id_configuration.json()["jwks_uri"]
        logging.debug("JWKS URI: ", jwks_uri)
        keys = requests.get(jwks_uri).json()["keys"]
        logging.debug("Keys: ", keys)
        for key in keys:
            if key["kid"] == decoded_jwt_data.kid and key["x5t"] == decoded_jwt_data.x5t:
                return True
    except Exception as e:
        print("An error occurred: ", e)
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


if __name__ == '__main__':
    header_token = sys.argv[1] + " " + sys.argv[2]
    logging.debug("Header token: ", header_token)
    token = extract_token_from_header(header_token)
    logging.debug("Token: ", token)
    decoded_jwt = DecodedJwt(add_padding(token))
    decoded = decoded_jwt.decode()
    logging.debug("ISS: ", decoded.iss)
    logging.debug("Client ID: ", decoded.client_id)
    logging.debug("X5T: ", decoded.x5t)
    logging.debug("KID: ", decoded.kid)
    is_valid_issuer = check_issuer(decoded)
    is_valid_client_id = check_client_id(decoded)
    is_valid_signature = check_signature(decoded)
    logging.debug("Is valid issuer: ", is_valid_issuer)
    logging.debug("Is valid client id: ", is_valid_client_id)
    logging.debug("Is valid signature: ", is_valid_signature)
    if is_valid_issuer and is_valid_client_id and is_valid_signature:
        logging.info("JWT is valid")
    else:
        logging.info("JWT is invalid")
