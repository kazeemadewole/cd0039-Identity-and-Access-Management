import json
from flask import request, _request_ctx_stack, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen

AUTH0_DOMAIN = 'dev-ulzpoitd.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'https://127.0.0.1:8080/api'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():
    if 'Authorization' not in request.headers:
        raise AuthError({
            'code': 'Authorization_header_missng',
            'description': 'Authorization header is missing'
        }, 401)
 
    auth_header = request.headers['Authorization']
    header_parts = auth_header.split(' ')

    if len(header_parts) != 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token'
        }, 401)
    elif header_parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token'
        }, 401)
    return header_parts[1]

'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_permissions(permission, payload):
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'permissions not included in the token'
        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'Unauthorized',
            'description': 'permissions not found'
        }, 403)
    return True

'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    # jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    # jwks = json.loads(jsonurl.read())
    jwks = {"keys":[{"alg":"RS256","kty":"RSA","use":"sig","n":"r60GXJlduMcRA6_7HfRH3-KOCaH_u8Q-boIal8zMuoWpTzjzWPCbbi6IkNk-fZRNdOTc2F5uTQrd9QrbEC4yj2Kj5A4WUodFSCJJp40Rkgs_bmkE22xvCfDgavsSHIDoOs5zHzGVQSsF82VIHXWvRUU_8IoSC1zvAclTbgZf8YqTXeAdfFWnfL9TWsIina_LJTs6ROggm34ZW53Cwn5ZyDYn4LLCEB8qx1Uk5O4FIi9vTSZYTFC9c9hG4n1beFVO1yBOAVBCQI7luMG72-QoGQWvSDN5EbQGbLje5uneRFGzbtE8_PTT7_RH_60b6YADmvDm84MHvRgXoO6SKNrjIQ","e":"AQAB","kid":"xCjTTTG-z1h76pkzCGq-f","x5t":"3VNf7p-Tg-YJ9wbmqQS9qsEGp1I","x5c":["MIIDDTCCAfWgAwIBAgIJY9rOg8krE1U3MA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi11bHpwb2l0ZC51cy5hdXRoMC5jb20wHhcNMjIwNzIwMTExOTE1WhcNMzYwMzI4MTExOTE1WjAkMSIwIAYDVQQDExlkZXYtdWx6cG9pdGQudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr60GXJlduMcRA6/7HfRH3+KOCaH/u8Q+boIal8zMuoWpTzjzWPCbbi6IkNk+fZRNdOTc2F5uTQrd9QrbEC4yj2Kj5A4WUodFSCJJp40Rkgs/bmkE22xvCfDgavsSHIDoOs5zHzGVQSsF82VIHXWvRUU/8IoSC1zvAclTbgZf8YqTXeAdfFWnfL9TWsIina/LJTs6ROggm34ZW53Cwn5ZyDYn4LLCEB8qx1Uk5O4FIi9vTSZYTFC9c9hG4n1beFVO1yBOAVBCQI7luMG72+QoGQWvSDN5EbQGbLje5uneRFGzbtE8/PTT7/RH/60b6YADmvDm84MHvRgXoO6SKNrjIQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQG6P/+uwSuVjRpaYqJlWZ+vB9AhTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBADKhc5v0JPAKcVOSkXlSrw3Ri0oNUtqocIW2m1Ly49AGDnDishNZIDFFPsgnKtn3gpOtAjUDB62fCAt4IMsQNvEYulFlYFQOHeyser/nPTJIXvcPYDDIUmF+RXgs8dRxqJiVXEoYKvxFKTmpnEJAQ4d6GUHrcpMKcs73xNA8wXi8Hj4xqO5r0vn5DqAZp+nYrxymfpj0WtPuy9j+LeQyaezkoSTBkWOK/wzJsXvrgU2gVQijxZICpicqFxtZD0MFy0yp4jZVNzolAxpUIJA8RwtVSKdnKkOJBNBT98WDyx48ss0ml2vbhwuiSd1JemHyQf8sOa5gsnd5HpCtmZRwGbg="]},{"alg":"RS256","kty":"RSA","use":"sig","n":"xGe9SAypkclHHzAJCIVSppyOtJoRF3aPAsAB5TfdloHlkEzcD76EsxBIIyI8wLBngyEzXRs6z2zeyBvDHAd1G7yJd8Tvzzt7x9YjAUksv_NGMh59JG1zTzbX6GKN6A2t3kMbB8P_1z6LtugMgUKla73TkFH7PxB1F1tNF6RLJclJ0rTqfCOdfgpV60qhTz7-UmFA-HYABNW2Y5-ExuAB6bjCIf8oVFnJO3nROXvTab8OtcE_r-Vo80Es4ArvPnUr3DHGuoG87gnczkoksCdy3-c1zhbtWCqE4vCdnm5G2OOBCEhXQt0_bpyoD6yC3kPsYMdsGAZqknjMCUbgh3McKw","e":"AQAB","kid":"ijHx4H5HQmiacwLatlbwR","x5t":"SreswZcZGX2SqTKVdw7ljyWtyP8","x5c":["MIIDDTCCAfWgAwIBAgIJa+i+2Gi4hmeQMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNVBAMTGWRldi11bHpwb2l0ZC51cy5hdXRoMC5jb20wHhcNMjIwNzIwMTExOTE1WhcNMzYwMzI4MTExOTE1WjAkMSIwIAYDVQQDExlkZXYtdWx6cG9pdGQudXMuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxGe9SAypkclHHzAJCIVSppyOtJoRF3aPAsAB5TfdloHlkEzcD76EsxBIIyI8wLBngyEzXRs6z2zeyBvDHAd1G7yJd8Tvzzt7x9YjAUksv/NGMh59JG1zTzbX6GKN6A2t3kMbB8P/1z6LtugMgUKla73TkFH7PxB1F1tNF6RLJclJ0rTqfCOdfgpV60qhTz7+UmFA+HYABNW2Y5+ExuAB6bjCIf8oVFnJO3nROXvTab8OtcE/r+Vo80Es4ArvPnUr3DHGuoG87gnczkoksCdy3+c1zhbtWCqE4vCdnm5G2OOBCEhXQt0/bpyoD6yC3kPsYMdsGAZqknjMCUbgh3McKwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBT5jo7sLTtXp6Z/dp5/tC7MwpT2dTAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAHYvFAVX8h2CD4Tty5r8ONzKbY6AEqZBs2a6inyzZZJKgdhdzk/qbeY0mIlDbSu56lBNOXtzQ7BIYG+c3zqNbqJLS6zplkUh/HZR78wunRaSeSdnBTjX38qX1TxM0Gd1sRHsRGkOKGXLuGLn5GkRyr4uHCzSlvIsDruGI3Wh7x2G15j1UdiKhYrHlXPg2EB3gOkddIg246v7sMoXh4sEXFyUOpJzEzC3IQzLHPyaU2FFjvXqXVLAjd01rw8UzOTT4tmmaBhyGbxYkq7kAI+/RojLMUKPlEfQGDYlfTrm5an1zrsnHv3vv9r/OeaU0R8jBqmxDMKMXT3fw9neZ1PXFa4="]}]}
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )
            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
            }, 400)

'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            try:
                payload = verify_decode_jwt(token)
            except BaseException:
                abort(401)

            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator