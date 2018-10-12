import jwt
from jwt.exceptions import InvalidSignatureError
import base64

private_key = open('sample_private.key','r').read()
public_key = open('sample_public.key','r').read()

# it follows the claims i want to sign
claims = { 'email' : 'john.doe@example.com', 'role': 'standard_user' }

print ('encoding the following claims')
print (claims)

encoded_jwt = jwt.encode(claims, private_key, algorithm='RS256')

print ('here is the encoded signed token')

print (encoded_jwt)

print ('validating and decoding...')

decoded_jwt = jwt.decode(encoded_jwt, public_key)

print (decoded_jwt)

print ('Now I try to tamper the token changing the John Doe''s role from standard_user to admin')

print ('tampering..')

encoded_jwt_splitted = encoded_jwt.split(b'.')

encoded_jwt_header = encoded_jwt_splitted[0]

encoded_jwt_payload = encoded_jwt_splitted[1]

encoded_jwt_signature = encoded_jwt_splitted[2]

print (encoded_jwt_payload)

# added extra padding (=) to avoid b64decode raising an exception: 
# https://stackoverflow.com/questions/2941995/python-ignore-incorrect-padding-error-when-base64-decoding
decoded_jwt_payload = base64.b64decode(encoded_jwt_payload + b'=' * (-len(encoded_jwt_payload) % 4))

tampered_decoded_jwt_payload = decoded_jwt_payload.replace(b'standard_user', b'admin')

tampered_encoded_jwt_payload = base64.b64encode(tampered_decoded_jwt_payload)

tampered_encoded_jwt = encoded_jwt_header + b'.' + tampered_encoded_jwt_payload + b'.' + encoded_jwt_signature

print ('here is the tampered token')

print (tampered_encoded_jwt)

print ('validating and decoding tampered jwt')

try:
    tampered_decoded_jwt = jwt.decode(tampered_encoded_jwt, public_key)

except InvalidSignatureError as e:
    print(e)
    quit(-1)

print (tampered_decoded_jwt)
quit(0)