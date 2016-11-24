
# Testing of the key session
from session.key import KeySession

local_session = KeySession()
remote_session = KeySession()

local_session.set_remote_public_key_ecdh(remote_session.get_public_key_ecdh())
local_session.set_remote_public_key_rsa(remote_session.get_public_key_rsa())

print(len(local_session.get_shared_key()))
