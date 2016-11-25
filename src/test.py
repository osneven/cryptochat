
### Key sessions
from session.key import KeySession
local_key = KeySession()
remote_key = KeySession()

# Exchange public ECDH keys, the shared key is also generated here
local_key.set_remote_public_key_ecdh(remote_key.get_public_key_ecdh())
remote_key.set_remote_public_key_ecdh(local_key.get_public_key_ecdh())

# Exchange public RSA keys
local_key.set_remote_public_key_rsa(remote_key.get_public_key_rsa())
remote_key.set_remote_public_key_rsa(local_key.get_public_key_rsa())

### Communication sessions
from session.communication import CommunicationSession
local_comm = CommunicationSession()
remote_comm = CommunicationSession()
local_comm.set_key_session(local_key)
remote_comm.set_key_session(remote_key)

from os import urandom
message = urandom(5000)

## Local -> Remote
# Test AES encryption and decryption using the shared key
aes_ciphertext = local_comm.get_aes_suite().encrypt(message)
aes_plaintext = remote_comm.get_aes_suite().decrypt(aes_ciphertext)
print("AES success:", aes_plaintext == message)

# Test RSA encryption and decryption using the private and remote public RSA keys
rsa_ciphertext = local_comm.get_rsa_suite().encrypt(message)
rsa_plaintext = remote_comm.get_rsa_suite().decrypt(rsa_ciphertext)
print("RSA success:", rsa_plaintext == message)
