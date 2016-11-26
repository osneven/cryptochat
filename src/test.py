
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

#print("RSA private:", local_key.fingerprint(local_key.get_private_key_rsa()))
#print("RSA public:", local_key.fingerprint(local_key.get_public_key_rsa()))
#print("ECDH private:", local_key.fingerprint(local_key.get_private_key_ecdh()))
#print("ECDH public:", local_key.fingerprint(local_key.get_public_key_ecdh()))

# Clients
key_bytes = remote_key.get_public_key_ecdh_bytes()
key_fingerprint = KeySession.fingerprint(key_bytes)
key_signature = remote_comm.sign(key_fingerprint)
print("SIG LENGTH:",len(key_signature))
# Server
remote_bytes = local_key.get_remote_public_key_ecdh_bytes()
remote_fingerprint = KeySession.fingerprint(remote_bytes)
print("FF LENGTH:",len(remote_fingerprint))
remote_match = local_comm.verify(key_signature, remote_fingerprint)
print("Fingerprint client->server success:", remote_match)




from os import urandom
message = urandom(50)

## Local -> Remote
# Test AES encryption and decryption using the shared key
aes_ciphertext = local_comm.encrypt_shared(message)
aes_plaintext = remote_comm.decrypt_shared(aes_ciphertext)
print("AES success:", aes_plaintext == message)

# Test RSA encryption and decryption using the private and remote public RSA keys
rsa_ciphertext = local_comm.encrypt(message)
rsa_plaintext = remote_comm.decrypt(rsa_ciphertext)
print("RSA success:", rsa_plaintext == message)
