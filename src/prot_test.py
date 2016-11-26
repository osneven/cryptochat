from os import urandom
from session.communication import CommunicationSession
from session.key import KeySession
from protocol.key_exchange import KeyExchangeProtocol

### Test key echange protocol

## Initialize for local and remote

# Initialize key sessions
local_key_session = KeySession()
remote_key_session = KeySession()

# Initialize communication sessions
local_comm_session = CommunicationSession()
local_comm_session.set_key_session(local_key_session)
remote_comm_session = CommunicationSession()
remote_comm_session.set_key_session(remote_key_session)

# Initialize protocols
local_kep = KeyExchangeProtocol(server_side=True)
local_kep.set_comm_session(local_comm_session)
remote_kep = KeyExchangeProtocol(server_side=False)
remote_kep.set_comm_session(remote_comm_session)

print("Initiated")

## Exchange keys
print("Starting key exchange ...")

def handle(data, pad):
	print(pad+"\t"+data[1])
	if not data[0]:
		print("#ERROR#")
		exit()

# Step 0x0, plaintext ECDH exchange
packet_0 = local_kep.encode()
data_0 = remote_kep.decode(packet_0)
handle(data_0, "CLIENT")

packet_1 = remote_kep.encode()
data_1 = local_kep.decode(packet_1)
handle(data_1, "SERVER")

# Step 0x1, ciphertext (shared key encryption) RSA exchange
packet_2 = local_kep.encode()
data_2 = remote_kep.decode(packet_2)
handle(data_2, "CLIENT")

# Step 0x2, ciphertext (public key encryption) RSA exchange
packet_3 = remote_kep.encode()
data_3 = local_kep.decode(packet_3)
handle(data_3, "SERVER")

# Step 0x3, "authenticated"
packet_4 = local_kep.encode()
data_4 = remote_kep.decode(packet_4)
handle(data_4, "CLIENT")

## Test that RSA encryption now works

# Test local to remote encryption
message = urandom(50)
rsa_ciphertext_0 = local_comm_session.encrypt(message)
rsa_plaintext_0 = remote_comm_session.decrypt(rsa_ciphertext_0)
print("Local  -> Remote success:", rsa_plaintext_0 == message)

# Test remote to local encryption
message = urandom(50)
rsa_ciphertext_1 = remote_comm_session.encrypt(message)
rsa_plaintext_1 = local_comm_session.decrypt(rsa_ciphertext_1)
print("Remote -> Local success:", rsa_plaintext_1 == message)
