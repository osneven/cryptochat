from utils.exceptions import ProtocolHasFinishedError
from protocol.base import BaseProtocol
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import InvalidToken

# Protocol that handles the initial key exchange between the local and remote
class KeyExchangeProtocol(BaseProtocol):
	def __init__(self, server_side=True):
		super().__init__()
		self.__previous_stage_code = None
		self.__server_side = server_side
		self.__init_stage_codes()

	# Initialize the stage codes
	def __init_stage_codes(self):
		self.__stage_codes = {

			# This denotes the plaintext public ECDH key
			0x0 : ("ECDH_EXCHANGE", self.__encode_stage_0, self.__decode_stage_0),

			# This denotes the servers ciphertext public RSA key, encrypted using the shared key
			0x1	: ("RSA_EXCHANGE", self.__encode_stage_1, self.__decode_stage_1),

			# This denotes the clients ciphertext public RSA key, ecrypted using the servers public RSA key
			0x2	: ("RSA_EXCHANGE_REPLY", self.__encode_stage_2, self.__decode_stage_2),

			# This denotes a successful authentication with the server
			0x3	: ("SUCCESSFUL_AUTHENTICATION", self.__encode_stage_3, self.__decode_stage_3)
		}

	# Encodings for all the stage codes
	def __encode_stage_0(self): # Returns the plaintext public ECDH key
		return self._comm_session.get_key_session().get_public_key_ecdh_bytes()
	def __encode_stage_1(self): # Returns the ciphertext(shared key) public RSA key
		plaintext = self._comm_session.get_key_session().get_public_key_rsa_bytes()
		return self._comm_session.encrypt_shared(plaintext)
	def __encode_stage_2(self): # Returns the ciphertext(public key) public RSA key followed by its plaintext fingerprint
		key = self._comm_session.get_key_session().get_public_key_rsa_bytes()
		fingerprint = self._comm_session.get_key_session().fingerprint(key)
		return self._comm_session.encrypt(key) + fingerprint
	def __encode_stage_3(self):
		return b""

	# Decodings for all the stage codes
	# Return (True, feedback string) for success, retrun (False, error string)
	def __decode_stage_0(self, data): # Data should contain the plaintext remote public ECDH key
		self._comm_session.get_key_session().set_remote_public_key_ecdh_bytes(data)
		return (True, "Remote public ECDH key recieved")
	def __decode_stage_1(self, data): # Data should contain the ciphertext(shared key) remote public RSA key
		try:
			plaintext = self._comm_session.decrypt_shared(data)
		except InvalidToken:
			return (False, self.__stage_codes[0x1] + " - ERROR - Shared key couldn't decrypt the remote public RSA key")
		self._comm_session.get_key_session().set_remote_public_key_rsa_bytes(plaintext)
		return (True, "Remote public RSA key recieved")
	def __decode_stage_2(self, data): # Data should contain the ciphertext(public key) remote public RSA key followed by its plaintext fingerprint
		cipher_key = data[:-32]
		fingerprint = data[-32:]
		key = self._comm_session.decrypt(cipher_key)
		try:
			match = self._comm_session.get_key_session().fingerprint(key) == fingerprint
		except InvalidSignature:
			return (False, self.__stage_codes[0x2] + " - ERROR - Calculated fingerprint does not match the recieved")
		self._comm_session.get_key_session().set_remote_public_key_rsa_bytes(key)
		return (True, "Remote public RSA key recieved and verified")
	def __decode_stage_3(self, data):
		return (True, "Successfully authenticated")

	# Decodes and handles the data
	# data, the raw data to use
	def decode(self, data):
		self._ensure_has_comm_session()
		if not isinstance(data, bytes):
			raise TypeError("The data must be an instance of bytes")

		# Decode stage code
		if len(data) < 1:
			raise ValueError("No data was parsed")
		stage_code = data[0]
		if not stage_code in list(self.__stage_codes):
			raise ValueError("Unrecognized stage code")
		self.__previous_stage_code = stage_code
		self._finished = stage_code == 0x3

		# Decode the rest of the data
		out = self.__stage_codes[stage_code][2](data[1:])
		return out

	# Encodes and returns the data to be sent
	def encode(self):
		if self._finished:
			raise ProtocolHasFinishedError("The key exchanged has already completed")
		self._ensure_has_comm_session()

		# Encode the stage code
		if (self.__server_side and self.__previous_stage_code is None) or (not self.__server_side and self.__previous_stage_code == 0x0):
			stage_code = 0x0
		else:
			stage_code = self.__previous_stage_code + 1
		stage_code_bytes = bytes([stage_code])
		self.__previous_stage_code = stage_code

		# Encode the needed data
		data_bytes = self.__stage_codes[stage_code][1]()

		return stage_code_bytes + data_bytes
