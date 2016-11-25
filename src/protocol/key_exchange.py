from protocol.base import BaseProtocol

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
	def __encode_stage_0(self, data):
		pass
	def __encode_stage_1(self, data):
		pass
	def __encode_stage_2(self, data):
		pass
	def __encode_stage_3(self, data):
		pass

	# Decodings for all the stage codes
	def __decode_stage_0(self, data):
		pass
	def __decode_stage_1(self, data):
		pass
	def __decode_stage_2(self, data):
		pass
	def __decode_stage_3(self, data):
		pass

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

		# Decode the rest of the data
		self.__previous_stage_code = stage_code
		self.__stage_codes[stage_code][1](data[1:])
