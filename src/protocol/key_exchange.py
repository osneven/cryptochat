class KeyExchangeProtocol:

	# conn, the connection object to exchange keys with
	# private_rsa_key, the private key of which the public matching key will be exchanged with the connection
	# first_to_stage, if true, it sends the first packet, otherwise, it waits for the first packet to be sent
	def __init__(self, conn, private_rsa_key, first_to_stage=False):
		self._conn = conn
		self._private_rsa_key = private_rsa_key
		self._send_stage = first_to_stage

		# The ordered stage list of which packet types that has to be sent
		self._stages = [

			# Exchange public ECDH keys					# Client			Server
			self.PacketCodes.REQUEST_ECDH_PUBLIC_KEY,	#			<--
			self.PacketCodes.REPLY_ECDH_PUBLIC_KEY,		#			-->
			self.PacketCodes.REQUEST_NEXT,				#			<--
			self.PacketCodes.REQUEST_ECDH_PUBLIC_KEY,	#			-->
			self.PacketCodes.REPLY_ECDH_PUBLIC_KEY,		#			<--
		]

	# Starts the key exchange protocol
	def start(self):
		for stage in self._stages:
			if self._send_stage:
				self._send_stage(stage)
			else:
				self._recv_stage(stage)
			self._send_stage = !self._send_stage


	def _send_stage(self, stage):
		pass

	def _recv_stage(self, stage):
		pass


	# Encodes and returns a stage with some optional data
	# Encodes, such that the first byte of the data is the stage integer and the rest is the optional data
	# stage, the stage to encode
	# data, the data to encode with the stage. If this value is 'None', no data is appended
	def __encode_stage(self, stage, data=None):
		encoded_bytes = bytes([stage])
		if data is not None:
			if isinstance(data, bytes):
				raise TypeError("The data must be an instace of bytes")
			encoded_bytes += data
		return encoded_bytes

	# Decodes and returns a stage and some data. If no data was found, 'None' is returned after the stage
	# data, the data to decode
	def __decode_stage(self, data):
		if not isinstance(data, bytes):
			raise TypeError("The data must be an instance of bytes")
		if not len(data) > 1:
			raise ValueError("The data must contain a packet code")
		decoded_stage = data[0]
		if not decoded_stage in self.PacketCodes().__dict__():
			raise ValueError("The packet code '" + hex(decoded_stage) + "' is not recognized")
		decoded_data = None
		if len(data) > 2:
			decoded_data = data[1:]
		return decoded_stage, decoded_data


	# The packet codes used to identify the packet types
	class PacketCodes:
		# If any error occurs, e.g a bad key, out of sync stages or an unkown packet code
		# If this is recieved, send it back and then reset the protocol
		ERROR									= 0x0

		# Request the connection for its next request
		# No data needed
		REQUEST_NEXT							= 0x1

		# Request the connection for its public ECDH key
		# No data needed
		REQUEST_ECDH_PUBLIC_KEY					= 0x2

		# Reply the connection's public ECDH key request
		# Needs to be sent with the local public ECDH key
		REPLY_ECDH_PUBLIC_KEY					= 0x3

		# Request the connection to verify its shared ECDH key
		# Needs to be sent some random data, encrypted (AES-256) with the local shared ECDH key
		REQUEST_ECDH_SHARED_KEY_VERIFICATION	= 0x4

		# Reply the connection's shared ECDH verification request
		# Needs to be sent with the digest (SHA-256) of the random decrypted data, recieved by the request
		REPLY_ECDH_SHARED_KEY_VERIFICATION		= 0x5

		# Request the connection for its public RSA key, encrypted (AES-256) with the local shared ECDH key
		# No data needed
		REQUEST_ENCRYPTED_RSA_PUBLIC_KEY		= 0x6

		# Reply the connection's encrypted public RSA request
		# Needs to be sent with the local public RSA key, encrypted (AES-256) with the local shared ECDH key
		REPLY_ENCRYPTED_RSA_PUBLIC_KEY			= 0x7

		# Request the connection to verify the local copy of the remote public RSA key
		# Needs to be sent with some random data, encrypted with the local copy of the remote public RSA key
		REQUEST_RSA_PUBLIC_KEY_VERIFICATION		= 0x8

		# Reply the connection's public RSA key verification request
		# Needs to be sent with the digest (SHA-256) of the random decrypted data, recived by the request
		REPLY_RSA_PUBLIC_KEY_VERIFICATION		= 0x9

		@staticmethod
		def __dict__():
			packet_codes = {}
			for x in dir(KeyExchangeProtocol.PacketCodes):
				if not x.startswith("_") and x != "get_all_packet_codes":
					packet_codes[getattr(KeyExchangeProtocol.PacketCodes, x)] = x
			return packet_codes
