class KeyExchangeProtocol:

	# conn, the connection object to exchange keys with
	# private_rsa_key, the private key of which the public matching key will be exchanged with the connection
	# first_to_stage, if true, it sends the first packet, otherwise, it waits for the first packet to be sent
	def __init__(self, conn, private_rsa_key, first_to_stage=False):
		self._conn = conn
		self._private_rsa_key
		self._send_stage = first_to_stage

		# The ordered stage list of which packet types that has to be sent
		self._stages = [

			# Exchange public ECDH keys				# Client			Server
			PacketCodes.REQUEST_ECDH_PUBLIC_KEY,	#			<--
			PacketCodes.REPLY_ECDH_PUBLIC_KEY,		#			-->
			PacketCodes.REQUEST_NEXT,				#			<--
			PacketCodes.REQUEST_ECDH_PUBLIC_KEY,	#			-->
			PacketCodes.REPLY_ECDH_PUBLIC_KEY,		#			<--
		]

	# Starts the key exchange protocol
	def start(self):
		for stage in self._stages:


	def __next_stage(self, stage):
		if self._send_stage:
			bytes_to_send = stage[1](self)

		# Change stage sending turn
		self._send_stage = not self._send_stage

	def __encode_stage(self, stage, data=None):
		pass

	def __decode_stage(self, stage, data):
		if not isinstance(data, bytes):
			raise TypeError("data must be an instance of 'bytes'")
		if not len(data) > 1:
			raise ValueError("data must contain a packet code")

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
