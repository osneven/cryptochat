from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC
from utils.exceptions import KeyNotGeneratedError, RemoteKeyNotRecievedError, KeyAlreadyGeneratedError

# A session that holds and manages the cryptography keys needed for communication between the local and remote
class KeySession:

	def __init__(self):
		self.__rsa_key = self.__RSAKeyHold()
		self.__ecdh_key = self.__ECDHKeyHold()
		self.__shared_key = self.__SharedKeyHold()
		self.reload_session()

	# Generates and stores both the private ECDH and RSA keys
	def reload_session(self):

		# Reset all the keys
		self.__rsa_key.reset()
		self.__ecdh_key.reset()
		self.__shared_key.reset()

		# Generate the keys that can be
		self.__rsa_key.generate()
		self.__ecdh_key.generate()

	# Returns the private local keys
	def get_private_key_rsa(self): return self.__rsa_key.get_private()
	def get_private_key_ecdh(self): return self.__ecdh_key.get_private()
	def get_shared_key(self): return self.__shared_key.get_private()

	# Returns the public local keys
	def get_public_key_rsa(self): return self.__rsa_key.get_public()
	def get_public_key_ecdh(self): return self.__ecdh_key.get_public()

	# Sets the public remote keys
	def set_remote_public_key_ecdh(self, key): # This also generates the shared private key
		self.__ecdh_key.set_public_remote(key)
		self.__shared_key.generate(self.__ecdh_key.get_private(), self.__ecdh_key.get_public_remote())
	def set_remote_public_key_rsa(self, key): self.__rsa_key.set_public_remote(key)

	# Returns the public remote keys
	def get_remote_public_key_ecdh(self): return self.__ecdh_key.get_public_remote()
	def get_remote_public_key_rsa(self): return self.__rsa_key.get_public_remote()

	# Super class for all the needed keys in the session
	class __KeyHold:
		def __init__(self):
			self.reset()

		# Sets the key as 'not' generated
		def reset(self):
			self._generated = False

		# Generates a key
		def generate(self):
			if self._generated:
				raise KeyAlreadyGeneratedError("The key has already been generated")
			self._generated = True

		# Returns true if the generation method is called
		def is_generated(self):
			return self._generated

	# Generates and holds the exchanged shared key
	class __SharedKeyHold(__KeyHold):

		def __init__(self):
			super().__init__()
			self.__salt = b'\xe6\xb3\xdf\x8e\xbc\x95\x94Qi%)a"o\xde\xcb' # TODO: Load this from a config file
			self.__otherinfo = b'Derivation of the exchanged ECDH key.'

		def reset(self):
			super().reset()

		# Generates and derives the shared key from the private and public keys
		# private_key, the private elliptic curve key
		# public_key, the public elliptic curve key
		def generate(self, private_key, public_key):
			super().generate()
			if not isinstance(private_key, EllipticCurvePrivateKey):
				raise TypeError("The private_key must be an instance of EllipticCurvePrivateKey")
			if not isinstance(public_key, EllipticCurvePublicKey):
				raise TypeError("The public_key must be an instance of EllipticCurvePublicKey")
			shared_key = private_key.exchange(ec.ECDH(), public_key)
			self.__private_key = self.__derive_key(shared_key)

		# Derives and returns a key
		def __derive_key(self, key):
			ckdf = ConcatKDFHMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=self.__salt,
			otherinfo=self.__otherinfo,
			backend=default_backend())
			return ckdf.derive(key)

		def get_private(self):
			if not self._generated:
				raise KeyNotGeneratedError("The shared key has not been generated")
			return self.__private_key

	# Super class for all the needed assymmetric keys in the session
	class __AssymmetricKeyHold(__KeyHold):
		def __init__(self):
			super().__init__()

		# Sets the remote public key as 'not' recieved
		def reset(self):
			super().reset()
			self._recieved_remote = False

		# Returns the local private key
		def get_private(self):
			if not self._generated:
				raise KeyNotGeneratedError("The assymmetric key has not been generated")
			return self._private_key

		# Returns the local public key
		def get_public(self):
			return self.get_private().public_key()

		# Sets the remote public key as 'recieved'
		def set_public_remote(self):
			self._recieved_remote = True

		# Returns the remote public key
		def get_public_remote(self):
			if not self._recieved_remote:
				raise RemoteKeyNotRecievedError("The remote public key has not been recieved")
			return self._remote_public_key

	# Generates and holds the local RSA key pair and remote public key
	class __RSAKeyHold(__AssymmetricKeyHold):
		def __init__(self):
			super().__init__()

		# Generates a RSA key pair
		def generate(self):
			super().generate()
			self._private_key = rsa.generate_private_key(
				public_exponent=65537,
				key_size=2048,
				backend=default_backend())

		# Sets the remote public RSA key
		# key, the key to set
		def set_public_remote(self, key):
			super().set_public_remote()
			if not isinstance(key, RSAPublicKey):
				raise TypeError("The public key must be an instance of RSAPublicKey")
			self._remote_public_key = key

	# Generates and holds the local ECDH key pair and remote public key
	class __ECDHKeyHold(__AssymmetricKeyHold):
		def __init__(self):
			super().__init__()

		# Generates a ECDH key pair, using the secp256k1 curve
		def generate(self):
			super().generate()
			self._private_key = ec.generate_private_key(
				ec.SECP256K1(),
				default_backend())

		# Sets the remote public ECDH key
		# key, the key to set
		def set_public_remote(self, key):
			super().set_public_remote()
			if not isinstance(key, EllipticCurvePublicKey):
				raise TypeError("The public key must be an instance of EllipticCurvePublicKey")
			self._remote_public_key = key
