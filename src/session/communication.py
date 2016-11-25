import os
from session.key import KeySession
from utils.exceptions import MissingKeySessionError
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# A session that handles cipher communication between the local and remote
class CommunicationSession:
	def __init__(self):
		self.__has_key_session = False

	# Sets the key session used for cipher communication
	# This also initializes the cipher suites
	# key_session, the key session to use
	def set_key_session(self, key_session):
		if not isinstance(key_session, KeySession):
			raise TypeError("The key_session must be an instance of KeySession")
		self.__key_session = key_session
		self.__has_key_session = True
		self.__rsa_suite = self.__RSASuite(self.__key_session)
		self.__aes_suite = self.__AESSuite(self.__key_session)

	# Checks for, and raises if neseccary, a MissingKeySessionError
	def __ensure_has_key_session(self):
		if not self.__has_key_session:
			raise MissingKeySessionError("No key session is set")

	# Returns the RSA suite
	def get_rsa_suite(self):
		self.__ensure_has_key_session()
		return self.__rsa_suite

	# Returns the AES suite
	def get_aes_suite(self):
		self.__ensure_has_key_session()
		return self.__aes_suite

	# Super for all the needed suits
	class __Suite:

		# key_session, the key session to encrypt and decrypt with
		def __init__(self, key_session):
			self._key_session = key_session

		# Encrypts the plaintext, and returns its ciphertext
		# plaintext, the byte message to encrypt
		def encrypt(self, plaintext):
			if not isinstance(plaintext, bytes):
				raise TypeError("The plaintext must be an instance of bytes")

		# Decrypts the ciphertext, and returns its plaintext
		# ciphertext, the byte message to decrypt
		def decrypt(self, ciphertext):
			if not isinstance(ciphertext, bytes):
				raise TypeError("The ciphertext must be an instance of bytes")

	# Handles RSA assymmetric encryption and decryption
	class __RSASuite(__Suite):

		# key_session, the key session to encrypt and decrypt with
		def __init__(self, key_session):
			super().__init__(key_session)

		# Encrypts the plaintext using the public remote RSA key, and returns its ciphertext
		# plaintext, the byte message to encrypt
		def encrypt(self, plaintext):
			super().encrypt(plaintext)
			plaintext_parts = []
			[ plaintext_parts.append(plaintext[i:][:470]) for i in list(range(0, len(plaintext), 470)) ]
			return self.__encrypt_parts(plaintext_parts)

		# Encrypt each plaintext part and append them to each other, returns the ciphertext in one piece
		def __encrypt_parts(self, plaintext_parts):
			ciphertext = b""
			for part in plaintext_parts:
				ciphertext += self._key_session.get_remote_public_key_rsa().encrypt(
					part,
					self.__get_padding()
				)
			return ciphertext

		# Decrypts the ciphertext using the private RSA key, and returns its plaintext
		# ciphertext, the byte message to decrypt
		def decrypt(self, ciphertext):
			super().decrypt(ciphertext)
			ciphertext_parts = []
			size = int(self._key_session.get_private_key_rsa().key_size/8)
			[ ciphertext_parts.append(ciphertext[i:][:size]) for i in list(range(0, len(ciphertext), size)) ]
			return self.__decrypt_parts(ciphertext_parts)

		# Decrypt each ciphertext part and append them to each other, returns the plaintext in one piece
		def __decrypt_parts(self, ciphertext_parts):
			plaintext = b""
			for part in ciphertext_parts:
				plaintext += self._key_session.get_private_key_rsa().decrypt(
					part,
					self.__get_padding()
				)
			return plaintext

		# Returns the padding type used for encryption and decryption
		def __get_padding(self):
			from cryptography.hazmat.primitives.asymmetric import padding
			return padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA1()),
				algorithm=hashes.SHA1(),
				label=None
			)

	# Handles AES symmetric encryption and decryption
	# This functions as a wrapper for the Fernet object while implementing a KeySession
	class __AESSuite(__Suite):

		# key_session, the key session to encrypt and decrypt with
		def __init__(self, key_session):
			super().__init__(key_session)
			self.__fernet = Fernet(key_session.get_shared())

		# Encrypts the plaintext using the shared "AES" key, and returns its ciphertext and the iv
		# Return foramt: IV(128 bits) || Ciphertext(multiple of 128 bits)
		# plaintext, the byte message to encrypt
		def encrypt(self, plaintext):
			super().encrypt(plaintext)
			return self.__fernet.encrypt(plaintext)

		# Decrypts the ciphertext using the shared "AES" key, and returns its plaintext
		# ciphertext, the byte message to decrypt
		def decrypt(self, ciphertext):
			super().decrypt(ciphertext)
			return self.__fernet.decrypt(ciphertext)
