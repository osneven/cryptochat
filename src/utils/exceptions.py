
# Raised when trying to retrive a local key before it has been generated
class KeyNotGeneratedError(Exception):
	def __init__(self, message):
		super().__init__(message)

# Raised when trying to regenerate a local key
class KeyAlreadyGeneratedError(Exception):
	def __init__(self, message):
		super().__init__(message)

# Raised when trying to retrieve a remote public key before it has been recieved
class RemoteKeyNotRecievedError(Exception):
	def __init__(self, message):
		super().__init__(message)

# Raised when trying to encode a shared key before its been derived
class KeyNotDerivedError(Exception):
	def __init__(self, message):
		super().__init__(message)

# Raised when trying to retrieve a cipher suite before a key session has been set
class MissingKeySessionError(Exception):
	def __init__(self, message):
		super().__init__(message)

# Raised when trying to decode/encode packet data before a communication session has been set
class MissingCommunicationSessionError(Exception):
	def __init__(self, message):
		super().__init__(message)

# Raised when trying to encode a new message after a protocol has finished
class ProtocolHasFinishedError(Exception):
	def __init__(self, message):
		super().__init__(message)
