
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