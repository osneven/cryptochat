from session.communication import CommunicationSession
from utils.exceptions import MissingCommunicationSessionError

# Super class for all needed protocol
class BaseProtocol:
	def __init__(self):
		self.__has_comm_session = False

	# Checks if a communication session has been set, if not raises an error
	def _ensure_has_comm_session(self):
		if not self.__has_comm_session:
			raise MissingCommunicationSessionError("No communication session is set")

	# Sets the communication session
	# comm_session, the communication session to use
	def set_comm_session(self, comm_session):
		if not isinstance(comm_session, CommunicationSession):
			raise TypeError("The key_session must be an instance of CommunicationSession")
		self.__comm_session = comm_session
		self.__has_comm_session = True
