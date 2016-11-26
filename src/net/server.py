from threading import Thread
from session.key import KeySession
from session.communication import CommunicationSession
from protocol.key_exchange import KeyExchangeProtocol

class SocketServer:
	def __init__(self, host='', port=5555, max_clients=100):
		if not type(host) is str: raise TypeError("The host value must be a string")
		elif not type(port) is int: raise TypeError("The port value must be an integer")
		elif not type(max_clients) is int: raise TypeError("The max_clients value must be an integer")

		import socket
		self.__host = host
		self.__port = port
		self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.__max_clients = max_clients
		self.__client_threads = []

		self.__setup_socket()

	def __setup_socket(self):
		self.__sock.bind((self.__host, self.__port))

	def listen(self):
		self.__sock.listen(self.__max_clients)
		print("SERVER: Listening for clients ...")
		while True:
			conn, addr = self.__sock.accpet()
			self.__client_threads.append(self.__ClientThread(conn, addr))

	# Handles protocol to each remote
	class __ClientThread(Thread):
		def __init__(self, conn, addr):
			super().__init__()
			self.__conn = conn
			self.__addr = addr
			self.__comm_session = CommunicationSession()
			self.__comm_session.set_key_session(KeySession())
			self.__kep = KeyExchangeProtocol()
			self.__kep.set_comm_session(self.__comm_session)

		# This gets executed by Thread and acts as the main loop for the client
		def run(self):
			while 1:
				# Handle key exhange
				if not self.__kep.is_finished():
					out_data = self.__kep.encode()
					self.__send(out_data)
					in_data = self.__recv()
					keep_alive, message = self.__kep.decode(in_data)
					print("CLIENT ->\t", message)
					if not keep_alive:
						self.join()

		# Sends the data as a single packet to the client
		def __send(self, data):
			self.__conn.sendall(data)

		# Waits and returns the next incomming packet
		def __recv(self):
			return self.__conn.recv(2048)
