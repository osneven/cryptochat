class SocketServer:
	from user_session import UserSession

	def __init__(self, host='', port=5555, max_clients=100):
		if not type(host) is str: raise TypeError("The host value must be a string")
		elif not type(port) is int: raise TypeError("The port value must be an integer")
		elif not type(max_clients) is int: raise TypeError("The max_clients value must be an integer")

		import socket
		self.__host = host
		self.__port = port
		self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.__max_clients = max_clients
		self.__user_sessions = []

		self.__setup_socket()

	def __setup_socket(self):
		self.__sock.bind((self.__host, self.__port))

	def listen(self):
		self.__sock.listen(self.__max_clients)
		print("SERVER: Listening for clients ...")
		while True:
			conn, addr = self.__sock.accpet()
			user_session = UserSession(conn, addr)
			user_session.listen()
			user_session.init_connection()
			self.__user_sessions.append(user_session)
