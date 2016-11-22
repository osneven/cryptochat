class UserSession:
	def __init__(self, conn, addr):
		self.__conn = conn
		self.__addr = addr
		self.__pending_messages = []
		self.__thread = None

	# Exchanges some information the server needs before talking with the client
	def init_connection(self):
		# Generate and send an unique public cryptography key
		# Get a nickname from the client

	# Creates a new thread that listens from data from the client
	def listen(self):
		from threading import Thread
		self.__thread = Thread(target=self.__listen_for_data)
		self.__thread.start()

	def __listen_for_data(self):
		while True:
			data = self.__conn.recv(20480)

			# IMPLEMENT CRYPTO HERE

			message = data.decode("UTF-8")
			self.__pending_messages.append(message)

	# Stops the thread and closes the connection
	def disconnect(self):
		if self.__thread is not None:
			self.__thread.join()
			self.__thread = None
		self.__conn.close()

	# Return the address as a string
	def __str__(self):
		return self.addr

	def get_conn(self):
		return self.__conn
	def get_addr(self):
		return self.__addr
