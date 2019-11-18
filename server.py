import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import re
import os
from aio_tcpserver import tcp_server
import symmetric_encryption
import assymetric_encryption
import handshake_ec
import assymetric_encryption
from hmac_generator import buildHMAC

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_NEGOTIATE = 1
STATE_READY = 2
STATE_OPEN = 3
STATE_DATA = 4
STATE_ROTATE = 5
STATE_CLOSE= 6

#GLOBAL
storage_dir = 'files'

class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor
		"""
		self.signal = signal
		self.state = 0
		self.file = None
		self.file_name = None
		self.file_path = None
		self.storage_dir = storage_dir
		self.buffer = ''
		self.peername = ''

	def connection_made(self, transport) -> None:	#Override from asyncio.BaseProtocol
		"""
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
		self.peername = transport.get_extra_info('peername')
		logger.info('\n\nConnection from {}'.format(self.peername))
		self.transport = transport
		self.rsa_server_private_key = assymetric_encryption.getPrivateKeyFromBytes( open("server_private_key.pem","rb").read())
		self.rsa_client_public_key = assymetric_encryption.getPublicKeyFromBytes( open("client_public_key.pem", "rb").read() )
		self.state = STATE_CONNECT


	def data_received(self, data: bytes) -> None:	#Override from asyncio.Protocol
		"""
        Called when data is received from the client.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
		logger.debug('Received: {}'.format(data))
		try:
			self.buffer += data.decode()
		except:
			logger.exception('Could not decode data from client')

		idx = self.buffer.find('\r\n')

		while idx >= 0:  # While there are separators
			frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
			self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

			self.on_frame(frame)  # Process the frame
			idx = self.buffer.find('\r\n')

		if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
			logger.warning('Buffer too large')
			self.buffer = ''
			self.transport.close()


	def on_frame(self, frame: str) -> None:
		"""
		Called when a frame (JSON Object) is extracted

		:param frame: The JSON object to process
		:return:
		"""
		#logger.debug("Frame: {}".format(frame))

		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode JSON message: {}".format(frame))
			self.transport.close()
			return

		mtype = message.get('type', "").upper()

		if mtype == 'NEGOTIATE':
			ret = self.process_negotiate(message)
		elif mtype == 'EXCHANGE':
			ret = self.exchange_key(message)
		elif mtype == 'SECURE':
			ret = self.process_secure(message)
		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'See server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()
	
	def process_negotiate(self, message: dict) -> bool:
		logger.debug(f"Process Open: {message}")

		if self.state != STATE_CONNECT:
			logger.warning("Invalid state. Discarding")
			return False
		
		if not 'proposal' in message:
			logger.warning("No proposal string")
			return False
		
		proposal = message["proposal"]
		parts = proposal.split("_")
		self.key_exchange_algorithm = parts[0]
		self.cipher_algortithm = parts[1]

		if self.key_exchange_algorithm != "DH":
			logger.warning("invalid key exchange algorithm. Aborting")
			return False
		
		if not self.cipher_algortithm in symmetric_encryption.SUPPORTED_ALGORITHMS:
			logger.warning(f"{self.cipher_algortithm} not supported. Aborting")
			return False
		
		if issubclass(symmetric_encryption.SUPPORTED_ALGORITHMS[self.cipher_algortithm], symmetric_encryption.algorithms.BlockCipherAlgorithm):
			self.cipher_mode = parts[2]
			self.digest_algorithm = parts[3].lower()

			if not self.cipher_mode in symmetric_encryption.SUPPORTED_MODES:
				logger.warning(f"{self.cipher_mode} not supported. Aborting")
				return False

		else:
			self.digest_algorithm = parts[2].lower()
		
		if not self.digest_algorithm in assymetric_encryption.SUPPORTED_HASHES:
			logger.warning(f"{self.digest_algorithm} not supported. Aborting")
			return False
		
		self.state = STATE_NEGOTIATE
		self._send({ 'type' : 'OK' })
		return True
	
	def exchange_key(self, message: dict) -> bool:
		logger.info("Exchanging key with client")

		if self.state != STATE_NEGOTIATE:
			logger.warning("Invalid state. Aborting")
			return False

		if not "peer_key" in message:
			logger.warning("No peer key in message. Aborting")
			return False
		
		dh_private_key, dh_public_key = handshake_ec.generateKeyPair()
		dh_public_bytes = handshake_ec.getPeerPublicBytesFromKey(dh_public_key)
		dh_peer_public_bytes = base64.b64decode( message["peer_key"] )
		dh_peer_public_key = handshake_ec.buildPeerPublicKey(dh_peer_public_bytes)

		message = {
			'type' : 'EXCHANGE',
			'peer_key' : base64.b64encode(dh_public_bytes).decode()
		}

		self.shared_key = handshake_ec.deriveSharedKey(dh_private_key, dh_peer_public_key)
		self.state = STATE_READY
		self._send(message)
		return True
	
	def process_secure(self, message: dict) -> bool:

		unsecure_message = self.unsecure(message)
		mtype = unsecure_message["type"]

		if mtype == 'ROTATE':
			ret = self.process_rotate()
		elif mtype == 'OPEN':
			ret = self.process_open(unsecure_message)
		elif mtype == 'DATA':
			ret = self.process_data(unsecure_message)
		elif mtype == 'CLOSE':
			ret = self.process_close(unsecure_message)
		else:
			logger.warning("Invalid message type in payload. Aborting")
			ret = False
		
		return ret
	
	def process_rotate(self):
		message = {"type" : "OK"}
		secure_message = self.secure(message)
		self._send(secure_message)
		return True

	def process_open(self, message: dict) -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Open: {}".format(message))

		if self.state != STATE_READY:
			logger.warning("Invalid state. Discarding")
			return False

		if not 'file_name' in message:
			logger.warning("No filename in Open")
			return False

		# Only chars and letters in the filename
		file_name = re.sub(r'[^\w\.]', '', message['file_name'])
		file_path = os.path.join(self.storage_dir, file_name)
		if not os.path.exists("files"):
			try:
				os.mkdir("files")
			except:
				logger.exception("Unable to create storage directory")
				return False

		try:
			self.file = open(file_path, "wb")
			logger.info("File open")
		except Exception:
			logger.exception("Unable to open file")
			return False
		
		message = {'type': 'OK'}
		secure_message = self.secure(message)

		self.file_name = file_name
		self.file_path = file_path
		self.state = STATE_OPEN
		self._send(secure_message)
		return True


	def process_data(self, message: str) -> bool:
		"""
		Processes a DATA message from the client
		This message should contain a chunk of the file

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Data: {}".format(message))

		if self.state == STATE_OPEN:
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		try:
			self.file.write(bdata)
			self.file.flush()
		except:
			logger.exception("Could not write to file")
			return False
		
		message = {"type" : "OK"}
		secure_message = self.secure(message)
		self._send(secure_message)

		return True


	def process_close(self, message: str) -> bool:
		"""
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Close: {}".format(message))

		self.transport.close()
		if self.file is not None:
			self.file.close()
			self.shared_key = None
			self.rsa_server_private_key = None
			self.rsa_client_public_key = None
			self.file = None

		self.state = STATE_CLOSE

		return True

	def secure(self,message: dict) -> dict:
		secure_message = {
			'type' : 'SECURE',
			'payload' : json.dumps(message)
		}
		return secure_message
	
	def unsecure(self, secure_message: dict) -> dict:
		unsecure_message = json.loads( secure_message["payload"] )
		return unsecure_message

	def _send(self, message: str) -> None:
		"""
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
		logger.debug("Send: {}".format(message))

		message_b = (json.dumps(message) + '\r\n').encode()
		self.transport.write(message_b)

def main():
	global storage_dir

	parser = argparse.ArgumentParser(description='Receives files from clients.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages (default=False)',
						default=0)
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='TCP Port to use (default=5000)')

	parser.add_argument('-d', type=str, required=False, dest='storage_dir',
						default='files',
						help='Where to store files (default=./files)')

	args = parser.parse_args()
	storage_dir = os.path.abspath(args.storage_dir)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	if port <= 0 or port > 65535:
		logger.error("Invalid port")
		return

	if port < 1024 and not os.geteuid() == 0:
		logger.error("Ports below 1024 require eUID=0 (root)")
		return

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Port: {} LogLevel: {} Storage: {}".format(port, level, storage_dir))
	tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == '__main__':
	main()


