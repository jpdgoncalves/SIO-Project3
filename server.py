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
import secure
from hmac_generator import buildHMAC

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_NEGOTIATE = 1
STATE_EXCHANGE = 2
STATE_READY = 3
STATE_OPEN = 4
STATE_DATA = 5
STATE_ROTATE = 6
STATE_CLOSE= 7

#GLOBAL
storage_dir = 'files'

class ClientHandler(asyncio.Protocol):

    def __init__(self, signal):
        """
        Default constructor
        """
        self.signal = signal
        self.state = STATE_CONNECT
        self.file = None
        self.file_name = None
        self.file_path = None
        self.storage_dir = storage_dir
        self.buffer = ''
        self.peername = ''

        self.own_apriv_key = None
        self.client_apub_key = None
        self.exchange_share_key = None
        self.key_exchange_algorithm = ""
        self.cipher_algorithm = ""
        self.cipher_mode = ""
        self.digest_algorithm = ""
        self.oak_filename = "server_private_key.pem"
        self.cak_filename = "client_public_key.pem"
        
        self.read_size = 1024
        self.read_bytes_to_rotate = self.read_size * 1024 * 2
        self.total_read_bytes = 0

    def connection_made(self, transport) -> None:	#Override from asyncio.BaseProtocol
        """
        Called when a client connects

        :param transport: The transport stream to use with this client
        :return:
        """
        self.peername = transport.get_extra_info('peername')
        logger.info('\n\nConnection from {}'.format(self.peername))
        self.transport = transport
        self.state = STATE_CONNECT

        with open(self.oak_filename,"rb") as oak_file, open(self.cak_filename,"rb") as cak_file:
            self.own_apriv_key = assymetric_encryption.getPrivateKeyFromBytes(oak_file.read())
            self.client_apub_key = assymetric_encryption.getPublicKeyFromBytes(cak_file.read())
    
    def connection_lost(self,exc):
        print("Connection was lost")
        print(exc)

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
        logger.debug("Frame: {}".format(frame))

        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode JSON message: {}".format(frame))
            self.transport.close()
            return

        mtype = message.get('type', "").upper()
        error = True

        if mtype == "NEGOTIATE":
            error = self.process_negotiate(message)
        elif mtype == "EXCHANGE":
            error = self.process_exchange(message)
        elif mtype == "SECURE":
            error = self.process_secure(message)
        else:
            logger.warn("Invalid message type. Closing connection.")

        if error:
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
        logger.debug(f"Process Negotiate: {message}")

        if self.state != STATE_CONNECT:
            logger.warn("Invalid state for negotiations. Closing connection")
            return True
        
        if not "proposal" in message:
            logger.warn("No proposal string. Closing connection.")
            
        self._get_parameters(message["proposal"])
        error = self._verify_parameters()

        if not error:

            message = {
                "type" : "OK"
                }
            
            self.state = STATE_EXCHANGE
            self._send(message)

        return error
    
    def process_exchange(self, message: dict) -> bool:
        logger.info("Exchanging key with client")

        if self.state != STATE_EXCHANGE:
            logger.warn("Invalid state for exchange message. Closing connection")
            return True
        
        exchange_priv_key, exchange_public_key = handshake_ec.generateKeyPair()
        exchange_public_bytes = handshake_ec.getPeerPublicBytesFromKey(exchange_public_key)
        
        exchange_peer_bytes = base64.b64decode(message["peer_key"].encode())
        exchange_peer_key = handshake_ec.buildPeerPublicKey(exchange_peer_bytes)
        exchange_shared_key = handshake_ec.deriveSharedKey(exchange_priv_key, exchange_peer_key)

        self.exchange_share_key = exchange_shared_key
        self.state = STATE_READY
        self.send_exchange(exchange_public_bytes)
        return False
    
    def process_secure(self, message: dict) -> bool:
        logger.info(f"Process Secure.")

        message = secure.unsecure(message, self.exchange_share_key, self.own_apriv_key,
                                  self.cipher_algorithm, self.cipher_mode, self.digest_algorithm)

        error = True
        mtype = message.get("type", None)

        if mtype == "OPEN":
            error = self.process_open(message)
        elif mtype == "DATA":
            error = self.process_data(message)
        elif mtype == "ROTATE":
            error = self.process_rotate(message)
        elif mtype == "CLOSE":
            error = self.process_close(message)
        else:
            logger.warn("Invalid message type(non secure context). Closing connection")

        return error

    def process_open(self,message: dict) -> bool:
        """
        Processes an OPEN message from the client
        This message should contain the filename

        :param message: The message to process
        :return: Boolean indicating the success of the operation
        """
        logger.debug("Process Open: {}".format(message))

        if self.state != STATE_READY:
            logger.warning("Invalid state. Discarding")
            return True

        if not 'file_name' in message:
            logger.warning("No filename in Open")
            return True

        # Only chars and letters in the filename
        file_name = re.sub(r'[^\w\.]', '', message['file_name'])
        file_path = os.path.join(self.storage_dir, file_name)
        if not os.path.exists("files"):
            try:
                os.mkdir("files")
            except:
                logger.exception("Unable to create storage directory")
                return True

        try:
            self.file = open(file_path, "wb")
            logger.info("File open")
        except Exception:
            logger.exception("Unable to open file")
            return True
        

        self.file_name = file_name
        self.file_path = file_path
        self.state = STATE_OPEN
        self.send_ok()
        return False


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
            return True

        try:
            data = message.get('data', None)
            if data is None:
                logger.debug("Invalid message. No data found")
                return True

            bdata = base64.b64decode(message['data'].encode())
            read_bytes = len(bdata)
        except:
            logger.exception("Could not decode base64 content from message.data")
            return True

        try:
            self.file.write(bdata)
            self.file.flush()
        except:
            logger.exception("Could not write to file")
            return True
        
        self.total_read_bytes += read_bytes

        if self.total_read_bytes >= self.read_bytes_to_rotate:
            self.state = STATE_ROTATE
            self.total_read_bytes = 0
        
        self.send_ok()
        return False
    

    def process_rotate(self, message: dict) -> bool:
        logger.info("Process Rotate.")

        if self.state != STATE_ROTATE:
            logger.warn("Invalid state for rotate. Closing connection")
            return True
        
        if not "peer_key" in message:
            logger.warn("No peer key found in message")
            return True
        
        exchange_priv_key, exchange_public_key = handshake_ec.generateKeyPair()
        exchange_public_bytes = handshake_ec.getPeerPublicBytesFromKey(exchange_public_key)
        
        exchange_peer_bytes = base64.b64decode(message["peer_key"].encode())
        exchange_peer_key = handshake_ec.buildPeerPublicKey(exchange_peer_bytes)
        exchange_shared_key = handshake_ec.deriveSharedKey(exchange_priv_key, exchange_peer_key)

        self.send_rotate(exchange_public_bytes, exchange_shared_key)
        return False


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
            self.file = None

        self.state = STATE_CLOSE
        return False
    

    def send_exchange(self, exchange_public_bytes: bytes):

        message = {
            "type" : "EXCHANGE",
            "peer_key" : base64.b64encode(exchange_public_bytes).decode()
        }
        self._send(message)
    
    def send_ok(self):
        
        message = {
            "type" : "OK"
        }

        message = secure.secure(message, self.exchange_share_key, self.client_apub_key,
                                self.cipher_algorithm, self.cipher_mode, self.digest_algorithm)

        self._send(message)
    
    def send_rotate(self, exchange_public_bytes: bytes ,exchange_shared_key: bytes):
        
        message = {
            "type" : "ROTATE",
            "peer_key" : base64.b64encode(exchange_public_bytes).decode()
        }

        message = secure.secure(message, self.exchange_share_key, self.client_apub_key,
                                self.cipher_algorithm, self.cipher_mode, self.digest_algorithm)

        self.exchange_share_key = exchange_shared_key
        self.state = STATE_DATA
        self._send(message)
    
    def _get_parameters(self, proposal: str):
        
        parts = proposal.split("_")

        self.key_exchange_algorithm = parts[0]
        self.cipher_algorithm = parts[1]

        if len(parts) == 4:
            self.cipher_mode = parts[2]
            self.digest_algorithm = parts[3]
        else:
            self.digest_algorithm = parts[2]
    
        
    def _verify_parameters(self) -> bool:
        
        if not self.cipher_algorithm in symmetric_encryption.SUPPORTED_ALGORITHMS:
            logger.warn("This algorithm is not supported. Closing connection.")
            return True
        
        if issubclass(symmetric_encryption.SUPPORTED_ALGORITHMS[self.cipher_algorithm], symmetric_encryption.algorithms.BlockCipherAlgorithm):
            if not self.cipher_mode in symmetric_encryption.SUPPORTED_MODES:
                logger.warn("This mode is not supported. Closing connection.")
                return True
        
        if not self.digest_algorithm in assymetric_encryption.SUPPORTED_HASHES:
            logger.warn("This hash is not supported. Closing connection.")
            return True

        return False


    def _send(self, message: dict) -> None:
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


