import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import symmetric_encryption
import assymetric_encryption
import handshake_ec
import secure
from hmac_generator import buildHMAC

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_NEGOTIATE = 1
STATE_EXCHANGE = 2
STATE_OPEN = 3
STATE_DATA = 4
STATE_ROTATE = 5
STATE_CLOSE = 6

CIPHER_ALGORITHM = "AES"
CIPHER_MODE = "CBC"
DIGEST_ALGORITHM = "sha512"

class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        self.file_name = file_name
        self.file = None
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks

        self.key_exchange_algorithm = "DH"
        self.cipher_algorithm = CIPHER_ALGORITHM
        self.cipher_mode = CIPHER_MODE
        self.digest_algorithm = DIGEST_ALGORITHM

        self.complete = False
        self.exchange_priv_key = None
        self.exchange_shared_key = None
        self.own_apriv_key = None
        self.server_apublic_key = None 
        self.oak_filename = "client_private_key.pem"
        self.sak_filename = "server_public_key.pem"

        self.read_size = 16 * 60
        self.read_bytes_to_rotate = self.read_size * 1092
        self.total_read_bytes = 0

    def connection_made(self, transport) -> None:	#Override from asyncio.BaseProtocol
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """

        with open(self.oak_filename,"rb") as oak_file, open(self.sak_filename,"rb") as sak_file:
            self.own_apriv_key = assymetric_encryption.getPrivateKeyFromBytes(oak_file.read())
            self.server_apublic_key = assymetric_encryption.getPublicKeyFromBytes(oak_file.read()) 

        self.transport = transport
        self.state = STATE_CONNECT
        logger.debug('Connected to Server')
        self.send_negotiation_string()


    def data_received(self, data: str) -> None:		#Override from asyncio.Protocol
        """
        Called when data is received from the server.
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
            logger.warning('Buffer to large')
            self.buffer = ''
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)
        error = True

        if mtype == "OK":
            error = self.process_ok(message)
        elif mtype == "EXCHANGE":
            error = self.process_exchange(message)
        elif mtype == "SECURE":
            error = self.process_secure(message)
        elif mtype == "ERROR":
            error = True
            logger.warn(f"Got an error from the server: {message}")
        else:
            logger.warn("Invalid message type.")
            error = True

        if error:
            logger.warn("Something went wrong. Closing connection")
            self.transport.close()
            self.loop.stop()
        
        if self.complete:
            logger.info("File sent with sucess. Closing connection")
            self.transport.close()
            self.loop.stop()

    def connection_lost(self, exc):		#Override from asyncio.BaseProtocol
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')
        self.loop.stop()
    
    def process_ok(self, message: dict) -> bool:
        logger.info("Processing ok message (unsecure context).")

        if self.state != STATE_NEGOTIATE:
            logger.warn("Invalid state for this message")
            return True
        
        self.send_exchange()

        return False

    def process_exchange(self, message: dict) -> bool:
        logger.info("Processing exchange message.")

        if self.state != STATE_EXCHANGE:
            logger.warn("Invalid state for this message.")
            return True
        
        exchange_peer_bytes = base64.b64decode(message["peer_key"].encode())
        exchange_peer_key = handshake_ec.buildPeerPublicKey(exchange_peer_bytes)
        exchange_shared_key = handshake_ec.deriveSharedKey(self.exchange_priv_key, exchange_peer_key)

        self.exchange_shared_key = exchange_shared_key
        self.send_file_open()
        return False
    
    def process_secure(self, message: dict) -> bool:
        logger.info("Processing secure message.")

        message = secure.unsecure(message, self.shared_key, self.own_apriv_key,
                                  self.cipher_algorithm, self.cipher_mode, self.digest_algorithm)

        error = False
        mtype = message.get("type", None)

        if mtype == "OK":
            if self.state == STATE_OPEN:
                error = self.send_file_data()
            elif self.state == STATE_DATA:
                error = self.send_file_data()
            elif self.state == STATE_ROTATE:
                error = self.send_rotate()
            elif self.state == STATE_CLOSE:
                error = self.send_close()
        elif mtype == "ROTATE":
            error = self.process_rotate(message)
        elif mtype == "ERROR":
            logger.warn("Something went wrong(secure context)")
            error = True

        return error
    
    def process_rotate(message: dict) -> bool:
        logger.info("Processing rotate")

        if self.state != STATE_ROTATE:
            logger.warn("Invalid state for rotating keys. Closing connection.")
            return True
        
        exchange_peer_bytes = base64.b64decode(message["peer_key"].encode())
        exchange_peer_key = handshake_ec.buildPeerPublicKey(exchange_peer_bytes)
        exchange_shared_key = handshake_ec.deriveSharedKey(self.exchange_priv_key, exchange_peer_key)

        self.exchange_shared_key = exchange_shared_key
        self.state = STATE_DATA

        return self.send_file_data()
    
    def send_negotiation_string(self):
        logger.info("Sending negotiation string.")

        message = {
            "type" : "NEGOTIATE",
            "proposal" : self._get_proposal()
        }

        self.state = STATE_NEGOTIATE
        self._send(message)
    
    def send_exchange(self):
        logger.info("Sending an Exchange message.")

        message = {
            "type" : "EXCHANGE",
            "peer_key" : None
        }

        exchange_priv_key, exchange_public_key = handshake_ec.generateKeyPair()
        exchange_public_bytes = handshake_ec.getPeerPublicBytesFromKey(exchange_public_key)
        message["peer_key"] = base64.b64encode(exchange_public_bytes).decode()

        self.exchange_priv_key = exchange_priv_key
        self.state = STATE_EXCHANGE
        self._send(message)
    
    def send_file_open(self):
        logger.info("Sending an Open message.")

        message = {
            "type" : "OPEN",
            "file_name" : self.file_name
        }

        message = secure.secure(message, self.exchange_shared_key, self.server_apublic_key,
                                self.cipher_algorithm, self.cipher_mode, self.digest_algorithm)

        self.file = open(self.file_name, "rb")
        self.state = STATE_OPEN
        self._send(message)

    def send_file_data(self) -> bool:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """

        """ with open(self.file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            read_size = 16 * 60
            while True:
                data = f.read(16 * 60)
                message['data'] = base64.b64encode(data).decode()
                self._send(message)

                if len(data) != read_size:
                    break

            self._send({'type': 'CLOSE'})
            logger.info("File transferred. Closing transport")
            self.transport.close() """
        if self.state == STATE_OPEN:
            self.state = STATE_DATA
        
        if self.state != STATE_DATA:
            logger.warn("Invalid state for data messages. Closing connection.")
            return True
        
        message = {
            "type" : "DATA",
            "data" : None
        }
        
        data = self.file.read(self.read_size)
        read_size = len(data)
        message["data"] = base64.b64encode(data).decode()
        
        self.total_read_bytes += read_size

        if self.total_read_bytes >= self.read_bytes_to_rotate:
            self.state = STATE_ROTATE
            self.total_read_bytes = 0
        elif read_size < self.read_size:
            self.state = STATE_CLOSE
        
        message = secure.secure(message, self.exchange_shared_key, self.server_apublic_key,
                                self.cipher_algorithm, self.cipher_mode, self.digest_algorithm)
        self._send(message)
        return False

    def send_rotate(self) -> bool:
        logger.info("Sending a rotate message")

        if self.state != STATE_ROTATE:
            logger.warn("Invalid state to send rotate message. Closing connection")
            return True
        
        message = {
            "type" : "ROTATE",
            "peer_key" : None
        }

        exchange_priv_key, exchange_public_key = handshake_ec.generateKeyPair()
        exchange_public_bytes = handshake_ec.getPeerPublicBytesFromKey(exchange_public_key)
        message["peer_key"] = base64.b64encode(exchange_public_bytes).decode()

        message = secure.secure(message, self.exchange_shared_key, self.server_apublic_key,
                                self.cipher_algorithm, self.cipher_mode, self.digest_algorithm)

        self.exchange_priv_key = exchange_priv_key
        self._send(message)
        return False
    
    def send_close(self):
        logger.info("Sending close.")

        if self.state != STATE_CLOSE:
            logger.warn("Invalid state for close message. ")
            return True
        
        message = {
            "type" : "CLOSE"
        }

        message = secure.secure(message, self.exchange_shared_key, self.server_apublic_key,
                                self.cipher_algorithm, self.cipher_mode, self.digest_algorithm)

        self.file.close()
        self.complete = True
        self._send(message)
        return False
    
    def _get_proposal(self) -> str:
        proposal = self.key_exchange_algorithm + "_" + self.cipher_algorithm
        proposal += "_" + self.cipher_mode if len(self.cipher_mode) != 0 else ""
        proposal += "_" + self.digest_algorithm
        return proposal

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
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, nargs=1,
                        dest='port', default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose == 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()