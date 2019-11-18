import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import symmetric_encryption
import assymetric_encryption
import handshake_ec
from hmac_generator import buildHMAC

logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_NEGOTIATE = 1
STATE_OPEN = 3
STATE_DATA = 4
STATE_ROTATE = 5
STATE_CLOSE = 6


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
        self.file_end = False
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks
        self.key_exchange_algorithm = "DH"
        self.cipher_algorithm = "AES"
        self.cipher_mode = "CBC"
        self.digest_algorithm = "SHA512"

    def connection_made(self, transport) -> None:	#Override from asyncio.BaseProtocol
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')
        

        message = {'type': 'NEGOTIATE', 'proposal': self._get_proposal()}

        self.state = STATE_NEGOTIATE
        self._send(message)


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

        #logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)

        if mtype == 'SECURE':
            message = self.unsecure(message)
            mtype = message.get('type', None)

        if mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_NEGOTIATE:
                logger.info("Negotiations sucessfull. Sending peer key.")
                self.exchange_key()
            elif self.state == STATE_ROTATE:
                logger.info("Rotating keys")
            elif self.state == STATE_OPEN:
                logger.info("Channel open")
                self.send_file_portion()
            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                logger.info("Sending data")
                self.send_file_portion()
            elif self.state == STATE_CLOSE:
                logger.info("Closing Server")
                self.send_close()
            else:
                logger.warning("Ignoring message from server")
            return
        elif mtype == 'EXCHANGE':
            if self.state == STATE_NEGOTIATE:
                logger.info("Received peer key from server.")
                self.derive_key(message)
                self.send_secure_open()
                return
            else:
                logger.warning("Invalid state for this type of message. Aborting")
        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message.get('data', None)))
        else:
            logger.warning("Invalid message type")

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
    
    def exchange_key(self):
        logger.info('Exchanging key with server')

        dh_private_key, dh_public_key = handshake_ec.generateKeyPair()
        dh_public_bytes = handshake_ec.getPeerPublicBytesFromKey(dh_public_key)

        message = {
            'type' : 'EXCHANGE',
            'peer_key' : base64.b64encode(dh_public_bytes).decode()
        }

        self.dh_private_key = dh_private_key
        self._send(message)
    
    def derive_key(self,message: dict):
        logger.info("Deriving key")

        if not "peer_key" in message:
            logger.warning("No peer key found. Aborting")
            self.transport.close()
            self.loop.stop()

        dh_peer_public_bytes = base64.b64decode( message["peer_key"].encode() )
        dh_peer_public_key = handshake_ec.buildPeerPublicKey(dh_peer_public_bytes)

        self.share_key = handshake_ec.deriveSharedKey(self.dh_private_key, dh_peer_public_key)
    
    def send_secure_open(self):

        message = {'type' : 'OPEN', 'file_name': self.file_name}

        secure_message = {
            'type' : 'SECURE',
            'payload' : json.dumps(message)
        }

        self.file = open(self.file_name, "rb")
        self.state = STATE_OPEN
        self._send(secure_message)

    def send_file_portion(self) -> None:
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
        message = {'type' : 'DATA', 'data': None}
        read_size = 16*60
        data = self.file.read(read_size)
        message['data'] = base64.b64encode(data).decode()
        secure_message = self.secure(message)
        
        if len(data) != read_size:
            self.state = STATE_CLOSE
        else:
            self.state = STATE_DATA
        self._send(secure_message)
    
    def send_close(self):
        message = {'type' : 'CLOSE'}
        secure_message = self.secure(message)
        self._send(secure_message)
    
    def _get_proposal(self) -> str:
        proposal = self.key_exchange_algorithm + "_" + self.cipher_algorithm
        proposal += "_" + self.cipher_mode if len(self.cipher_mode) != 0 else ""
        proposal += "_" + self.digest_algorithm
        return proposal
    
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