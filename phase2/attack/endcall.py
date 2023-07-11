import socket
import time
import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64


MSGLEN = 4096

class MySocket:

    def __init__(self, sock=None):
        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

    def connect(self, host, port):
        self.sock.connect((host, port))

    def close(self):
        self.sock.close()
        
    def send(self, msg):
        totalsent = 0
#        msg = msg.encode('utf-8')  # convert string to bytes
        MSGLEN = len(msg)
        
        while totalsent < MSGLEN:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent

    def receive(self):
        chunks = []
        bytes_recd = 0
        while bytes_recd < MSGLEN:
            chunk = self.sock.recv(min(MSGLEN - bytes_recd, 2048))
            if chunk == b'':
                raise RuntimeError("socket connection broken")
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
        return b''.join(chunks)


    def encrypt_message(self, base64_rsa_key, message):
        # Decode the base64 public key
        rsa_key = base64.b64decode(base64_rsa_key).decode()
        print(rsa_key)
        # Load the public key
        public_key = serialization.load_pem_public_key(
            rsa_key.encode(),
            backend=default_backend()
        )

        # Encrypt the message with RSA and PKCS1 OAEP padding
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message

        
    def decrypt_message(self, base64_private_key, encrypted_message):
        # Decode the base64 private key
        private_key_str = base64.b64decode(base64_private_key).decode()

        # Load the private key
        private_key = rsa.PrivateKey.load_pkcs1(private_key_str.encode())
        
        # Decrypt the message
        decrypted_message = rsa.decrypt(encrypted_message, private_key)
        return decrypted_message.decode()  # Convert bytes to string
    


host = '192.168.0.216'  # Replace with the host IP you want to connect to
port = 10000  # Replace with the port you want to connect to
"""
peer = '{ \
  "hash_id": "6NSPYQESY2RT3AFJ", \
  "session": "UO44FNFDWLGTITE3", \
  "peer_hash_id": "6NSPYQESY2RT3AFJ", \
}'
"""
peer_hash_id = 'WOYXCNFRXYCVFO66'   # alice hash_id

# bob public key
rsa_key = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF4SWVDZGU0aW1iWlg4RzFHTzB4NgpiNHZHdDY2ZmVZbUZDNWZVWVBLM2VxMTJhVHkwNXh2K2NYTUlsTWkyUG9XclRobUYveStpcHJBMk5vNU5HblhNCllCNW1iaGJoTVlmRzVDK3BoUHpBOGVpNUZ0SHFVZDFPNU5JMWZQNzFPTVpFZGNQajBJUyttWWtWN2pVNG5lR3gKc3Vpa0N4dmFCaXNVcjEwa0dlc245MjE0VUtXQ003MEJ6QWZ2ZTJmcEpnN21vOUNtQUhHYWF6YkdZcUJaWlgrdwpXMHBBYm8rbWlpRmZPMmw3RUlIeGZMcnQwSzQ0QXpKNnNhSUJJZzVjc2tBUkpQRUR1SGg5T1B4YXFvMVBkRmRJCnZoWDZsdmxWbUtQd0NDTXBkemRvMUVxaytLYUpsN1p5QjJQMjZnRms2MmlzZVJEcktmbHVIM1pObTNYTjNpUHcKSlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='



my_socket = MySocket()
print("before connect")
my_socket.connect(host, port)
print("after connect")


encrypt_msg = my_socket.encrypt_message(rsa_key, peer_hash_id)
my_socket.send(encrypt_msg)
my_socket.close()


