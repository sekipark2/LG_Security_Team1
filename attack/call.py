import socket
import time
import rsa
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

        # Load the public key
        public_key = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
        
        # Encrypt the message
        encrypted_message = rsa.encrypt(message.encode(), public_key)
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
port = 10002  # Replace with the port you want to connect to
peer = '{ \
  "hash_id": "WOYXCNFRXYCVFO66", \
  "session": "IGCHY7UIPRTUDPXS", \
  "peer_hash_id": "6NSPYQESY2RT3AFJ", \
}'
peer_hash_id = 'WOYXCNFRXYCVFO66'   # alice hash_id

# bob public key
rsa_key = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFrUENhUFBxcFlWZFYyTXJkVmRqRgo1NWsxVVordVZxZFRhMi9kUENpRHFPOG5scmRYcko3eGRVTXNHYVlmOHU4RDdFcThOS3NjV1U4M3hKQUM4NW8yCklIR2ZtVjVhNmdNMGpQSVhnTVRtOUNhUllhb3hsb29TT0I1K3o1alZWeUVIczNjNFZHL0N0QXYxYUhJVTkxRm0KeHdyWGs2UElCQ3Z4emJ1TDJ5VzRQN2w4ZGhEMG54QUphUERLbFJ4OWs1Z1NITkIxSjM5b1RCTTFMaWJWNkY4eQp3NEhuSGFhQTlRaFN0TnFyUXpFUXhRQTh4N0thbkJ3NHY2R253alUwTVJKS1F3QmVjNTZ5WWY2M3h1N2FCYUc5Ci9waVJYcHBkajZPakNBdmduUkYwMStWYVQ1TXYwR1ppQVFiaTc2TEd3T1BTOFo4QWNsRklmYnlhMjRlenE3eVAKNFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='



my_socket = MySocket()
my_socket.connect(host, port)
encrypt_msg = my_socket.encrypt_message(rsa_key, peer_hash_id)
print(encrypt_msg)
my_socket.send(encrypt_msg)

while True:
    time.sleep(1)
    
my_socket.close()

