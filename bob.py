from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64
import re
import socket
import math
import time

# IMPORTANT: set the variables to appropriate values
# P.S. Bob is the server - start it first
# P.S. Bob only receives now, it can send in later versions
fn_priv_key = "bob.pem" # filename of the private key (make sure it's generated)
# how to generate:
# ssh-keygen -t rsa -b 2048 -m PEM -f bob.pem
server_ip = "0.0.0.0" # listening from anywhere
server_port = 1234 # listening port

# P.S. there is a key gen function from the library, but I don't quite trust it yet

def load_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    return private_key

def get_private_key(filename):
	try:
		key = load_key(filename)
		return key
	except:
		raise Exception("please generate key! by running `ssh-keygen -t rsa -b 2048 -m PEM -f {}`".format(filename))
		assert(0==1)
		key = gen_key()
		save_key(key, filename)
		return key

def encrypt_data(partner_pub_key, message_):
    message_encoded = message_.encode()
    enc_message = partner_pub_key.encrypt(
        message_encoded,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    enc_message_b64 = base64.b64encode(enc_message)
    return enc_message_b64

def decrypt_data(fn_priv_key, enc_message_b64):
    priv_key = get_private_key(fn_priv_key)

    try:
        enc_message = base64.b64decode(enc_message_b64)
        message_ = priv_key.decrypt(
            enc_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        #print("message_ -> {}".format(message_))
        return (True, message_.decode())
    except Exception as e:
        print("decryption failed:", str(e))
        return (False, "")

def get_my_pub_key(fn_priv_key):
    print("get_my_pub_key: started")
    priv_key = get_private_key(fn_priv_key)
    print("get_my_pub_key: private key loaded")

    # Derive the public key from the private key
    pub_key = priv_key.public_key()
    print("get_my_pub_key: public key derived")

    str_pub_key = pub_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print("get_my_pub_key: serialized public key")
    print("str_pub_key -> {}".format(str_pub_key))

    # just for checks
    new_key = serialization.load_pem_public_key(str_pub_key)
    assert(isinstance(new_key, rsa.RSAPublicKey))

    return str_pub_key

def send_large_data(partner_pub_key, large_data_, cs):
    print("running send large data")
    rest_data = int(math.ceil(len(large_data_)*1.0 / 128)*128)
    print("data len -> {}".format(rest_data))
    cs.send("data {}".format(rest_data).encode())
    resp = cs.recv(512).decode()
    if resp != "ok":
        print("recipient not accepting")
        return
    offset = 0
    #cnt = int(math.ceil(rest_data * 1.0 / 128))
    cnt = rest_data / 128
    print("will send {} chunks".format(cnt))
    i = 0
    while rest_data > 0:
        print("doing while")
        chunk = large_data_[offset:offset+128]
        print("got a chunk")
        data_ = encrypt_data(partner_pub_key, chunk)
        offset += 128
        rest_data -= 128
        i += 1
        print("{} / {}".format(i, cnt))
        cs.send(data_)
        resp = cs.recv(256)
        if resp != "recv {}".format(i):
            print("something is wrong, resp -> {}".format(resp))
            return


def get_large_data(cs):
    print("running get large data")
    large_data = ""
    length_str = cs.recv(512).decode()
    print("got length str -> {}".format(length_str))
    reg_len = re.compile(r"data (\d+)")
    oops = reg_len.match(length_str)
    if oops == False:
        print("oops")
    assert(oops)
    m = reg_len.match(length_str)
    data_len = int(m[1])
    counts = int(math.ceil(data_len * 1.0 / 128))
    print("will await {} chunks".format(counts))
    time.sleep(2)
    cs.send("ok".encode())
    i = 0
    while i*128 < data_len:
        try:
            enc_data_ = cs.recv(512).decode()
            #print("rx {} bytes -> {}".format(len(enc_data_),enc_data_))
            if (len(enc_data_) == 0):
                continue
            (ok, data_) = decrypt_data(fn_priv_key, enc_data_)
            if ok == False:
                print("error decoding -> {}".format(enc_data_))
            large_data += data_
            i += 1
            cs.send("recv {}".format(i).encode())
            if i % 100 == 0:
                print("received {} / {}".format(i,counts))
        except Exception as e:
            print("exception -> {}".format(e.what()))
            break
    print("received large data ({}) -> {}".format(data_len, large_data))

partner_pub_key = ""
    
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# bind the socket to a specific address and port
server.bind((server_ip, server_port))
# listen for incoming connections
server.listen(0)
print(f"Listening on {server_ip}:{server_port}")

# accept incoming connections
while True:
    partner_pub_key = ""

    client_socket, client_address = server.accept()
    print(f"Accepted connection from {client_address[0]}:{client_address[1]}")
    my_pub_kkey = get_my_pub_key(fn_priv_key)
    print("will send my pub key")
    print("my pub key is -> {}".format(my_pub_kkey))
    client_socket.send(my_pub_kkey)
    try:
        ppk_b64 = client_socket.recv(512)
        print("raw socket, recv -> {}".format(ppk_b64))
        partner_pub_key_ser = ppk_b64 # base64.b64decode(ppk_b64)
        print("partner_pub_key_ser -> {}",format(partner_pub_key_ser))
        partner_pub_key = serialization.load_pem_public_key(partner_pub_key_ser)
    except Exception as e:
        print("failed getting ppk -> {}".format(e.what()))

    assert(partner_pub_key != "")
    print("have partner pub key -> {}".format(ppk_b64))

    while True:
        try:
            get_large_data(client_socket)
            request = client_socket.recv(512)
        except Exception as e:
            print("exception -> {}".format(e.what()))
            break
