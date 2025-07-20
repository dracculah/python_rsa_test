Testing a simple message exchange via asymmetric keys (RSA) with a the help of python hazmat library.

Bob creates the TCP server and listens (has nothing to say (currently)).
Alice is a TCP client, connects to Bob and has a secret message

Both Alice and Bob exchange their pubic keys (in plaintext), then the Alice tells how long the message is (in blocks of 128 bytes), Bob agrees and receives the chucks and reconstructs the message. 
The confirmation messages (similar like ACK) are sent in plaintext.

This is still a very drafty version, no harm is meant intentionally, but still use at your OWN RISK.
