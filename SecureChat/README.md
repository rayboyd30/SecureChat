# Secure Chat

This project implements a secure chat client with a custom JCE Provider and AES implementation. Note: this provider doesn't include a signed certificate form Oracle thus Linux is the only supported platform.

Usage instructions:
1. Clone the repository
2. run: javac *.java
3. run: java Chat -s PORT_NUMBER to instantiate server
4. run java Chat -c ADDRESS PORT_NUMBER to instantiate client
