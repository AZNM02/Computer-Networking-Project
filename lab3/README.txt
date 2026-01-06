Group Members
- Megan Yam (meganyam)
- Samuel Shi Jie Then (stsj)
- Aung Zar Ni Min (aznm)

Language: Python 3

How to run
1. cd lab3
2. ./run <port> (May need to run "chmod +x ./run" beforehand)
   Example: ./run 1234

The proxy will listen on the given port for HTTP/HTTPS proxy connections.
To test with Firefox, configure it to use "localhost:<port>" as HTTP and HTTPS proxy.

Files
- proxy.py  : HTTP/1.0 proxy with CONNECT tunnelling
- run       : helper script to start the proxy
