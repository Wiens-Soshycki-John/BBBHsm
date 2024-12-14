# BBBHsm
Amateur HSM to be deployed on a BeagleBone Black

Contributors:
John Wiens-Soshycki: johnworkws@gmail.com/johnws@my.yorku.ca
Alex Phan: stelx7@my.yorku.ca
Delano Vernon: dominatorw20@gmail.com
Augustino Dang: augdang@my.yorku.ca

File Structure
All html must stay in subfolder templates.

The true functionality of this project lies in kmipHSM.py and cryptoFuncs.py
The former runs the server and control endpoints where the latter has
the implementation of our cryptographic functions.

Our pem files and server.conf are proof of our attempt to implement the KMIP protocol
for our HSM.


Running the code
Import into your favourite Digital Workspace, run kmipHsm.py and connect to the website via
127.0.01:5000 locally (ensure file structure is the same as how it appears in main).

To run on the BeagleBoneBlack, scp the files over, log in with ssh and run python3 kmipHsm.py
change to listen on all ports (127.0.0.1 -> 0.0.0.0; port=5000)
ip for browser should be 192.168.7.2:5000 (assuming you are connected locally to the board via
usb, ethernet cannot be connected to connect this way). Additionaly the 7.2 changes to 7.1 for mac
os.

Otherwise the ip become 192.168.xx.xxxx where the x are a concatenation of the ip of the ethernet
network the board is connected too.

No rights reserverd.

