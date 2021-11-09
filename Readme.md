Image Encryption Using Triple DES

Frame Work: 
Flask 

Set Up Procedure: 
Create a new env 
Install Python 3.6
Install the libraries listed in the requierement.txt 

Run Project:
Python app.py

Functionality: 
- Can decrypt and encrypt Images using DES alogrithm 

Advantages
The image can only be viewed by the receiver as the image is encrypted using Triple DES and the key is only known to the sender and receiver.
Since the image is encrypted using Triple DES, it is more secure than DES.
Since the key is entered by the sender and receiver and is not stored in the database, it makes the encryption and decryption more secure.

Disadvantages
The file size to be transmitted becomes large since it contains encrypted data.
Since the file size is huge it can be suspected to contain some critical information.
