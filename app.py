from flask import Flask, request, flash,jsonify, render_template,redirect, url_for, request
import pickle
from werkzeug.utils import secure_filename
import os

basedir = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = 'templates/upload/encrypt/'
UPLOAD_FOLDER2 = 'templates/upload/decrypt/'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app = Flask(__name__,template_folder='templates')
app = Flask(__name__,static_folder="templates/images")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['UPLOAD_FOLDER2'] = UPLOAD_FOLDER2

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Route for handling the login page logic
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/next')
def next():
    return render_template('next.html')

##Encryption
pi=100005
salt_const=b"$ez*}-d3](%d%$#*!)$#%s45le$*fhucdivyanshu75456dgfdrrrrfgfs^"


from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from getpass import getpass
from Crypto.Protocol.KDF import PBKDF2




#encrypting function
def encryptor(path,password):
	#opening the image file
	try:
		with open(path, 'rb') as imagefile:
			image=imagefile.read()
			
		#padding	
		while len(image)%8!=0:
			image+=b" "
	except:
		print("Error loading the file, make sure file is in same directory, spelled correctly and non-corrupted")
		exit()
	
	#hashing original image in SHA256	
	hash_of_original=SHA256.new(data=image)
	
	
	
	#Inputting Keys
	key_enc=password
	
	
	#Salting and hashing password
	key_enc=PBKDF2(key_enc,salt_const,48,count=pi)

	
	try:
		
		cipher1=DES.new(key_enc[0:8],DES.MODE_CBC,key_enc[24:32])
		ciphertext1=cipher1.encrypt(image)
		cipher2=DES.new(key_enc[8:16],DES.MODE_CBC,key_enc[32:40])
		ciphertext2=cipher2.decrypt(ciphertext1)
		cipher3=DES.new(key_enc[16:24],DES.MODE_CBC,key_enc[40:48])
		ciphertext3=cipher3.encrypt(ciphertext2)
	except:
		print("			Encryption failed...Possible causes:Library not installed properly/low device memory/Incorrect padding or conversions")
		exit()
	
	#Adding hash at end of encrypted bytes
	ciphertext3+=hash_of_original.digest()

	
	#Saving the file encrypted
	try:
		dpath=path
		with open(dpath, 'wb') as image_file:
    			image_file.write(ciphertext3)
        
		print("			Encrypted Image Saved successfully as filename "+dpath)
        
    		
		
	except:
		temp_path=input("Saving file failed!. Enter alternate name without format to save the encrypted file. If it is still failing then check system memory ==="+dpath)
		try:
			dpath=temp_path+path
			dpath="encrypted_"+path
			with open(dpath, 'wb') as image_file:
    				image_file.write(ciphertext3)
			print("			Encrypted Image Saved successfully as filename "+dpath)
			exit()
		except:
			print("			Failed....Exiting...")
			exit()


from flask import send_file,send_from_directory

@app.route('/downloadFile/<path:filename>/<int:type>', methods=['GET', 'POST'])
def downloadFile (filename,type):
    #For windows you need to use drive name [ex: F:/Example.pdf]
    path = ""
    if type==1:
        path = os.path.join(basedir, app.config['UPLOAD_FOLDER'],filename)
    if type==2:
        path = os.path.join(basedir, app.config['UPLOAD_FOLDER2'],filename)
    return send_file(path, as_attachment=True)

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = "encrypted."+ file.filename.rsplit('.', 1)[1].lower()
            file.save(os.path.join(basedir, app.config['UPLOAD_FOLDER'], filename))
            password = request.values.get("password")
            encryptor(os.path.join(basedir, app.config['UPLOAD_FOLDER'], filename),password)
            return redirect(url_for('downloadFile',filename=filename,type=1))
             
    return render_template('encrypt.html')

#decrypting function
def decryptor(encrypted_image_path,password):
	
	try:
		with open(encrypted_image_path,'rb') as encrypted_file:
			encrypted_data_with_hash=encrypted_file.read()
			
	except:
		print("			Unable to read source cipher data. Make sure the file is in same directory...Exiting...")
		exit()
	
	
	#Inputting the key
	key_dec=password
	
	
	#extracting hash and cipher data without hash
	extracted_hash=encrypted_data_with_hash[-32:]
	encrypted_data=encrypted_data_with_hash[:-32]

	
	#salting and hashing password
	key_dec=PBKDF2(key_dec,salt_const,48,count=pi)
	

	#decrypting using triple 3 key DES
	print("			Decrypting...")
	try:
		
		cipher1=DES.new(key_dec[16:24],DES.MODE_CBC,key_dec[40:48])
		plaintext1=cipher1.decrypt(encrypted_data)
		cipher2=DES.new(key_dec[8:16],DES.MODE_CBC,key_dec[32:40])
		plaintext2=cipher2.encrypt(plaintext1)
		cipher3=DES.new(key_dec[0:8],DES.MODE_CBC,key_dec[24:32])
		plaintext3=cipher3.decrypt(plaintext2)
		
		
	except:
		print("			Decryption failed...Possible causes:Library not installed properly/low device memory/Incorrect padding or conversions")
		
	
	
	
	
	#hashing decrypted plain text
	hash_of_decrypted=SHA256.new(data=plaintext3)

	
	#matching hashes
	if hash_of_decrypted.digest()==extracted_hash:
		print("Password Correct !!!")
		print("			DECRYPTION SUCCESSFUL!!!")
        
	else:
		print("Incorrect Password!!!")
		return False
		
		
		
	#saving the decrypted file	
	try:
		epath=encrypted_image_path

		epath=epath
		with open(epath, 'wb') as image_file:
			image_file.write(plaintext3)
		print("			Image saved successully with name " + epath)
		print("			Note: If the decrypted image is appearing to be corrupted then password may be wrong or it may be file format error")
	except:
		try:
			epath=encrypted_image_path
			with open(epath, 'wb') as image_file:
				image_file.write(plaintext3)
			print("			Image saved successully with name " + epath)
			print("			Note: If the decrypted image is appearing to be corrupted then password may be wrong or it may be file format error")
		except:
			print("			Failed! Exiting...")
			return False
    
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = "decrypted."+ file.filename.rsplit('.', 1)[1].lower()
            file.save(os.path.join(basedir, app.config['UPLOAD_FOLDER2'], filename))
            password = request.values.get("password")
            decryptor(os.path.join(basedir, app.config['UPLOAD_FOLDER2'], filename),password)
            return redirect(url_for('downloadFile',filename=filename,type=2))
    return render_template('decrypt.html')

if __name__ == '__main__':
    app.debug = True
    app.run()
