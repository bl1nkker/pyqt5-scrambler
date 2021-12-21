from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import QApplication
# Hashlib Setup
import hashlib
# RSA screen setup
import rsa
from rsa import PublicKey

SH = bytes()

# Caesar screen Setup
alphabet = "abcdefghijklmnopqrstuvwxyz "
letter_to_index = dict(zip(alphabet, range(len(alphabet))))
index_to_letter = dict(zip(range(len(alphabet)), alphabet))

# PyQT5
MainScreenForm, MainScreenWindow = uic.loadUiType("main_screen.ui")
HashlibScreenForm, HashlibScreenWindow = uic.loadUiType("hashlib_screen.ui")
RsaScreenForm, RsaScreenWindow = uic.loadUiType("rsa_screen.ui")
CaesarScreenForm, CaesarScreenWindow = uic.loadUiType("caesar_screen.ui")

app = QApplication([])
main_screen_window = MainScreenWindow()
main_screen_form = MainScreenForm()
main_screen_form.setupUi(main_screen_window)

hashlib_screen_window = HashlibScreenWindow()
hashlib_screen_form = HashlibScreenForm()
hashlib_screen_form.setupUi(hashlib_screen_window)

rsa_screen_window = RsaScreenWindow()
rsa_screen_form = RsaScreenForm()
rsa_screen_form.setupUi(rsa_screen_window)

caesar_screen_window = CaesarScreenWindow()
caesar_screen_form = CaesarScreenForm()
caesar_screen_form.setupUi(caesar_screen_window)


# Main Screen Setup
def open_hashlib_screen():
    hashlib_screen_window.show()
    main_screen_window.hide()


def open_rsa_screen():
    rsa_screen_window.show()
    main_screen_window.hide()


def open_caesar_screen():
    caesar_screen_window.show()
    main_screen_window.hide()


def close_current_window(current_window):
    main_screen_window.show()
    current_window.hide()


def hashlib_to_md5():
    text_to_encrypt = hashlib_screen_form.textInput.text()
    encrypted_text = hashlib.md5(f'{text_to_encrypt}'.encode())
    hashlib_screen_form.md5Label.setText(encrypted_text.hexdigest())


def hashlib_to_sha256():
    text_to_encrypt = hashlib_screen_form.textInput.text()
    encrypted_text = hashlib.sha256(f'{text_to_encrypt}'.encode())
    hashlib_screen_form.sha256Label.setText(encrypted_text.hexdigest())


def rsa_encrypt_and_generate_keys():
    global SH
    text_to_encrypt = rsa_screen_form.toHashInput.text()
    message = text_to_encrypt.encode()
    hash = rsa.compute_hash(message, 'SHA-256')

    (pubkey, privkey) = rsa.newkeys(512)
    SH = rsa.sign_hash(hash, privkey, 'SHA-256')
    sh_to_display = SH.decode('utf-8', errors='ignore')
    rsa_screen_form.publicELabel.setText(f'Public Key (e): {str(pubkey.e)}')
    rsa_screen_form.publicNLabel.setText(f'Public Key (n): {str(pubkey.n)}')

    rsa_screen_form.hashLabel.setText(sh_to_display)


def rsa_verify():
    global SH
    text_to_encrypt = rsa_screen_form.toVerifyInput.text()
    message = text_to_encrypt.encode()
    e = rsa_screen_form.publicEInput.text()
    n = rsa_screen_form.publicNInput.text()
    pubkey = PublicKey(e=e, n=n)
    try:
        rsa.verify(message, SH, pubkey)
        rsa_screen_form.verifyLabel.setText('Verification passed!')
    except:
        rsa_screen_form.verifyLabel.setText('Verification failed!')


def caesar_encrypt():
    message = caesar_screen_form.encryptInput.text()
    shift = int(caesar_screen_form.encryptShiftValue.text())
    cipher = ""
    for letter in message:
        number = (letter_to_index[letter] + shift) % len(letter_to_index)
        letter = index_to_letter[number]
        cipher += letter
    caesar_screen_form.encryptLabel.setText(f'Encription Result: {cipher}')


def caesar_decrypt():
    cipher = caesar_screen_form.decryptInput.text()
    shift = int(caesar_screen_form.decryptShiftValue.text())
    decrypted = ""
    for letter in cipher:
        number = (letter_to_index[letter] - shift) % len(letter_to_index)
        letter = index_to_letter[number]
        decrypted += letter

    caesar_screen_form.decryptLabel.setText(f'Decription Result: {decrypted}')


# Main screen buttons handlers
main_screen_form.goToHashScreen.clicked.connect(open_hashlib_screen)
main_screen_form.goToRsaScreen.clicked.connect(open_rsa_screen)
main_screen_form.goToCaesarScreen.clicked.connect(open_caesar_screen)
# Hashlib screen buttons handlers
hashlib_screen_form.toSha256Button.clicked.connect(hashlib_to_sha256)
hashlib_screen_form.toMd5Button.clicked.connect(hashlib_to_md5)
hashlib_screen_form.closeButton.clicked.connect(lambda x: close_current_window(hashlib_screen_window))
# RSA screen buttons handlers
rsa_screen_form.encryptButton.clicked.connect(rsa_encrypt_and_generate_keys)
rsa_screen_form.verifyButton.clicked.connect(rsa_verify)
rsa_screen_form.closeButton.clicked.connect(lambda x: close_current_window(rsa_screen_window))
# Caesar screen buttons handlers
caesar_screen_form.encryptButton.clicked.connect(caesar_encrypt)
caesar_screen_form.decryptButton.clicked.connect(caesar_decrypt)
caesar_screen_form.closeButton.clicked.connect(lambda x: close_current_window(caesar_screen_window))

main_screen_window.show()
app.exec()
