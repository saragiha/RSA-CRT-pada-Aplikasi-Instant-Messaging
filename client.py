import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QSpinBox,
    QHBoxLayout, QRadioButton, QButtonGroup
)
from PyQt5.QtCore import Qt, pyqtSignal
from threading import Thread

class ClientApp(QWidget):
    message_received = pyqtSignal(str)
    
    def __init__(self, port=3000):
        super().__init__()
        self.rsa_key = None
        self.server_socket = None
        self.initUI()

    def initUI(self, port=3000):
        self.username_label = QLabel('Username:', self)
        self.username_edit = QLineEdit(self)

        self.server_ip_label = QLabel('Server IP:', self)
        self.server_ip_edit = QLineEdit(self)
        self.connect_button = QPushButton('Connect to Server', self)

        self.p_label = QLabel('Value p:', self)
        self.p_spinbox = QSpinBox(self)
        self.q_label = QLabel('Value q:', self)
        self.q_spinbox = QSpinBox(self)

        self.info_label = QLabel('', self)

        button_layout = QHBoxLayout()

        self.generate_key_button = QPushButton('Generate Key', self)
        self.generate_random_key_button = QPushButton('Random Key', self)

        button_layout.addWidget(self.generate_key_button)
        button_layout.addWidget(self.generate_random_key_button)

        self.encryption_method_label = QLabel('Encryption Method:', self)
        
        # Radio buttons for selecting encryption method
        self.rsa_crt_radio = QRadioButton('RSA-CRT', self)
        self.rsa_radio = QRadioButton('RSA', self)

        # Set up a button group for exclusive selection
        self.encryption_method_group = QButtonGroup(self)
        self.encryption_method_group.addButton(self.rsa_crt_radio)
        self.encryption_method_group.addButton(self.rsa_radio)
        self.rsa_crt_radio.setChecked(False)  # Default selection

        self.send_message_edit = QTextEdit(self)
        self.send_button = QPushButton('Send Message', self)
        self.send_button.clicked.connect(self.send_message)
        self.max_char_label = QLabel('Max 1024 characters: -', self)

        self.message_output_text = QTextEdit(self)
        self.message_output_text.setReadOnly(True)

        vbox = QVBoxLayout()

        vbox.addWidget(self.username_label)
        vbox.addWidget(self.username_edit)

        vbox.addWidget(self.server_ip_label)
        vbox.addWidget(self.server_ip_edit)
        vbox.addWidget(self.connect_button)

        hbox_pq = QHBoxLayout()
        hbox_pq.addWidget(self.p_label)
        hbox_pq.addWidget(self.p_spinbox)
        hbox_pq.addWidget(self.q_label)
        hbox_pq.addWidget(self.q_spinbox)
        vbox.addLayout(hbox_pq)

        vbox.addWidget(self.info_label)

        vbox.addLayout(button_layout)

        vbox.addWidget(self.encryption_method_label)
        vbox.addWidget(self.rsa_crt_radio)
        vbox.addWidget(self.rsa_radio)

        vbox.addWidget(self.send_message_edit)
        vbox.addWidget(self.send_button)
        vbox.addWidget(self.max_char_label)

        vbox.addWidget(self.message_output_text)

        self.setLayout(vbox)

        self.setGeometry(100, 100, 400, 500)
        self.setWindowTitle('RSA-CRT IM - Client')
        self.show()

        self.generate_key_button.clicked.connect(self.generate_key)
        self.generate_random_key_button.clicked.connect(self.generate_random_key)
        self.connect_button.clicked.connect(self.connect_to_server)
        self.send_button.clicked.connect(self.send_message)

    def generate_key(self):
        # Generate key with specified p and q values
        p_value = self.p_spinbox.value()
        q_value = self.q_spinbox.value()

        # Ensure p and q are prime numbers
        if not is_prime(p_value) or not is_prime(q_value):
            self.info_label.setText("p and q must be prime numbers.")
            return

        key = RSA.construct((p_value * q_value, 65537, pow(65537, -1, (p_value-1)*(q_value-1))))

        public_key = key.publickey().export_key()
        private_key = key.export_key()

        self.info_label.setText(f"Public Key:\n{public_key.decode('utf-8')}")
        with open('client_private.pem', 'wb') as f:
            f.write(private_key)

        self.rsa_key = key
        
        self.encryption_method_group.setExclusive(False)
        self.rsa_crt_radio.setChecked(False)
        self.rsa_radio.setChecked(False)
        self.encryption_method_group.setExclusive(True)

    def generate_random_key(self):
        random_key = RSA.generate(2048)
        public_key = random_key.publickey().export_key()

        self.info_label.setText(f"Random Key:\n{public_key.decode('utf-8')}")
        with open('random_private.pem', 'wb') as f:
            f.write(random_key.export_key())
            
        self.rsa_key = random_key

    def connect_to_server(self):
        server_ip = self.server_ip_edit.text()
        server_port = 3001  
        username = self.username_edit.text()
        
        if not username or not server_ip:
            self.info_label.setText("Username and Server IP required.")
            return
        
        if not self.rsa_key:
            self.info_label.setText("Generate RSA key pair first.")
            return

        self.info_label.setText('Connection Status: Connecting to Server')

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((server_ip, server_port))

                # Combine username and public key for sending
                data_to_send = f"{username}\n{self.rsa_key.publickey().export_key()}"
                s.send(data_to_send.encode('utf-8'))

                # Receive a response from the server
                response = s.recv(1024).decode('utf-8')
                self.message_output_text.append(response)
                print(f"Server response: {response}")
                
                self.server_socket = s
                
                receive_thread = Thread(target=self.receive_message)
                receive_thread.start()

        except socket.error as se:
            print(f"Socket error: {str(se)}")
            self.info_label.setText('Connection Status: Connection Failed')
        except Exception as e:
            print(f"Connection error: {str(e)}")
            self.info_label.setText('Connection Status: Connection Failed')

    def send_message(self):
        if not hasattr(self, 'server_socket'):
            self.info_label.setText("Connect to the server first.")
            return
        
        if not self.rsa_key:
            self.info_label.setText("Generate RSA key pair first.")
            return

        message = self.send_message_edit.toPlainText().encode('utf-8')
        self.message_output_text.append(f'Message sent: {message.decode("utf-8")}')
        
        cipher = PKCS1_OAEP.new(self.rsa_key)
        encrypted_message = cipher.encrypt(message)

        # Determine selected encryption method
        selected_method = 'RSA-CRT' if self.rsa_crt_radio.isChecked() else 'RSA'

        if selected_method == 'RSA-CRT':
            cipher = PKCS1_OAEP.new(self.rsa_key)

        encrypted_message = cipher.encrypt(message)
        # Send the encrypted message to the server (implement server-side handling)
        
        self.server_socket.send(encrypted_message)
        
    
    def receive_message(self):
        try:
            while True:
                encrypted_message = self. server_socket.recv(1042)
                if not encrypted_message:
                    break
                
                cipher = PKCS1_OAEP.new(self.rsa_key)
                decrypted_message = cipher.decrypt(encrypted_message).decode('utf-8')
                
                decrypted_message = self.rsa_key.decrypt(encrypted_message)
                self.message_received.emit(decrypted_message.decode('utf-8'))
                
        except Exception as e:
            print(f"Error receiving message: {str(e)}")    

def is_prime(n):
    if n <= 1:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    max_divisor = int(n**0.5) + 1
    for d in range(3, max_divisor, 2):
        if n % d == 0:
            return False
    return True

if __name__ == '__main__':
    app = QApplication([])
    client = ClientApp()
    app.exec_()