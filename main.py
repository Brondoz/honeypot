import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading

# Constants
log_format = logging.Formatter('%(asctime)s --- %(message)s')
global failed_attempts_by_ip

# Logs
logger_prey_info = logging.getLogger('Prey_Info')
logger_prey_info.setLevel(logging.INFO)
log_handler_prey_info = RotatingFileHandler('info_audits.log', maxBytes=2000, backupCount=5)
log_handler_prey_info.setFormatter(log_format)
logger_prey_info.addHandler(log_handler_prey_info)

logger_prey_input = logging.getLogger('Prey_Input')
logger_prey_input.setLevel(logging.INFO)
log_handler_prey_input = RotatingFileHandler('input_audits.log', maxBytes=2000, backupCount=5)
log_handler_prey_input.setFormatter(log_format)
logger_prey_input.addHandler(log_handler_prey_input)

logger_prey_passwords = logging.getLogger('Prey_Passwords')
logger_prey_passwords.setLevel(logging.INFO)
log_handler_prey_passwords = RotatingFileHandler('password_audits.log', maxBytes=2000, backupCount=5)
log_handler_prey_passwords.setFormatter(log_format)
logger_prey_passwords.addHandler(log_handler_prey_passwords)

failed_attempts_by_ip = {}

# SSH Server
class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

        # Utilisation du dictionnaire global pour suivre les échecs par IP
        if client_ip not in failed_attempts_by_ip:
            failed_attempts_by_ip[client_ip] = 0

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        # Log the attempted username and password
        logger_prey_passwords.info(f"Login attempt - IP: {self.client_ip} - Username: {username} - Password: {password}")

        global failed_attempts_by_ip
        if username == self.input_username and password == self.input_password:
            failed_attempts_by_ip[self.client_ip] = 0
            return paramiko.AUTH_SUCCESSFUL
        else:
            # Incrémenter le compteur d'échecs pour l'IP
            failed_attempts_by_ip[self.client_ip] += 1

            # Autoriser la connexion après 10 échecs
            if failed_attempts_by_ip[self.client_ip] >= 10:
                logger_prey_info.info(f"IP {self.client_ip} autorisée après {failed_attempts_by_ip[self.client_ip]} échecs.")
                failed_attempts_by_ip[self.client_ip] = 0
                return paramiko.AUTH_SUCCESSFUL

            return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


# Shell Emulator
def emul_shell(channel, client_ip):
    channel.send(b'phil-exucutive1$ ')
    command = b""

    while True:
        try:
            char = channel.recv(1)
            if not char:
                break
            channel.send(char)
            command += char

            if char == b'\r':
                command_str = command.strip().decode('utf-8')

                if command_str == 'exit':
                    channel.send(b'\nGoodbye!\r\n')
                    break
                elif command_str == 'pwd':
                    response = b'\n/usr/local/\r\n'
                elif command_str == 'whoami':
                    response = b'\nroot\r\n'
                elif command_str == 'ls':
                    response = b'\nlmao.conf\r\n'
                elif command_str == 'cat lmao.conf':
                    response = b'\nRight into my trap!!!! ;)\r\n'
                else:
                    response = b'\nCommand not found: ' + command + b'\r\n'

                logger_prey_input.info(f"{client_ip} -> {command_str}")
                channel.send(response)
                channel.send(b'phil-jumpbox2$ ')
                command = b""

        except Exception as e:
            print(f"[!] Erreur : {str(e)}")
            break

    channel.close()


# Gérer une session client
def manage_client(client, addr, host_key):
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)

        server = Server(client_ip=addr[0], input_username="root", input_password="Uxkqc4@PO_Eqgn$SNd0s_SxWp-!UWd")
        transport.start_server(server=server)

        channel = transport.accept(20)  # Timeout de 20 secondes pour l'authentification
        if channel is None:
            return

        logger_prey_info.info(f"Connexion réussie depuis {addr[0]}:{addr[1]} avec user=root")
        emul_shell(channel, addr[0])

    except Exception as e:
        print(f"[!] Erreur avec {addr[0]}: {str(e)}")

    finally:
        client.close()

# Main Logic
def main():
    host_key = paramiko.RSAKey.generate(2048)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind(('', 2222))
    server_socket.listen(100)

    print("[*] Honeypot SSH en attente de connexions sur le port 2222...")

    while True:
        try:
            client, addr = server_socket.accept()
            print(f"[*] Connexion établie depuis {addr[0]}:{addr[1]}")

            # Lancer un thread pour gérer la connexion
            thread = threading.Thread(target=manage_client, args=(client, addr, host_key))
            thread.start()

        except KeyboardInterrupt:
            print("[*] Arrêt du serveur.")
            server_socket.close()
            break

if __name__ == "__main__":
    main()
