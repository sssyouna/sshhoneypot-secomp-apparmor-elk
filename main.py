import socket
import paramiko
import threading
from   logs_writter import write_logs

BRUTEFORCE_LIMIT = 10

_attempts_left = {}
_attempts_lock = threading.Lock()

def register_login_attempt(client_addr, success):
    ip = client_addr[0]

    with _attempts_lock:
        # initialize if first time
        if ip not in _attempts_left:
            _attempts_left[ip] = BRUTEFORCE_LIMIT

        if success:
            _attempts_left[ip] = BRUTEFORCE_LIMIT
            return False

        # failed attempt
        _attempts_left[ip] -= 1

        if _attempts_left[ip] <= 0:
            write_logs(
                "[BRUTEFORCE]",
                f"Too many failed attempts (limit={BRUTEFORCE_LIMIT})",
                client_addr
            )
            return True

    return False



#create an object inheriting the paramiko server interface
#all the functions here are auto called by paramiko , that's ehy you wont see a callback
class SSHserver(paramiko.ServerInterface):
    #contructor for necessary atributtes

    def __init__(self,client_addr) -> None:
        self.client_addr = client_addr
        self.term = "unknown"
        self.width = 80
        self.height = 24
        self.shell_event = threading.Event()

    #check the credetientls and write them

    def check_auth_password(self, username, password):
        print(f"[LOGIN ATTEMPT] username:{username}, password:{password}")
        write_logs("[LOGIN ATTEMPT]",f"username:{username}, password:{password}",self.client_addr)
        if username == "yns" and password == "123":
            write_logs("[LOGGED IN]", f"username:{username}", self.client_addr)
            register_login_attempt(self.client_addr, success=True)
            return paramiko.AUTH_SUCCESSFUL

        is_bruteforce = register_login_attempt(self.client_addr, success=False)

        if is_bruteforce:
            print("[ALERT]", "Brute-force detected", self.client_addr)
            write_logs("[ALERT]", "Brute-force detected", self.client_addr)

        return paramiko.AUTH_FAILED


    #open the chanell the handle the connection 

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    #open a fake shell with dimentions
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        self.term = term
        self.width = width
        self.height = height
        return True


    def check_channel_shell_request(self, channel):
        self.shell_event.set()
        return True


    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        self.width = width
        self.height = height
        return True
    
    
import select

def handle_connection(client_sock, client_addr):
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(paramiko.RSAKey.from_private_key_file("key"))

    ssh = SSHserver(client_addr)
    transport.start_server(server=ssh)

    chan = transport.accept(20)
    if not chan:
        return

    # Wait for shell request
    ssh.shell_event.wait(10)

    # Send banner and initial prompt
    chan.send(b"Logged in successfully\r\n")
    chan.send(f"Welcome to SSH server ({ssh.term})\r\nTerminal size: {ssh.width}x{ssh.height}\r\n".encode())
    chan.send(b"$ ")

    buffer = b""
    while True:
        # Wait until the channel has data
        if chan.recv_ready():
            data = chan.recv(1024)
            if not data:
                break
            buffer += data

            # Only process commands on Enter
            if b"\r" in buffer or b"\n" in buffer:
                cmd = buffer.replace(b"\r", b"").replace(b"\x7f", b"").strip().decode(errors="ignore")
                buffer = b""
                print(f"commades sent {cmd}")
                write_logs("[COMMAND]",f"commande sent {cmd}"   , client_addr)

                if cmd.lower() in ("exit", "logout","q"):
                    chan.send(b"\r\nlogout\r\n")
                    break
                else:
                    chan.send(b"command not found\r\n$ ")

        # Sleep a tiny bit to avoid busy loop
        else:
            select.select([chan], [], [], 0.1)

    chan.close()
    transport.close()


        



def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    server_sock.bind(('', 2121))
    server_sock.listen(100)

    while True:
        client_sock, client_addr = server_sock.accept()
        write_logs("[connection ATTEMPT]","TCP connection established",client_addr)
        threading.Thread(
            target=handle_connection,
            args=(client_sock,client_addr),
            daemon=True
        ).start()


if __name__ == "__main__":
    main()


    chan.close()
    transport.close()


        



