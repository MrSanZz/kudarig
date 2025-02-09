#!/usr/bin/env python3

try:
    import socket
    import json
    import hashlib
    import time
    import sys
    import threading
    from datetime import datetime
    import sys
    from sys import stdout
    from colorama import init
    import os
    import argparse
    import psutil
except:
    import os
    os.system('pip3 install hashlib' if os.name == 'nt' else 'pip3 install hashlib --break-system-packages')
    os.system('pip3 install colorama' if os.name == 'nt' else 'pip3 install colorama --break-system-packages')
    os.system('pip3 install argparse' if os.name == 'nt' else 'pip3 install argparse --break-system-packages')
    os.system('pip3 install psutil' if os.name == 'nt' else 'pip3 install psutil --break-system-packages')
    os.system('python3 kudarig_andro.py')

init(autoreset=True)

parser = argparse.ArgumentParser(description='Usage: python3 kudarig.py [OPTIONS]')
parser.add_argument('-o', '--pool', type=str, help='Pool mining server', required=True)
parser.add_argument('-u', '--userworker',type=str, help='Mining server username and workername', required=True)
parser.add_argument('-p', '--password', type=str, help='Pool password', default='x')
parser.add_argument('-d', '--difficulty', type=int, help='Difficulty hash', default=8)
args = parser.parse_args()

global accepted, cancelled
accepted = 0
cancelled = 0

# Pool details (Slush Pool sebagai contoh)
try:
    FILTERED_URL = str(args.pool).replace('stratum+tcp://', '') if 'stratum+tcp://' in sys.argv[1] else sys.argv[1].replace('stratum+ssl://', '').replace('--pool=', '').replace('-o', '--pool=').split(':')
    POOL = (FILTERED_URL).split(':')[0] if type(FILTERED_URL) != list else (FILTERED_URL)[0]
    PORT = (FILTERED_URL).split(':')[1] if type(FILTERED_URL) != list else (FILTERED_URL)[1]
    USERNAME = str(args.userworker)
    PASSWORD = str(args.password)
    DIFFICULTY = int(args.difficulty)
except Exception as e:
    print(e)
    exit()

class Color:
    def red():
        red = '\033[1;31m'
        return red
    def yellow():
        yellow = '\033[1;33m'
        return yellow
    def blue():
        blue = '\033[1;34m'
        return blue
    def green():
        green = '\033[1;32m'
        return green
    def white():
        white = '\033[0m'
        return white
    class Background:
        def red_lime():
            red = '\033[1;31;46m'
            return red
        def yellow_lime():
            yellow = '\033[1;33;46m'
            return yellow
        def blue_lime():
            blue = '\033[1;34;46m'
            return blue
        def green_lime():
            green = '\033[1;32;46m'
            return green
        def white_lime():
            white = '\033[0;46m'
            return white
        def red_purple():
            red = '\033[1;31;45m'
            return red
        def yellow_purple():
            yellow = '\033[1;33;45m'
            return yellow
        def blue_purple():
            blue = '\033[1;34;45m'
            return blue
        def green_purple():
            green = '\033[1;32;45m'
            return green
        def white_purple():
            white = '\033[0;45m'
            return white

# Stratum client class
class StratumClient:
    try:
        def __init__(self, pool, port, username, password):
            self.pool = pool
            self.port = int(port)
            self.username = username
            self.password = password
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.buffer = b""
            self.job = None
            self.extranonce2 = "0"*8  # Default extranonce2
            self.ntime = None  # Akan diisi dari job
            self.difficulty = 1  # Default difficulty
            self.hash_count = 0  # Menghitung jumlah hash per detik
            self.start_time = time.time()  # Waktu mulai mining

        def times(self):
            # Mendapatkan waktu saat ini
            now = datetime.now()

            # Format sesuai kebutuhan
            formatted_time = now.strftime(" %Y %H:%M:%S ")
            return formatted_time

        def connect(self):
            """Connect to the mining pool."""
            formatted_time = self.times()
            try:
                self.socket.connect((self.pool, self.port))
                print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Connected to {self.pool}:{self.port}")
                print(f"[{formatted_time}] {Color.Background.white_lime()} miner      {Color.white()} Start Mining.. [Username: {self.username} password: {PASSWORD} diff: {DIFFICULTY}]")
            except Exception as e:
                print(f"\n[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Connection error: {e}")
                self.socket.close()
                os.system(f'python3 kudarig_andro.py --pool={POOL}:{PORT} --userworker={USERNAME} --password={PASSWORD} --diff={DIFFICULTY}')
                exit()
                return False
            return True

        def send_message(self, message):
            """Send a JSON message to the pool."""
            formatted_time = self.times()
            try:
                self.socket.sendall(json.dumps(message).encode('utf-8') + b'\n')
            except Exception as e:
                print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Error sending message: {e}")
                print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Restarting..")
                self.socket.close()
                self.connect()

        def receive_message(self):
            """Receive JSON messages from the pool."""
            formatted_time = self.times()
            try:
                while b'\n' not in self.buffer:
                    data = self.socket.recv(1024)
                    if not data:
                        raise ConnectionError("Connection closed by server")
                    self.buffer += data

                # Split buffer into messages
                messages = self.buffer.split(b'\n')
                # Keep the remaining incomplete data in buffer
                self.buffer = messages.pop() if messages[-1] else b''

                # Decode the first complete message
                print(f"[{formatted_time}] {Color.Background.white_lime()} miner      {Color.white()} Mining job received.")
                return json.loads(messages[0].decode('utf-8'))
            except json.JSONDecodeError as e:
                print(f"[{formatted_time}] {Color.Background.white_lime()} miner      {Color.white()} JSON decode error: {e}")
                return None
            except:
                pass


        def subscribe(self):
            """Subscribe to the mining pool."""
            message = {
                "id": 1,
                "method": "mining.subscribe",
                "params": []
            }
            self.send_message(message)
            return self.receive_message()

        def authorize(self):
            """Authorize the miner with the pool."""
            message = {
                "id": 2,
                "method": "mining.authorize",
                "params": [self.username, self.password]
            }
            self.send_message(message)
            return self.receive_message()

        def handle_job(self, job):
            try:
                """Handle mining job: hash and solve the job."""
                formatted_time = self.times()
                job_id = job[0]
                prevhash = job[1]
                coinb1 = job[2]
                coinb2 = job[3]
                merkle_branch = job[4]
                version = job[5]
                nbits = job[6]
                self.ntime = job[7]  # Update ntime from job
                clean_jobs = job[8]

                # Target difficulty
                def nbits_to_target(nbits):
                    exponent = int(nbits[:2], 16)
                    mantissa = int(nbits[2:], 16)
                    return mantissa * (2 ** (8 * (exponent - 3)))

                target = nbits_to_target(nbits)

                # Mining loop (simulasi)
                nonce = 0
                while True:
                    # Build block header
                    header = (
                        version + prevhash + coinb1 + merkle_branch[0] + self.ntime + nbits +
                        self.extranonce2 + f"{nonce:08x}"
                    )
                    header_bytes = bytes.fromhex(header)
                    hash_result = hashlib.sha256(hashlib.sha256(header_bytes).digest()).hexdigest()

                    # Update hash count
                    self.hash_count += 1

                    # Check if the hash is below the target
                    if int(hash_result, 16) < target:
                        print(f"\n[{formatted_time}] {Color.Background.white_purple()} miner      {Color.white()} Found solution: {hash_result} with nonce {nonce:08x}")
                        self.submit_solution(job_id, nonce)
                        break
                    if hash_result.startswith("0"*int(DIFFICULTY)):
                        print(f"\n[{formatted_time}] {Color.Background.white_lime()} miner      {Color.white()} Submitting: {hash_result} with nonce {nonce:08x} [{job_id}]")
                        self.submit_solution(job_id, nonce)
                    nonce += 1

                    # Update hashrate display
                    self.update_hashrate(hash_result, target, nonce)
            except KeyboardInterrupt:
                print(f"\n[{formatted_time}] {Color.Background.yellow_lime()} signal     {Color.white()} Stop signal received, exiting..")
                exit()

        def submit_solution(self, job_id, nonce):
            """Submit the solution (nonce) to the server."""
            global accepted, cancelled
            formatted_time = self.times()
            message = {
                "id": 3,
                "method": "mining.submit",
                "params": [
                    self.username,
                    job_id,
                    self.extranonce2,
                    self.ntime,
                    f"{nonce:08x}"
                ]
            }
            self.send_message(message)
            response = self.receive_message()

            if response is not None:
                item_terakhir = list(response.values())[-1]
                # Jika item terakhir adalah list, ambil elemen terakhir dari list tersebut
                if isinstance(item_terakhir, list):
                    item_terakhir = item_terakhir[-1]
                print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Submit response: {response}")
                if item_terakhir != False:
                    accepted += 1
                    print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Submit result: {Color.Background.green_purple()}Accepted {accepted}{Color.white()}/{Color.red()}{cancelled}{Color.white()}")
                elif item_terakhir == False:
                    cancelled += 1
                    print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Submit result: {Color.Background.green_purple()}Accepted {accepted}{Color.white()}/{Color.red()}{cancelled}{Color.white()}")
                else:
                    print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Submit result: {Color.Background.green_purple()}Accepted ?{Color.white()}/{Color.red()}?{Color.white()}")
            else:
                print(4)
                cancelled += 1
                print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Submit result: {Color.Background.green_purple()}Accepted {accepted}{Color.white()}/{Color.red()}{cancelled}{Color.white()}")

        def update_hashrates(self, a, b, nonce):
            """Calculate and display the current hashrate."""
            elapsed_time = time.time() - self.start_time
            if nonce % 1000000 == 0:
                hashrate = self.hash_count / elapsed_time
                sys.stdout.write(f"\rHashrate: {hashrate:.2f} H/s - current: {len(a)} - target: {len(str(b))} - nonce: {nonce}")
                sys.stdout.flush()

        def update_hashrate(self, a, b, nonce):
            """Calculate and display the current hashrate."""
            formatted_time = self.times()
            elapsed_time = time.time() - self.start_time
            if nonce % 1000000 == 0:
                hashrate = self.hash_count / elapsed_time
                hashrate_mhs = hashrate / 1e6
                sys.stdout.write(f"\r[{formatted_time}] {Color.Background.white_lime()} miner      {Color.white()} Speed: {hashrate:.2f} // {hashrate_mhs:.2f} MH/s")
                sys.stdout.flush()

        def start(self):
            """Start the mining process."""
            formatted_time = self.times()
            if not self.connect():
                return

            # Subscribe to the pool
            response = self.subscribe()
            if response['error'] == None:
                print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Subscribe response: {Color.green()}Successfully{Color.white()}")
            else:
                print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Subscribe response: {Color.red()}Failed{Color.white()}")
                exit()

            # Authorize the miner
            response = self.authorize()
            if response['error'] == None:
                print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Authorize response: {Color.green()}Successfully{Color.white()}")
            elif response['id'] == None:
                print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Subscribe response: {Color.red()}Failed{Color.white()}")
                exit()
            else:
                print(f"[{formatted_time}] {Color.Background.white_purple()} connection {Color.white()} Subscribe response: {Color.red()}Failed{Color.white()}")
                exit()

            # Keep listening for new jobs and mine
            while True:
                response = self.receive_message()
                if response:
                    # Process the mining job
                    if response.get("method") == "mining.notify":
                        job = response["params"]
                        self.handle_job(job)

        def start_hashrate_reporter(self):
            """Start a thread to report hashrate periodically."""
            def reporter():
                while True:
                    self.report_hashrate()
                    time.sleep(120)  # Kirim laporan setiap 2 menit

            report_thread = threading.Thread(target=reporter, daemon=True)
            report_thread.start()

        def report_hashrate(self):
            """Report the current hashrate to the pool."""
            formatted_time = self.times()
            elapsed_time = time.time() - self.start_time
            if elapsed_time > 0:
                hashrate = self.hash_count / elapsed_time  # Hashrate dalam hash per detik
                hashrate_mhs = hashrate / 1e6  # Konversi ke MH/s
                print(f"\n[{formatted_time}] {Color.Background.white_lime()} miner      {Color.white()} Reporting Hashrate: {hashrate_mhs:.2f} MH/s")

                # Kirim pesan (beberapa pool membutuhkan metode khusus)
                message = {
                    "id": 4,  # ID pesan unik
                    "method": "mining.extranonce.subscribe",
                    "params": [hashrate_mhs]
                }
                self.send_message(message)
    except KeyboardInterrupt:
        now = datetime.now()
        # Format sesuai kebutuhan
        formatted_time = now.strftime(" %Y %H:%M:%S ")
        print(f"\n[{formatted_time}] {Color.Background.yellow_lime()} signal     {Color.white()} Stop signal received, exiting..")
        exit()

# Main function
def main():
    stdout.flush()
    p = psutil.Process(os.getpid())
    p.nice(psutil.REALTIME_PRIORITY_CLASS if os.name == 'nt' else -40)
    client = StratumClient(POOL, PORT, USERNAME, PASSWORD)
    client.start()

if __name__ == "__main__":
    main()
