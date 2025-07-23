# ==================================================================================
# IP 주소 및 포트 스캐너 (v2.0)
#
# 이 스크립트는 특정 IP 주소의 포트가 열려 있는지 확인하거나,
# 지정된 IP 주소 범위 전체를 스캔하여 열려 있는 포트를 찾아 파일에 저장합니다.
# ==================================================================================

import socket
import sys
import threading
import time
import argparse

# --- 기본 설정 ---
# 아래 값들은 스크립트 실행 시 별도의 옵션을 주지 않을 경우 사용되는 기본값입니다.
# 터미널에서 명령어를 입력하여 이 설정들을 대부분 변경할 수 있습니다.

# 스캔할 기본 포트 번호입니다.
DEFAULT_PORT = 80

# 각 IP에 연결을 시도할 때 기다리는 최대 시간(초)입니다.
# 네트워크 상태가 좋지 않거나 느린 서버를 찾으려면 이 값을 늘릴 수 있습니다. (예: 1.0)
CONNECTION_TIMEOUT = 0.5

# 스캔에 성공한 IP 주소와 포트가 저장될 파일의 이름입니다.
OUTPUT_FILE = "found_ips.txt"

# 스캔 시 동시에 작업할 스레드(일꾼)의 수입니다.
# 숫자가 높을수록 스캔 속도가 빨라지지만, 컴퓨터와 네트워크에 부담을 줄 수 있습니다.
# 인터넷 회선이 빠르거나 컴퓨터 성능이 좋다면 값을 높여도 좋습니다. (예: 500 또는 1000)
DEFAULT_THREADS = 200

print_lock = threading.Lock()
found_ips_count = 0
scanned_count = 0
next_ip_to_scan = 0
next_ip_lock = threading.Lock()


def check_ip(address, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(CONNECTION_TIMEOUT)
            s.connect((address, port))
            return True
    except (socket.timeout, ConnectionRefusedError, OSError, socket.herror, socket.gaierror):
        return False

def save_found_ip(ip, port):
    with print_lock:
        with open(OUTPUT_FILE, "a") as f:
            f.write(f"{ip}:{port}\n")

def int_to_ip_str(ip_int):
    return f"{(ip_int >> 24) & 255}.{(ip_int >> 16) & 255}.{(ip_int >> 8) & 255}.{ip_int & 255}"

def ip_str_to_int(ip_str):
    parts = list(map(int, ip_str.split('.')))
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def worker(start_int, end_int, port_to_check):
    global scanned_count, found_ips_count, next_ip_to_scan

    while True:
        with next_ip_lock:
            current_ip_int = next_ip_to_scan
            next_ip_to_scan += 1

        if current_ip_int > end_int:
            break

        ip_address = int_to_ip_str(current_ip_int)

        if check_ip(ip_address, port_to_check):
            with print_lock:
                found_ips_count += 1
                print(f"\n[성공] {ip_address}:{port_to_check} (파일에 저장됨)")
                save_found_ip(ip_address, port_to_check)
        
        with print_lock:
            scanned_count += 1

def run_range_scan(start_ip_str, end_ip_str, port, threads):
    global next_ip_to_scan
    
    start_int = ip_str_to_int(start_ip_str)
    end_int = ip_str_to_int(end_ip_str)
    total_ips = end_int - start_int + 1

    next_ip_to_scan = start_int

    print("IP 범위 스캔을 시작합니다...")
    print(f"범위: {start_ip_str} - {end_ip_str}")
    print(f"포트: {port}")
    print(f"스레드 수: {threads}")
    print(f"총 {total_ips:,}개의 IP를 스캔합니다.")
    print("-" * 30)

    thread_list = []
    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(start_int, end_int, port))
        thread.daemon = True
        thread.start()
        thread_list.append(thread)

    start_time = time.time()
    try:
        while scanned_count < total_ips:
            time.sleep(1)
            elapsed_time = time.time() - start_time
            ips_per_sec = scanned_count / elapsed_time if elapsed_time > 0 else 0
            
            remaining_ips = total_ips - scanned_count
            if ips_per_sec > 0:
                eta_seconds = remaining_ips / ips_per_sec
                eta_str = time.strftime("%H:%M:%S", time.gmtime(eta_seconds))
            else:
                eta_str = "계산 중"

            progress = (scanned_count / total_ips) * 100
            sys.stdout.write(
                f"\r[진행] {scanned_count:,}/{total_ips:,} ({progress:.2f}%) | "
                f"[찾음] {found_ips_count} | "
                f"[속도] {ips_per_sec:.2f} IP/s | "
                f"[ETA] {eta_str}   "
            )
            sys.stdout.flush()
            
            if not any(t.is_alive() for t in thread_list):
                break
    except KeyboardInterrupt:
        print("\n사용자에 의해 스캔이 중단되었습니다. (Ctrl+C)")

    sys.stdout.write(
        f"\r[완료] 총 {scanned_count:,}개 IP 확인 | 찾은 IP: {found_ips_count}개 | 최종 정리 중...{' ' * 10}"
    )
    sys.stdout.flush()
    
    print("\n" + "-" * 30)
    print("스캔이 종료되었습니다.")

def run_single_test(ip, port):
    print(f"단일 테스트: {ip}:{port} (타임아웃: {CONNECTION_TIMEOUT}초)")
    print("-" * 30)
    if check_ip(ip, port):
        print(f"[성공] {ip}:{port}에 연결할 수 있습니다.")
        save_found_ip(ip, port)
    else:
        print(f"[실패] {ip}:{port}에 연결할 수 없습니다.")
    print("-" * 30)

# --- 메인 실행 부분 --- 
def main():
    # --- 사용법 안내 ---
    # 이 스크립트는 터미널(명령 프롬프트, PowerShell 등)에서 실행해야 합니다.
    # 
    # [기본 사용법]
    # python ip_scanner.py [모드] [옵션]
    #
    # [모드 1: IP 범위 스캔]
    # 특정 IP 범위를 스캔하여 열린 포트를 찾습니다.
    # 예시 1: 192.168.0.1 부터 192.168.0.255 까지 25565 포트를 스캔
    #   python ip_scanner.py --start 192.168.0.1 --end 192.168.0.255 --port 25565
    #
    # 예시 2: 10.0.0.0 부터 10.0.255.255 까지 기본 포트(25565)로 스캔
    #   python ip_scanner.py --start 10.0.0.0 --end 10.0.255.255
    #
    # [모드 2: 특정 IP 테스트]
    # 하나의 IP 주소와 포트만 간단하게 테스트합니다.
    # 예시: 8.8.8.8 IP의 53번 포트가 열려있는지 확인
    #   python ip_scanner.py --test 8.8.8.8 --port 53
    #
    # [도움말 보기]
    # 사용 가능한 모든 옵션을 보려면 아래 명령어를 입력하세요.
    #   python ip_scanner.py --help
    # --------------------------------------------------------------------------
    parser = argparse.ArgumentParser(
        description="IP 주소 및 포트 스캐너. 특정 IP를 테스트하거나 지정된 범위의 IP를 스캔합니다.",
        epilog="사용법 예시:\n  범위 스캔: python ip_scanner.py --start 192.168.0.1 --end 192.168.0.255\n  단일 테스트: python ip_scanner.py --test 8.8.8.8 --port 53",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--test", 
        type=str, 
        metavar="IP_ADDRESS",
        help="테스트할 단일 IP 주소를 지정합니다."
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=DEFAULT_PORT, 
        help=f"스캔 또는 테스트할 포트 번호입니다. (기본값: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--start", 
        type=str, 
        metavar="START_IP",
        help="범위 스캔을 시작할 IP 주소입니다. (예: 192.168.0.1)"
    )
    parser.add_argument(
        "--end", 
        type=str, 
        metavar="END_IP",
        help="범위 스캔을 종료할 IP 주소입니다. (예: 192.168.0.255)"
    )
    parser.add_argument(
        "--threads", 
        type=int, 
        default=DEFAULT_THREADS,
        help=f"동시에 실행할 스레드(작업자)의 수입니다. (기본값: {DEFAULT_THREADS})"
    )
    
    args = parser.parse_args()

    if args.test:
        run_single_test(args.test, args.port)
    elif args.start and args.end:
        run_range_scan(args.start, args.end, args.port, args.threads)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
