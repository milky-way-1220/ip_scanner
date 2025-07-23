import socket
import sys
import threading
import time
import argparse

# --- 기본 설정 ---
DEFAULT_PORT = 25565
CONNECTION_TIMEOUT = 0.5
OUTPUT_FILE = "found_ips.txt"
DEFAULT_THREADS = 200

# 스레드 간 공유 데이터 및 제어
print_lock = threading.Lock()
found_ips_count = 0
scanned_count = 0
# 스캔할 다음 IP 주소를 추적하는 카운터 (정수 형태)
# threading.Lock()을 사용하여 여러 스레드가 안전하게 접근하도록 합니다.
next_ip_to_scan = 0 
next_ip_lock = threading.Lock()

def check_ip(address, port):
    """지정된 IP와 포트에 TCP 연결을 시도합니다."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(CONNECTION_TIMEOUT)
            s.connect((address, port))
            return True
    except (socket.timeout, ConnectionRefusedError, OSError, socket.herror, socket.gaierror):
        return False

def save_found_ip(ip, port):
    """성공한 IP와 포트를 파일에 기록합니다."""
    with print_lock:
        with open(OUTPUT_FILE, "a") as f:
            f.write(f"{ip}:{port}\n")

def int_to_ip_str(ip_int):
    """정수를 점으로 구분된 IP 주소 문자열로 변환합니다."""
    return f"{(ip_int >> 24) & 255}.{(ip_int >> 16) & 255}.{(ip_int >> 8) & 255}.{ip_int & 255}"

def ip_str_to_int(ip_str):
    """점으로 구분된 IP 주소 문자열을 정수로 변환합니다."""
    parts = list(map(int, ip_str.split('.')))
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def worker(start_int, end_int, port_to_check):
    """작업자 스레드: 다음 IP를 가져와 스캔하고 결과를 처리합니다."""
    global scanned_count, found_ips_count, next_ip_to_scan

    while True:
        with next_ip_lock:
            current_ip_int = next_ip_to_scan
            next_ip_to_scan += 1

        if current_ip_int > end_int:
            break # 스캔 범위를 벗어나면 스레드 종료

        ip_address = int_to_ip_str(current_ip_int)

        if check_ip(ip_address, port_to_check):
            with print_lock:
                found_ips_count += 1
                # 진행률 표시줄이 지워지지 않도록 줄바꿈 추가
                print(f"\n[성공] {ip_address}:{port_to_check} (파일에 저장됨)")
                save_found_ip(ip_address, port_to_check)
        
        with print_lock:
            scanned_count += 1

def run_range_scan(start_ip_str, end_ip_str, port, threads):
    """지정된 IP 범위에 대해 스캔을 실행합니다."""
    global next_ip_to_scan
    
    start_int = ip_str_to_int(start_ip_str)
    end_int = ip_str_to_int(end_ip_str)
    total_ips = end_int - start_int + 1

    # 스캔 시작 IP 설정
    next_ip_to_scan = start_int

    print("IP 범위 스캔을 시작합니다...")
    print(f"범위: {start_ip_str} - {end_ip_str}")
    print(f"포트: {port}")
    print(f"스레드 수: {threads}")
    print(f"총 {total_ips:,}개의 IP를 스캔합니다.")
    print("-" * 30)

    thread_list = []
    for _ in range(threads):
        # 각 스레드에 시작/종료 IP(정수)와 포트 번호를 전달합니다.
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
            
            # 모든 스레드가 종료되었는지 확인 (더 안정적인 방식)
            if not any(t.is_alive() for t in thread_list):
                break
    except KeyboardInterrupt:
        print("\n사용자에 의해 스캔이 중단되었습니다.")

    # 최종 결과 표시
    sys.stdout.write(
        f"\r[완료] 총 {scanned_count:,}개 IP 확인 | 찾은 IP: {found_ips_count}개 | 최종 정리 중...{' ' * 10}"
    )
    sys.stdout.flush()
    
    print("\n" + "-" * 30)
    print("스캔이 종료되었습니다.")

def run_single_test(ip, port):
    """지정된 단일 IP와 포트를 테스트합니다."""
    print(f"단일 테스트: {ip}:{port} (타임아웃: {CONNECTION_TIMEOUT}초)")
    print("-" * 30)
    if check_ip(ip, port):
        print(f"[성공] {ip}:{port}에 연결할 수 있습니다.")
        save_found_ip(ip, port)
    else:
        print(f"[실패] {ip}:{port}에 연결할 수 없습니다.")
    print("-" * 30)

def main():
    """메인 함수: 명령줄 인수를 파싱하고 적절한 모드를 실행합니다."""
    parser = argparse.ArgumentParser(
        description="IP 주소 및 포트 스캐너. 테스트, 또는 지정된 범위의 IP를 스캔합니다.",
        formatter_class=argparse.RawTextHelpFormatter # 도움말 포맷 개선
    )
    parser.add_argument(
        "--test", 
        type=str, 
        metavar="IP_ADDRESS",
        help="테스트할 단일 IP 주소를 지정합니다. --port 옵션과 함께 사용할 수 있습니다."
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=DEFAULT_PORT, 
        help=f"스캔 또는 테스트할 포트 번호. (기본값: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--start", 
        type=str, 
        metavar="START_IP",
        help="범위 스캔을 시작할 IP 주소. (예: 192.168.0.1)"
    )
    parser.add_argument(
        "--end", 
        type=str, 
        metavar="END_IP",
        help="범위 스캔을 종료할 IP 주소. (예: 192.168.0.255)"
    )
    parser.add_argument(
        "--threads", 
        type=int, 
        default=DEFAULT_THREADS,
        help=f"동시에 실행할 스레드(작업자) 수. (기본값: {DEFAULT_THREADS})"
    )
    
    args = parser.parse_args()

    # 단일 테스트 모드
    if args.test:
        run_single_test(args.test, args.port)
    # 범위 스캔 모드
    elif args.start and args.end:
        run_range_scan(args.start, args.end, args.port, args.threads)
    # 잘못된 사용법 안내
    else:
        print("잘못된 사용법입니다. 아래 도움말을 확인하세요.")
        parser.print_help()

if __name__ == "__main__":
    main()
