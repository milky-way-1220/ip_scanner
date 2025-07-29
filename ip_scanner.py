# ==================================================================================
# IP 포트 스캐너 (v2.1)
#
# 이 스크립트는 특정 IP 주소의 포트가 열려 있는지 확인하거나,
# 지정된 IP 주소 범위 전체를 스캔하여 열려 있는 포트를 찾아 파일에 저장합니다.
# ==================================================================================

import socket
import sys
import threading
import time
import argparse
import psutil
import datetime

# --- 기본 설정 ---
# 아래 값들은 스크립트 실행 시 별도의 옵션을 주지 않을 경우 사용되는 기본값입니다.
# 터미널에서 명령어를 입력하여 이 설정들을 대부분 변경할 수 있습니다.

DEFAULT_PORT = 80

COMMON_PORTS = {
    'http': 80,
    'https': 443,
    'ssh': 22,
    'ftp': 21,
    'smtp': 25,
    'dns': 53,
    'minecraft': 25565
}

CONNECTION_TIMEOUT = 0.5
OUTPUT_FILE = "found_ips.txt"
DEFAULT_THREADS = 500  # 높은 값은 더 빠른 스캔을 제공하지만 시스템 부하가 증가할 수 있음

print_lock = threading.RLock()
found_ips_count = 0
scanned_count = 0
next_ip_to_scan = 0
next_ip_lock = threading.Lock()

def check_ip(address, port):
    """지정된 IP 주소와 포트에 연결을 시도하여 성공 여부를 반환합니다."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECTION_TIMEOUT)
    try:
        result = sock.connect_ex((address, port)) == 0
        return result
    except (socket.herror, socket.gaierror):
        return False
    finally:
        sock.close()

def save_found_ip(ip, port):
    """발견된 IP와 포트를 파일에 저장합니다. 스레드 안전성을 위해 잠금을 사용합니다."""
    with print_lock:
        with open(OUTPUT_FILE, "a") as f:
            f.write(f"{ip}:{port}\n")

def int_to_ip_str(ip_int):
    """정수형 IP 주소를 문자열 형식으로 변환합니다."""
    return f"{(ip_int >> 24) & 255}.{(ip_int >> 16) & 255}.{(ip_int >> 8) & 255}.{ip_int & 255}"

def clean_host(host_str):
    """URL이나 도메인 문자열에서 실제 호스트 부분만 추출합니다."""
    if '://' in host_str:
        host_str = host_str.split('://', 1)[1]
    
    host_str = host_str.split(':', 1)[0]
    host_str = host_str.split('/', 1)[0]
    
    return host_str

def resolve_host(host_str):
    """도메인 이름 또는 IP 주소를 IP 주소로 변환합니다."""
    host_str = clean_host(host_str)
    
    try:
        parts = list(map(int, host_str.split('.')))
        if len(parts) == 4 and all(0 <= p <= 255 for p in parts):
            return host_str
        
        return socket.gethostbyname(host_str)
    except socket.gaierror:
        return None
    except (ValueError, IndexError):
        try:
            return socket.gethostbyname(host_str)
        except socket.gaierror:
            return None

def ip_str_to_int(ip_str):
    """문자열 IP 주소를 정수형으로 변환합니다. 잘못된 형식일 경우 None을 반환합니다."""
    try:
        resolved_ip = resolve_host(ip_str)
        if resolved_ip is None:
            return None
            
        parts = list(map(int, resolved_ip.split('.')))
        if len(parts) != 4 or not all(0 <= p <= 255 for p in parts):
            return None
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    except (ValueError, IndexError):
        return None

def worker(end_int, port_to_check):
    """IP 스캔 작업을 수행하는 스레드 함수입니다."""
    global scanned_count, found_ips_count, next_ip_to_scan
    batch_size = 10  # 한 번에 처리할 IP 주소 수

    while True:
        with next_ip_lock:
            current_ip_int = next_ip_to_scan
            next_ip_to_scan += batch_size
            if current_ip_int > end_int:
                break
            batch_end = min(current_ip_int + batch_size, end_int + 1)

        for ip_int in range(current_ip_int, batch_end):
            ip_address = int_to_ip_str(ip_int)
            is_found = check_ip(ip_address, port_to_check)

            with print_lock:
                scanned_count += 1
                if is_found:
                    found_ips_count += 1
                    print(f"\n[성공] {ip_address}:{port_to_check} (파일에 저장됨)")
                    save_found_ip(ip_address, port_to_check)

def run_range_scan(start_host_str, end_host_str, port, threads):
    """지정된 IP 범위에 대해 스캔을 실행합니다."""
    global next_ip_to_scan
    
    try:
        # 시작 호스트 주소 처리
        start_ip = resolve_host(start_host_str)
        if start_ip is None:
            raise ValueError(f"시작 호스트 주소를 IP로 변환할 수 없습니다: {start_host_str}")
        start_int = ip_str_to_int(start_ip)
        if start_int is None:
            raise ValueError(f"시작 IP 주소 형식이 잘못되었습니다: {start_ip}")

        # 종료 호스트 주소 처리
        end_ip = resolve_host(end_host_str)
        if end_ip is None:
            raise ValueError(f"종료 호스트 주소를 IP로 변환할 수 없습니다: {end_host_str}")
        end_int = ip_str_to_int(end_ip)
        if end_int is None:
            raise ValueError(f"종료 IP 주소 형식이 잘못되었습니다: {end_ip}")

        if start_int > end_int:
            raise ValueError(f"시작 IP({start_ip})가 종료 IP({end_ip})보다 클 수 없습니다.")

        total_ips = end_int - start_int + 1
        next_ip_to_scan = start_int

    except ValueError as e:
        print(f"[오류] {str(e)}")
        sys.exit(1)

    print("IP 범위 스캔을 시작합니다...")
    if start_host_str != start_ip:
        print(f"시작 지점: {start_host_str} ({start_ip})")
    else:
        print(f"시작 지점: {start_ip}")
        
    if end_host_str != end_ip:
        print(f"종료 지점: {end_host_str} ({end_ip})")
    else:
        print(f"종료 지점: {end_ip}")
    
    print(f"포트: {port}")
    print(f"스레드 수: {threads}")
    print(f"총 {total_ips:,}개의 IP를 스캔합니다.")
    print("-" * 30)

    thread_list = []
    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(end_int, port))
        thread.daemon = True
        thread.start()
        thread_list.append(thread)

    start_time = time.time()
    last_update = 0
    progress_bar_width = 30
    try:
        while scanned_count < total_ips:
            current_time = time.time()
            if current_time - last_update >= 0.5:  # 0.5초마다 업데이트
                last_update = current_time
                elapsed_time = current_time - start_time
                ips_per_sec = scanned_count / elapsed_time if elapsed_time > 0 else 0
                
                remaining_ips = total_ips - scanned_count
                if ips_per_sec > 0:
                    eta_seconds = remaining_ips / ips_per_sec
                    eta = str(datetime.timedelta(seconds=int(eta_seconds)))
                else:
                    eta = "계산 중"

                progress = (scanned_count / total_ips)
                filled_width = int(progress_bar_width * progress)
                bar = '█' * filled_width + '░' * (progress_bar_width - filled_width)
                
                # 메모리 사용량 계산
                process = psutil.Process()
                memory_usage = process.memory_info().rss / 1024 / 1024  # MB 단위

                sys.stdout.write(
                    f"\r{bar} {progress*100:6.2f}% | "
                    f"진행: {scanned_count:,}/{total_ips:,} | "
                    f"찾음: {found_ips_count} | "
                    f"속도: {ips_per_sec:,.0f} IP/s | "
                    f"남은 시간: {eta} | "
                    f"메모리: {memory_usage:.1f}MB   "
                )
                sys.stdout.flush()

            time.sleep(0.1)
            if not any(t.is_alive() for t in thread_list):
                break
    except KeyboardInterrupt:
        total_time = time.time() - start_time
        print("\n\n스캔이 중단되었습니다. (Ctrl+C)")
        print("\n[스캔 요약]")
        print("-" * 50)
        print(f"▶ 진행 상태: {scanned_count:,}/{total_ips:,} ({(scanned_count/total_ips*100):.1f}%)")
        print(f"▶ 찾은 IP: {found_ips_count:,}개")
        print(f"▶ 소요 시간: {datetime.timedelta(seconds=int(total_time))}")
        print(f"▶ 평균 속도: {scanned_count/total_time:,.0f} IP/s")
        print(f"▶ 결과 파일: {OUTPUT_FILE}")
        if found_ips_count > 0:
            print(f"\n마지막으로 발견된 IP들이 {OUTPUT_FILE}에 저장되었습니다.")
        print("-" * 50)
        sys.exit(0)

    total_time = time.time() - start_time
    print("\n\n[스캔 완료]")
    print("-" * 50)
    print(f"▶ 검사한 IP: {scanned_count:,}개")
    print(f"▶ 찾은 IP: {found_ips_count:,}개")
    print(f"▶ 소요 시간: {datetime.timedelta(seconds=int(total_time))}")
    print(f"▶ 평균 속도: {scanned_count/total_time:,.0f} IP/s")
    print(f"▶ 메모리 사용: {psutil.Process().memory_info().rss / 1024 / 1024:.1f}MB")
    print(f"▶ 결과 파일: {OUTPUT_FILE}")
    if found_ips_count > 0:
        print(f"\n발견된 모든 IP가 {OUTPUT_FILE}에 저장되었습니다.")
    print("-" * 50)

def get_ports_to_test(host, specified_port):
    original_host = host
    host = clean_host(host)
    
    if '://' in original_host:
        protocol = original_host.split('://', 1)[0].lower()
        return [COMMON_PORTS[protocol]] if protocol in COMMON_PORTS else [specified_port]
    
    if specified_port != DEFAULT_PORT:
        return [specified_port]
    
    ports = [COMMON_PORTS['http'], COMMON_PORTS['https']]
    if any(x in host.lower() for x in ('minecraft', 'mc')):
        ports.append(COMMON_PORTS['minecraft'])
    
    return ports

def run_single_test(host, port):
    print(f"호스트 테스트: {host}")
    if port == DEFAULT_PORT:
        print("포트를 지정하지 않아 자주 사용되는 포트들을 검사합니다...")
    print(f"타임아웃: {CONNECTION_TIMEOUT}초")
    print("-" * 30)
    
    resolved_ip = resolve_host(host)
    if resolved_ip is None or ip_str_to_int(resolved_ip) is None:
        print(f"[오류] 유효하지 않은 호스트 주소입니다: {host}")
        return
        
    print(f"호스트 주소: {host}")
    if host != resolved_ip:
        print(f"IP 주소: {resolved_ip}")
    print("-" * 30)
    
    ports_to_test = get_ports_to_test(host, port)
    found_any = False
    
    service_names = {port: name.upper() for name, port in COMMON_PORTS.items()}
    
    for test_port in ports_to_test:
        service_info = f" ({service_names[test_port]})" if test_port in service_names else ""
        
        if check_ip(resolved_ip, test_port):
            print(f"[성공] {host}:{test_port}{service_info}에 연결할 수 있습니다.")
            save_found_ip(resolved_ip, test_port)
            found_any = True
        else:
            print(f"[실패] {host}:{test_port}{service_info}에 연결할 수 없습니다.")
    
    if not found_any and len(ports_to_test) > 1:
        print("\n다른 포트 번호를 지정하여 다시 시도해보세요.")
        print("자주 사용되는 포트 번호:")
        for service, port in COMMON_PORTS.items():
            print(f"- {service.upper()}: {port}")
    
    print("-" * 30)

def main():
    # --- 사용법 안내 ---
    # 이 스크립트는 터미널(명령 프롬프트, PowerShell 등)에서 실행해야 합니다.
    # 
    # [기본 사용법]
    # python ip_scanner.py [모드] [옵션]
    #
    # [모드 1: IP 범위 스캔]
    # 특정 IP 범위를 스캔하여 열린 포트를 찾습니다.
    # 예시 1: 192.168.0.1 부터 192.168.0.255 까지 80 포트를 스캔
    #   python ip_scanner.py --start 192.168.0.1 --end 192.168.0.255 --port 80
    #
    # 예시 2: 10.0.0.0 부터 10.0.255.255 까지 기본 포트(80)로 스캔
    #   python ip_scanner.py --start 10.0.0.0 --end 10.0.255.255
    #
    # [모드 2: 특정 IP 테스트]
    # 하나의 IP 주소와 포트만 간단하게 테스트합니다.
    # 예시: 8.8.8.8 IP의 53번 포트가 열려있는지 확인
    #   python ip_scanner.py --test 8.8.8.8 --port 53
    #
    #
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
    elif args.start or args.end:
        print("[오류] IP 범위 스캔을 위해서는 --start와 --end를 모두 지정해야 합니다.")
        parser.print_help()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
