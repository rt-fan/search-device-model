from pathlib import Path
import argparse
import logging
import platform
import re
import subprocess
import xml.etree.ElementTree as ET
import time
from conf import snmp_community


def get_sysobjectid(ip_address: str) -> str:
    """Получить sysObjectID для указанного IP (v2c). Сначала через pysnmp, затем резервно через snmpget."""
    oid = '1.3.6.1.2.1.1.2.0'  # sysObjectID
    communities = snmp_community

    # Попытка через pysnmp (кроссплатформенно, не требует net-snmp)
    try:
        from pysnmp.hlapi import (
            SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
            ObjectType, ObjectIdentity, getCmd
        )
        for community in communities:
            try:
                iterator = getCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=1),  # v2c
                    UdpTransportTarget((ip_address, 161), timeout=2, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
                errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
                if errorIndication or errorStatus:
                    continue
                if varBinds:
                    value = str(varBinds[0][1]).strip()
                    if value:
                        return value
            except Exception:
                continue
    except Exception:
        # pysnmp не установлен/не работает — пойдём в резерв
        pass

    # Резерв: системная утилита snmpget (актуально на Linux/macOS при установленном net-snmp)
    for community in communities:
        try:
            result = subprocess.run(
                ['snmpget', '-v', '2c', '-c', community, '-t', '2', '-r', '1', ip_address, oid],
                capture_output=True, text=True, timeout=4
            )
            if result.returncode == 0 and result.stdout:
                output = result.stdout.strip()
                if '=' in output:
                    return output.split('=', 1)[1].strip()
                return output
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            continue

    return 'Unknown'


def ping_host(ip_address: str, count: int = 1, timeout_sec: int = 1) -> bool:
    """Кросс‑платформенный ping: Windows/macOS/Linux (1 пакет, настраиваемый тайм‑аут)."""
    system = platform.system().lower()
    try:
        if 'windows' in system:
            cmd = ['ping', '-n', str(count), '-w', str(int(timeout_sec * 1000)), ip_address]
        elif 'darwin' in system:
            # macOS: -W в миллисекундах
            cmd = ['ping', '-c', str(count), '-W', str(int(timeout_sec * 1000)), ip_address]
        else:
            # Linux/Unix: -W в секундах
            cmd = ['ping', '-c', str(count), '-W', str(int(timeout_sec)), ip_address]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec + 2
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        return False


def parse_and_print_devices(xml_path: Path) -> None:
    """Разобрать devices из XML, печатать и писать в devices_list.txt (sysObjectID/NO_PING/NO_SNMP)."""
    project_dir = Path(__file__).resolve().parent
    devices_file = project_dir / 'devices_list.txt'
    # Очистим файл перед записью
    with devices_file.open('w', encoding='utf-8'):
        pass
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for device_element in root.findall('.//Device'):
            display_name = (device_element.findtext('DisplayName') or '').strip()
            host_name = (device_element.findtext('HostName') or '').strip()
            ip_address = (device_element.findtext('IPAddress') or '').strip()

            if not (display_name or host_name or ip_address):
                continue

            if ip_address:
                if not ping_host(ip_address):
                    status = 'NO_PING'
                else:
                    sys_object_id = get_sysobjectid(ip_address)
                    status = sys_object_id if sys_object_id != 'Unknown' else 'NO_SNMP'
            else:
                status = 'Unknown'
            with devices_file.open('a', encoding='utf-8') as df:
                df.write(f"{display_name} % {host_name} % {ip_address} % {status}\n")
            print(f"{display_name} - {host_name} - {ip_address} - {status}")
        return
    except ET.ParseError:
        pass  # Fall back to tolerant text scan below

    # Fallback: tolerant line-by-line scan for <Device> blocks
    tag_patterns = {
        'DisplayName': re.compile(r"<DisplayName>\s*(.*?)\s*</DisplayName>")
    ,   'HostName': re.compile(r"<HostName>\s*(.*?)\s*</HostName>")
    ,   'IPAddress': re.compile(r"<IPAddress>\s*(.*?)\s*</IPAddress>")
    }

    inside_device = False
    current_block_lines: list[str] = []

    with xml_path.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if not inside_device and '<Device' in line:
                inside_device = True
                current_block_lines = [line]
                continue

            if inside_device:
                current_block_lines.append(line)
                if '</Device>' in line:
                    block_text = ''.join(current_block_lines)
                    values: dict[str, str] = {}
                    for tag, pattern in tag_patterns.items():
                        match = pattern.search(block_text)
                        values[tag] = match.group(1).strip() if match else ''

                    if any(values.values()):
                        ip_addr = values['IPAddress']
                        if ip_addr:
                            if not ping_host(ip_addr):
                                status = 'NO_PING'
                            else:
                                sys_object_id = get_sysobjectid(ip_addr)
                                status = sys_object_id if sys_object_id != 'Unknown' else 'NO_SNMP'
                        else:
                            status = 'Unknown'
                        with devices_file.open('a', encoding='utf-8') as df:
                            df.write(f"{values['DisplayName']} % {values['HostName']} % {values['IPAddress']} % {status}\n")
                        print(f"{values['DisplayName']} - {values['HostName']} - {values['IPAddress']} - {status}")

                    inside_device = False
                    current_block_lines = []


def extract_ips_from_xml(xml_path: Path) -> list[str]:
    """Извлечь список IP из тегов <IPAddress> файла resp.xml (уникальные, в порядке встречаемости)."""
    ips: list[str] = []
    seen: set[str] = set()
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for device_element in root.findall('.//Device'):
            ip_address = (device_element.findtext('IPAddress') or '').strip()
            if ip_address and ip_address not in seen:
                seen.add(ip_address)
                ips.append(ip_address)
        return ips
    except ET.ParseError:
        pattern = re.compile(r"<IPAddress>\s*(.*?)\s*</IPAddress>")
        with xml_path.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                m = pattern.search(line)
                if not m:
                    continue
                ip = m.group(1).strip()
                if ip and ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
        return ips


def setup_logger(project_dir: Path) -> logging.Logger:
    logger = logging.getLogger('devices_model')
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(project_dir / 'log.txt', encoding='utf-8')
        fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


def scan_ips_with_snmp_and_optional_ssh(ips: list[str], mode: str, logger: logging.Logger) -> None:
    """Для каждого IP: ping -> SNMP sysObjectID; при режиме with-ssh пытаемся включить SNMP по SSH и повторяем SNMP."""
    if not ips:
        print("Список IP пуст")
        return

    use_ssh = (mode == 'with-ssh')
    credentials: list[list[str]] | None = None
    configure_snmp_on_device = None  # late bind
    if use_ssh:
        try:
            from conf import ssh1, ssh2, ssh3
            from ssh_connect import configure_snmp_on_device as _cfg
            configure_snmp_on_device = _cfg
            credentials = [ssh1, ssh2, ssh3]
        except Exception as e:
            logger.error(f"Не удалось загрузить креды/функцию SSH: {e}")
            print("Ошибка загрузки SSH-зависимостей, продолжаю без SSH")
            use_ssh = False

    for ip in ips:
        reachable = ping_host(ip)
        print(f"{ip}: ping={'ok' if reachable else 'fail'}")
        if not reachable:
            continue

        soid = get_sysobjectid(ip)
        if soid != 'Unknown':
            print(f"{ip}: sysObjectID={soid}")
            continue

        if use_ssh and configure_snmp_on_device and credentials:
            ok, vendor, out = configure_snmp_on_device(ip, credentials, logger)
            logger.info(f"{ip} | enable SNMP via SSH: success={ok}, vendor={vendor}")
            # Небольшая пауза и повторная попытка SNMP
            time.sleep(1.0)
            soid2 = get_sysobjectid(ip)
            if soid2 != 'Unknown':
                print(f"{ip}: SNMP включён ({vendor}), sysObjectID={soid2}")
            else:
                print(f"{ip}: SNMP не отвечает после SSH-настройки ({vendor})")
        else:
            print(f"{ip}: SNMP недоступен")


def main() -> None:
    project_dir = Path(__file__).resolve().parent

    parser = argparse.ArgumentParser(description='Пинг и SNMP-запросы для списка IP-адресов')
    parser.add_argument('--mode', choices=['basic', 'with-ssh'], default='basic',
                        help='basic: только пинг и SNMP; with-ssh: также попытаться включить SNMP по SSH')
    parser.add_argument('--ips', type=str, default=str(project_dir / 'resp.xml'),
                        help='Путь к файлу resp.xml (для извлечения IP)')
    parser.add_argument('--skip-xml', action='store_true',
                        help='Не выполнять разбор resp.xml')
    args = parser.parse_args()

    logger = setup_logger(project_dir)

    if not args.skip_xml:
        xml_file = Path(args.ips)
        parse_and_print_devices(xml_file)
        print("\n" + "="*50)

    # Если выбран with-ssh — берём IP напрямую из resp.xml и выполняем сканирование
    if args.mode == 'with-ssh':
        xml_for_ips = Path(args.ips)
        ips = extract_ips_from_xml(xml_for_ips)
        if ips:
            print(', '.join(ips))
            print("\n" + "-"*32 + " scan " + "-"*32)
            scan_ips_with_snmp_and_optional_ssh(ips, args.mode, logger)
        else:
            print("IP-адреса в resp.xml не найдены")


if __name__ == "__main__":
    main()
