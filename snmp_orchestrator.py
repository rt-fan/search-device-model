from pathlib import Path
import logging
import subprocess
import socket
from typing import Iterable
import platform

from ssh_connect import configure_snmp_on_device
from conf import ssh1, ssh2, ssh3
from main import get_sysobjectid


def iter_ips(ips_path: Path) -> Iterable[str]:
    with ips_path.open('r', encoding='utf-8') as f:
        for line in f:
            ip = line.strip()
            if ip:
                yield ip


def ping_host(ip: str, count: int = 1, timeout_s: int = 1) -> bool:
    system = platform.system().lower()
    try:
        if 'windows' in system:
            cmd = ['ping', '-n', str(count), '-w', str(int(timeout_s * 1000)), ip]
        elif 'darwin' in system:
            cmd = ['ping', '-c', str(count), '-W', str(int(timeout_s * 1000)), ip]
        else:
            cmd = ['ping', '-c', str(count), '-W', str(int(timeout_s)), ip]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s + 2
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        return False


def is_port_open(ip: str, port: int, timeout_s: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def main() -> None:
    project_dir = Path(__file__).resolve().parent
    ips_file = project_dir / 'ips.txt'
    log_file = project_dir / 'log.txt'

    # Логирование общего процесса
    logger = logging.getLogger('snmp_orchestrator')
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(log_file, encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    if logger.handlers:
        logger.handlers.clear()
    logger.addHandler(handler)

    credentials = [ssh1, ssh2, ssh3]

    for ip in iter_ips(ips_file):
        logger.info(f"{ip} | Start")

        # Ping
        if not ping_host(ip):
            logger.info(f"{ip} | Ping failed")
            continue
        logger.info(f"{ip} | Ping ok")

        # SNMP sysObjectID (до конфигурирования)
        sysobj = get_sysobjectid(ip)
        logger.info(f"{ip} | sysObjectID before: {sysobj}")
        if sysobj and sysobj != 'Unknown':
            logger.info(f"{ip} | SNMP already active, skip SSH config")
            continue

        # SSH: попытаться сконфигурировать SNMP (только если открыт TCP/22)
        if not is_port_open(ip, 22, 3.0):
            logger.info(f"{ip} | TCP port 22 closed, skip SSH config")
            continue
        ok, vendor, out = configure_snmp_on_device(ip, credentials, logger)
        if not ok:
            logger.info(f"{ip} | SSH configure failed")
            continue
        logger.info(f"{ip} | SSH configured for vendor {vendor}")

        # SNMP sysObjectID (после конфигурирования)
        sysobj_after = get_sysobjectid(ip)
        logger.info(f"{ip} | sysObjectID after: {sysobj_after}")

    logger.info("Run finished")


if __name__ == '__main__':
    main()
