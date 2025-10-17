from pathlib import Path
import logging
import time
import paramiko
from conf import ssh1, ssh2, ssh3


def _run_version_command_via_client(client: paramiko.SSHClient) -> str:
    """Открывает интерактивную оболочку, определяет промпт и выполняет show/display version."""
    chan = client.invoke_shell()
    output = ""
    end = time.time() + 2.0
    while time.time() < end:
        if chan.recv_ready():
            output += chan.recv(4096).decode('utf-8', errors='ignore')
        else:
            time.sleep(0.1)

    last_line = "".join(output.splitlines()[-1:])
    if '#' in last_line:
        cmd = 'show version\n'
    elif '>' in last_line:
        cmd = 'display version\n'
    else:
        cmd = 'show version\n'

    chan.send(cmd)
    cmd_output = ""
    end = time.time() + 4.0
    while time.time() < end:
        if chan.recv_ready():
            cmd_output += chan.recv(4096).decode('utf-8', errors='ignore')
        else:
            time.sleep(0.1)
    try:
        chan.close()
    except Exception:
        pass
    return cmd_output


def _run_version_command_via_transport(transport: paramiko.Transport) -> str:
    """Аналогично client, но через transport с интерактивной оболочкой."""
    chan = transport.open_session(timeout=10)
    try:
        chan.get_pty()
    except Exception:
        pass
    chan.invoke_shell()

    output = ""
    end = time.time() + 2.0
    while time.time() < end:
        if chan.recv_ready():
            output += chan.recv(4096).decode('utf-8', errors='ignore')
        else:
            time.sleep(0.1)

    last_line = "".join(output.splitlines()[-1:])
    if '#' in last_line:
        cmd = 'show version\n'
    elif '>' in last_line:
        cmd = 'display version\n'
    else:
        cmd = 'show version\n'

    chan.send(cmd)
    cmd_output = ""
    end = time.time() + 4.0
    while time.time() < end:
        if chan.recv_ready():
            cmd_output += chan.recv(4096).decode('utf-8', errors='ignore')
        else:
            time.sleep(0.1)
    try:
        chan.close()
    except Exception:
        pass
    return cmd_output


def configure_snmp_on_device(host: str, credentials: list[list[str]], logger: logging.Logger) -> tuple[bool, str, str]:
    """Подключается по SSH и настраивает SNMP в зависимости от вендора (Huawei/SNR).
    Возвращает (success, vendor, output). Все шаги логирует через logger."""
    for cred in credentials:
        username, password = cred[0], cred[1]
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            logger.info(f"{host} | SSH connect try as {username}")
            client.connect(
                hostname=host,
                username=username,
                password=password,
                port=22,
                timeout=10,
                auth_timeout=12,
                banner_timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )

            chan = client.invoke_shell()
            # Собираем первичный промпт
            buf = ""
            end = time.time() + 3.0
            while time.time() < end:
                if chan.recv_ready():
                    buf += chan.recv(4096).decode('utf-8', errors='ignore')
                else:
                    time.sleep(0.1)

            last_line = "".join(buf.splitlines()[-1:])
            vendor = 'Huawei' if '>' in last_line else ('SNR' if '#' in last_line else 'Unknown')
            logger.info(f"{host} | Detected vendor by prompt: {vendor} ({last_line})")

            def send(cmd: str, wait_sec: float = 0.6) -> str:
                chan.send(cmd + ('\n' if not cmd.endswith('\n') else ''))
                out = ""
                end_local = time.time() + max(wait_sec, 0.4)
                while time.time() < end_local:
                    if chan.recv_ready():
                        out += chan.recv(4096).decode('utf-8', errors='ignore')
                    else:
                        time.sleep(0.1)
                return out

            full_output = buf
            if vendor == 'Huawei':
                full_output += send('sys')
                full_output += send('snmp-agent')
                full_output += send('snmp-agent sys-info version v2c')
                full_output += send('snmp community read rline6139')
                full_output += send('quit')
                full_output += send('save', 1.0)
                full_output += send('y', 1.0)
                full_output += send('', 1.0)  # доп. Enter
            elif vendor == 'SNR':
                full_output += send('conf t')
                full_output += send('snmp-server securityip disable')
                full_output += send('exit')
                full_output += send('write', 1.0)
                full_output += send('y', 1.0)
                full_output += send('', 1.0)  # доп. Enter
            else:
                logger.warning(f"{host} | Unknown prompt, cannot determine vendor")

            try:
                chan.close()
            except Exception:
                pass
            try:
                client.close()
            except Exception:
                pass

            logger.info(f"{host} | Config output begin\n{full_output}\n{host} | Config output end")
            return True, vendor, full_output
        except paramiko.ssh_exception.AuthenticationException:
            logger.info(f"{host} | Auth failed for {username}")
            try:
                client.close()
            except Exception:
                pass
            continue
        except (paramiko.SSHException, OSError) as e:
            logger.error(f"{host} | SSH error for {username}: {e}")
            try:
                client.close()
            except Exception:
                pass
            continue

    return False, 'Unknown', ''


def ssh_connect(hostname, username, password):
    """Пробует подключиться по SSH. Возвращает (успех: bool, stdout: str)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=hostname,
            username=username,
            password=password,
            port=22,
            timeout=15,
            auth_timeout=20,
            banner_timeout=20,
            allow_agent=False,
            look_for_keys=False,
        )
        # При успехе определяем промпт и выполняем соответствующую команду
        try:
            out = _run_version_command_via_client(client)
        except Exception:
            out = ''
        return True, out
    except paramiko.ssh_exception.AuthenticationException:
        # Фоллбек: keyboard-interactive (если разрешён)
        try:
            transport = paramiko.Transport((hostname, 22))
            transport.start_client(timeout=20)

            def kbd_handler(title, instructions, prompts):
                return [password for _prompt, _echo in prompts]

            try:
                transport.auth_interactive(username, kbd_handler, submethods='')
                if transport.is_authenticated():
                    try:
                        out = _run_version_command_via_transport(transport)
                    except Exception:
                        out = ''
                    try:
                        transport.close()
                    except Exception:
                        pass
                    return True, out
            except paramiko.SSHException:
                pass

            # Фоллбек: попытка с ключами/ssh-agent
            try:
                pkey = None
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    hostname=hostname,
                    username=username,
                    port=22,
                    timeout=15,
                    auth_timeout=20,
                    banner_timeout=20,
                    allow_agent=True,
                    look_for_keys=True,
                )
                try:
                    out = _run_version_command_via_client(client)
                except Exception:
                    out = ''
                client.close()
                return True, out
            except Exception:
                return False, ''
            finally:
                try:
                    transport.close()
                except Exception:
                    pass
        except Exception:
            return False, ''
    except (paramiko.SSHException, OSError):
        return False, ''
    finally:
        try:
            client.close()
        except Exception:
            pass


if __name__ == "__main__":
    ip = ["192.168.1.10"]

    # Логирование Paramiko в файл
    project_dir = Path(__file__).resolve().parent
    log_file = project_dir / 'output.log'
    logging.getLogger("paramiko").setLevel(logging.DEBUG)
    paramiko.util.log_to_file(str(log_file))

    credentials = [ssh1, ssh2, ssh3]

    for host in ip:
        connected = False
        for cred in credentials:
            username, password = cred[0], cred[1]
            success, stdout_text = ssh_connect(host, username, password)
            if success:
                print(f"Connected to {host} as {username}")
                if stdout_text:
                    print(stdout_text.strip())
                connected = True
                break
        if not connected:
            print(f"Failed to connect to {host} with provided credentials")
