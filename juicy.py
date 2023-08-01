# -*- coding: utf-8 -*-
# Time       : 2023/6/26 11:05
# Author     : QIN2DIM
# Github     : https://github.com/QIN2DIM
# Description:
from __future__ import annotations

import argparse
import getpass
import inspect
import json
import logging
import os
import random
import secrets
import shutil
import socket
import subprocess
import sys
import time
import zipfile
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Literal, List, NoReturn, Union, Tuple
from urllib import request
from urllib.request import urlretrieve
from uuid import uuid4

logging.basicConfig(
    level=logging.INFO, stream=sys.stdout, format="%(asctime)s - %(levelname)s - %(message)s"
)

if not sys.platform.startswith("linux"):
    logging.error(" Opps~ 你只能在 Linux 操作系统上运行该脚本")
    sys.exit()
if getpass.getuser() != "root":
    logging.error(" Opps~ 你需要手动切换到 root 用户运行该脚本")
    sys.exit()

URL = "https://github.com/juicity/juicity/releases/download/v0.1.0/juicity-linux-x86_64.zip"

TEMPLATE_SERVICE = """
[Unit]
Description=juicity-server Service
Documentation=https://github.com/juicity/juicity
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
ExecStart={exec_start}
Restart=on-failure
LimitNPROC=512
LimitNOFILE=infinity
WorkingDirectory={working_directory}

[Install]
WantedBy=multi-user.target
"""


@dataclass
class Project:
    workstation = Path("/home/juicity")
    juicity_executable = workstation.joinpath("juicity-server")
    server_config = workstation.joinpath("server.json")

    client_nekoray_config = workstation.joinpath("nekoray_config.json")

    juicity_service = Path("/etc/systemd/system/juicity.service")

    # 设置别名
    root = Path(os.path.expanduser("~"))
    path_bash_aliases = root.joinpath(".bash_aliases")
    _remote_command = "python3 <(curl -fsSL https://ros.services/juicy.py)"
    _alias = "juicy"

    _server_ip = ""
    _server_port = -1

    def __post_init__(self):
        os.makedirs(self.workstation, exist_ok=True)

    @staticmethod
    def is_port_in_used(_port: int, proto: Literal["tcp", "udp"]) -> bool | None:
        """Check socket UDP/data_gram or TCP/data_stream"""
        proto2type = {"tcp": socket.SOCK_STREAM, "udp": socket.SOCK_DGRAM}
        socket_type = proto2type[proto]
        with suppress(socket.error), socket.socket(socket.AF_INET, socket_type) as s:
            s.bind(("127.0.0.1", _port))
            return False
        return True

    @property
    def server_ip(self):
        return self._server_ip

    @server_ip.setter
    def server_ip(self, ip: str):
        self._server_ip = ip

    @property
    def server_port(self):
        # 初始化监听端口
        if self._server_port < 0:
            rand_ports = list(range(41670, 46990))
            random.shuffle(rand_ports)
            for p in rand_ports:
                if not self.is_port_in_used(p, proto="udp"):
                    self._server_port = p
                    logging.info(f"正在初始化监听端口 - port={p}")
                    break

        # 返回已绑定的空闲端口
        return self._server_port

    @property
    def alias(self):
        # redirect to https://raw.githubusercontent.com/QIN2DIM/juicity-installer/main/juicy.py
        return f"alias {self._alias}='{self._remote_command}'"

    def set_alias(self):
        with open(self.path_bash_aliases, "a", encoding="utf8") as file:
            file.write(f"\n{self.alias}\n")
        logging.info(f"✅ 现在你可以通过别名唤起脚本 - alias={self._alias}")

    def remove_alias(self):
        text = self.path_bash_aliases.read_text(encoding="utf8")
        for ck in [f"\n{self.alias}\n", f"\n{self.alias}", f"{self.alias}\n", self.alias]:
            text = text.replace(ck, "")
        self.path_bash_aliases.write_text(text, encoding="utf8")

    @staticmethod
    def reset_shell() -> NoReturn:
        # Reload Linux SHELL and refresh alias values
        os.execl(os.environ["SHELL"], "bash", "-l")


@dataclass
class Certificate:
    domain: str

    @property
    def fullchain(self):
        return f"/etc/letsencrypt/live/{self.domain}/fullchain.pem"

    @property
    def privkey(self):
        return f"/etc/letsencrypt/live/{self.domain}/privkey.pem"


class CertBot:
    def __init__(self, domain: str):
        self._domain = domain

    def run(self):
        p = Path("/etc/letsencrypt/live/")
        if p.exists():
            logging.info("移除證書殘影...")
            for k in os.listdir(p):
                k_full = p.joinpath(k)
                if (
                    not p.joinpath(self._domain).exists()
                    and k.startswith(f"{self._domain}-")
                    and k_full.is_dir()
                ):
                    shutil.rmtree(k_full, ignore_errors=True)

        logging.info("正在为解析到本机的域名申请免费证书")

        logging.info("正在更新包索引")
        os.system("apt update -y > /dev/null 2>&1 ")

        logging.info("安装 certbot")
        os.system("apt install certbot -y > /dev/null 2>&1")

        logging.info("检查 80 端口占用")
        if Project.is_port_in_used(80, proto="tcp"):
            # 执行温和清理
            os.system("systemctl stop nginx > /dev/null 2>&1 && nginx -s stop > /dev/null 2>&1")
            os.system("kill $(lsof -t -i:80)  > /dev/null 2>&1")

        logging.info("开始申请证书")
        cmd = (
            "certbot certonly "
            "--standalone "
            "--register-unsafely-without-email "
            "--agree-tos "
            "-d {domain}"
        )
        p = subprocess.Popen(
            cmd.format(domain=self._domain).split(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            text=True,
        )
        output = p.stderr.read().strip()
        if output and "168 hours" in output:
            logging.warning(
                """
                一个域名每168小时只能申请5次免费证书，
                你可以为当前主机创建一条新的域名A纪录来解决这个问题。
                在解决这个问题之前你没有必要进入到后续的安装步骤。
                """
            )
            sys.exit()

    def remove(self):
        """可能存在重复申请的 domain-0001"""
        logging.info("移除可能残留的证书文件")
        p = subprocess.Popen(
            f"certbot delete --cert-name {self._domain}".split(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        p.stdin.write("y\n")
        p.stdin.flush()

        # 兜底
        shutil.rmtree(Path(Certificate(self._domain).fullchain).parent, ignore_errors=True)


@dataclass
class JuicityService:
    path: Path
    name: str = "juicity"

    @classmethod
    def build_from_template(cls, path: Path, template: str | None = ""):
        if template:
            path.write_text(template, encoding="utf8")
            os.system("systemctl daemon-reload")
        return cls(path=path)

    def download_juicity_server(self, workstation: Path):
        """下载的是 .zip 文件"""
        zip_path = workstation.joinpath(URL.split("/")[-1])
        ex_path = workstation.joinpath("juicity-server")

        try:
            urlretrieve(URL, f"{zip_path}")
            logging.info(f"下载完毕 - zip_path={zip_path}")
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(workstation)
        except OSError:
            logging.info("服务正忙，尝试停止任务...")
            self.stop()
            time.sleep(0.5)
            return self.download_juicity_server(workstation)
        else:
            os.system(f"chmod +x {ex_path}")
            logging.info(f"授予执行权限 - ex_path={ex_path}")

    def start(self):
        """部署服务之前需要先初始化服务端配置并将其写到工作空间"""
        os.system(f"systemctl enable --now {self.name}")
        logging.info("系统服务已启动")
        logging.info("已设置服务开机自启")

    def stop(self):
        logging.info("停止系统服务")
        os.system(f"systemctl stop {self.name}")

    def restart(self):
        logging.info("重启系统服务")
        os.system(f"systemctl daemon-reload && systemctl restart {self.name}")

    def status(self) -> Tuple[bool, str]:
        result = subprocess.run(
            f"systemctl is-active {self.name}".split(), capture_output=True, text=True
        )
        text = result.stdout.strip()
        response = None
        if text == "inactive":
            text = "\033[91m" + text + "\033[0m"
        elif text == "active":
            text = "\033[32m" + text + "\033[0m"
            response = True
        return response, text

    def remove(self, workstation: Path):
        logging.info("注销系统服务")
        os.system(f"systemctl disable --now {self.name} > /dev/null 2>&1")

        logging.info("关停相关进程")
        os.system("pkill juicity-server")

        logging.info("移除系统服务配置文件")
        if self.path.exists():
            os.remove(self.path)

        logging.info("移除工作空间")
        shutil.rmtree(workstation)


# =================================== Runtime Settings ===================================


def from_dict_to_cls(cls, data):
    return cls(
        **{
            key: (data[key] if val.default == val.empty else data.get(key, val.default))
            for key, val in inspect.signature(cls).parameters.items()
        }
    )


@dataclass
class User:
    username: str
    password: str

    @classmethod
    def gen(cls):
        return cls(username=str(uuid4()), password=secrets.token_hex()[:16])


@dataclass
class ServerConfig:
    """
    Config template of juicity-server
    https://github.com/juicity/juicity/blob/main/cmd/server/README.md
    """

    listen: str | int
    certificate: str
    private_key: str
    users: Dict[str, str] = field(default_factory=dict)
    congestion_control: Literal["bbr", "cubic", "new_reno"] = "bbr"
    log_level: str = "info"

    def __post_init__(self):
        self.users = self.users or {}

        if isinstance(self.listen, int):
            self.listen = str(self.listen)
        if not self.listen.startswith(":"):
            self.listen = f":{self.listen}"

    @classmethod
    def from_automation(
        cls, users: List[User] | User, path_fullchain: str, path_privkey: str, server_port: int
    ):
        if not isinstance(users, list):
            users = [users]
        users = {user.username: user.password for user in users}
        return cls(
            listen=server_port, certificate=path_fullchain, private_key=path_privkey, users=users
        )

    def to_json(self, sp: Path):
        sp.write_text(json.dumps(self.__dict__, indent=4, ensure_ascii=True))
        logging.info(f"保存服务端配置文件 - save_path={sp}")


@dataclass
class NekoRayConfig:
    """
    https://github.com/juicity/juicity/tree/main/cmd/client
    Config template of juicity-client
    Apply on the NekoRay(v3.8+)
    """

    server: str
    listen: str
    uuid: str
    password: str
    sni: str | None = None
    allow_insecure: bool = False
    congestion_control: Literal["bbr", "cubic", "new_reno"] = "bbr"
    log_level: str = "info"

    @classmethod
    def from_server(
        cls,
        user: User,
        server_config: ServerConfig,
        server_addr: str,
        server_port: int,
        server_ip: str,
    ):
        return cls(
            server=f"{server_ip}:{server_port}",
            listen="127.0.0.1:%socks_port%",
            uuid=user.username,
            password=user.password,
            sni=server_addr,
            congestion_control=server_config.congestion_control,
        )

    @classmethod
    def from_json(cls, sp: Path):
        data = json.loads(sp.read_text(encoding="utf8"))
        return from_dict_to_cls(cls, data)

    def to_json(self, sp: Path):
        sp.write_text(json.dumps(self.__dict__, indent=4, ensure_ascii=True))

    @property
    def showcase(self) -> str:
        return json.dumps(self.__dict__, indent=4, ensure_ascii=True)

    @property
    def sharelink(self) -> str:
        sl = (
            f"juicity://{self.uuid}:{self.password}@{self.server}"
            f"?congestion_control={self.congestion_control}"
            f"&allow_insecure={int(self.allow_insecure)}"
        )
        if self.sni:
            sl += f"&sni={self.sni}"
        return sl

    @property
    def serv_peer(self) -> Tuple[str, str]:
        serv_addr, serv_port = self.server.split(":")
        return serv_addr, serv_port


# =================================== DataModel ===================================


TEMPLATE_PRINT_NEKORAY = """
\033[36m--> NekoRay 自定义核心配置\033[0m
# 名称：(custom)
# 地址：{server_addr}
# 端口：{listen_port}
# 命令：run -c %config%
# 核心：juicity

{nekoray_config}
"""

TEMPLATE_PRINT_SHARELINK = """
\033[36m--> Juicity 通用订阅\033[0m
\033[34m{sharelink}\033[0m
"""


class Template:
    @staticmethod
    def print_nekoray(nekoray: NekoRayConfig):
        serv_addr, serv_port = nekoray.serv_peer
        print(TEMPLATE_PRINT_SHARELINK.format(sharelink=nekoray.sharelink))
        print(
            TEMPLATE_PRINT_NEKORAY.format(
                server_addr=serv_addr, listen_port=serv_port, nekoray_config=nekoray.showcase
            )
        )


def gen_clients(server_addr: str, user: User, server_config: ServerConfig, project: Project):
    """
    client: Literal["NekoRay", "v2rayN", "Meta"]

    :param server_addr:
    :param user:
    :param server_config:
    :param project:
    :return:
    """
    logging.info("正在生成客户端配置文件")

    # 生成客户端通用实例
    server_ip, server_port = project.server_ip, project.server_port

    # 生成 NekoRay 客户端配置实例
    # https://matsuridayo.github.io/n-extra_core/
    nekoray = NekoRayConfig.from_server(user, server_config, server_addr, server_port, server_ip)
    nekoray.to_json(project.client_nekoray_config)
    Template.print_nekoray(nekoray)


def _validate_domain(domain: str | None) -> Union[NoReturn, Tuple[str, str]]:
    """

    :param domain:
    :return: Tuple[domain, server_ip]
    """
    if not domain:
        domain = input("> 解析到本机的域名：")

    try:
        server_ip = socket.getaddrinfo(domain, None)[-1][4][0]
    except socket.gaierror:
        logging.error(f"域名不可达或拼写错误的域名 - {domain=}")
    else:
        my_ip = request.urlopen("http://ifconfig.me/ip").read().decode("utf8")
        if my_ip != server_ip:
            logging.error(f"你的主机外网IP与域名解析到的IP不一致 - {my_ip=} {domain=} {server_ip=}")
        else:
            return domain, server_ip

    # 域名解析错误，应当阻止用户执行安装脚本
    sys.exit()


def recv_stream(script: str, pipe: Literal["stdout", "stderr"] = "stdout") -> str:
    p = subprocess.Popen(
        script.split(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        text=True,
    )
    if pipe == "stdout":
        return p.stdout.read().strip()
    if pipe == "stderr":
        return p.stderr.read().strip()


class Scaffold:
    @staticmethod
    def install(params: argparse.Namespace):
        """
        1. 运行 certbot 申请证书
        3. 初始化 Project 环境对象
        4. 初始化 server config
        5. 初始化 client config
        6. 生成 nekoray juicity config 配置信息
        :param params:
        :return:
        """
        (domain, server_ip) = _validate_domain(params.domain)
        logging.info(f"域名解析成功 - {domain=}")

        # 初始化证书对象
        cert = Certificate(domain)

        # 为绑定到本机的域名申请证书
        if not Path(cert.fullchain).exists():
            CertBot(domain).run()
        else:
            logging.info(f"证书文件已存在 - path={Path(cert.fullchain).parent}")

        # 初始化 workstation
        project = Project()
        # 设置脚本别名
        project.set_alias()

        user = User.gen()
        server_port = project.server_port

        # 初始化系统服务配置
        project.server_ip = server_ip
        template = TEMPLATE_SERVICE.format(
            exec_start=f"{project.juicity_executable} run -c {project.server_config}",
            working_directory=f"{project.workstation}",
        )
        juicity = JuicityService.build_from_template(
            path=project.juicity_service, template=template
        )

        logging.info(f"正在下载 juicity-server")
        juicity.download_juicity_server(project.workstation)

        logging.info("正在生成默认的服务端配置")
        server_config = ServerConfig.from_automation(
            user, cert.fullchain, cert.privkey, server_port
        )
        server_config.to_json(project.server_config)

        logging.info("正在部署系统服务")
        juicity.start()

        logging.info("正在检查服务状态")
        (response, text) = juicity.status()

        # 在控制台输出客户端配置
        if response is True:
            gen_clients(domain, user, server_config, project)
            project.reset_shell()
        else:
            logging.info(f"服务启动失败 - status={text}")

    @staticmethod
    def remove(params: argparse.Namespace):
        (domain, _) = _validate_domain(params.domain)
        logging.info(f"解绑服务 - bind={domain}")

        project = Project()

        # 移除脚本别名
        project.remove_alias()

        # 移除可能残留的证书文件
        CertBot(domain).remove()

        # 关停进程，注销系统服务，移除工作空间
        service = JuicityService.build_from_template(project.juicity_service)
        service.remove(project.workstation)

        project.reset_shell()

    @staticmethod
    def check(params: argparse.Namespace):
        def print_nekoray():
            if not project.client_nekoray_config.exists():
                logging.error(f"❌ 客户端配置文件不存在 - path={project.client_nekoray_config}")
            else:
                nekoray = NekoRayConfig.from_json(project.client_nekoray_config)
                Template.print_nekoray(nekoray)

        project = Project()

        show_all = not any([params.clash, params.nekoray, params.v2ray])
        if show_all:
            print_nekoray()
        elif params.nekoray:
            print_nekoray()
        elif params.clash:
            logging.warning("Unimplemented feature")
        elif params.v2ray:
            logging.warning("Unimplemented feature")

    @staticmethod
    def service_relay(cmd: str):
        project = Project()
        juicity = JuicityService.build_from_template(path=project.juicity_service)

        if cmd == "status":
            active = recv_stream(f"systemctl is-active {juicity.name}")
            logging.info(f"status - {active}")
            version = recv_stream(f"{project.juicity_executable} -v")
            logging.info(f"version - {version}")
        elif cmd == "log":
            # FIXME unknown syslog
            syslog = recv_stream(f"journalctl -u {juicity.name} -f -o cat")
            print(syslog)
        elif cmd == "start":
            juicity.start()
        elif cmd == "stop":
            juicity.stop()
        elif cmd == "restart":
            juicity.restart()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Juicity Scaffold (Python3.8+)")
    subparsers = parser.add_subparsers(dest="command")

    install_parser = subparsers.add_parser("install", help="Automatically install and run")
    install_parser.add_argument("-d", "--domain", type=str, help="传参指定域名，否则需要在运行脚本后以交互的形式输入")

    remove_parser = subparsers.add_parser("remove", help="Uninstall services and associated caches")
    remove_parser.add_argument("-d", "--domain", type=str, help="传参指定域名，否则需要在运行脚本后以交互的形式输入")

    check_parser = subparsers.add_parser("check", help="Print client configuration")
    check_parser.add_argument("--nekoray", action="store_true", help="show NekoRay config")
    check_parser.add_argument("--clash", action="store_true", help="show Clash.Meta config")
    check_parser.add_argument("--v2ray", action="store_true", help="show v2rayN config")

    status_parser = subparsers.add_parser("status", help="Check juicity-service status")
    log_parser = subparsers.add_parser("log", help="Check juicity-service syslog")
    start_parser = subparsers.add_parser("start", help="Start juicity-service")
    stop_parser = subparsers.add_parser("stop", help="Stop juicity-service")
    restart_parser = subparsers.add_parser("restart", help="restart juicity-service")

    args = parser.parse_args()
    command = args.command

    with suppress(KeyboardInterrupt):
        if command == "install":
            Scaffold.install(params=args)
        elif command == "remove":
            Scaffold.remove(params=args)
        elif command == "check":
            Scaffold.check(params=args)
        elif command in ["status", "log", "start", "stop", "restart"]:
            Scaffold.service_relay(command)
        else:
            parser.print_help()
