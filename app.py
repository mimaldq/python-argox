import os
import sys
import json
import base64
import random
import string
import subprocess
import threading
import time
import signal
import logging
import asyncio
import aiohttp
from pathlib import Path
from aiohttp import web, ClientSession
from urllib.parse import urlparse, quote, urlencode
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List, Any, Tuple
import yaml
import uuid as uuid_module
import requests
import re
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
import socket
import select

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 环境变量配置
UPLOAD_URL = os.getenv('UPLOAD_URL', '')
PROJECT_URL = os.getenv('PROJECT_URL', '')
AUTO_ACCESS = os.getenv('AUTO_ACCESS', 'false').lower() == 'true'
FILE_PATH = os.getenv('FILE_PATH', './tmp')
SUB_PATH = os.getenv('SUB_PATH', 'sub')
PORT = int(os.getenv('SERVER_PORT', os.getenv('PORT', '3000')))
UUID = os.getenv('UUID', 'e2cae6af-5cdd-fa48-4137-ad3e617fbab0')
NEZHA_SERVER = os.getenv('NEZHA_SERVER', '')
NEZHA_PORT = os.getenv('NEZHA_PORT', '')
NEZHA_KEY = os.getenv('NEZHA_KEY', '')
ARGO_DOMAIN = os.getenv('ARGO_DOMAIN', '')
ARGO_AUTH = os.getenv('ARGO_AUTH', '')
ARGO_PORT = int(os.getenv('ARGO_PORT', '7860'))
CFIP = os.getenv('CFIP', 'cdns.doon.eu.org')
CFPORT = int(os.getenv('CFPORT', '443'))
NAME = os.getenv('NAME', '')
MONITOR_KEY = os.getenv('MONITOR_KEY', '')
MONITOR_SERVER = os.getenv('MONITOR_SERVER', '')
MONITOR_URL = os.getenv('MONITOR_URL', '')

# 全局常量
XRAY_PORT = 3001
WS_PORTS = {
    'vless': 3003,
    'vmess': 3004,
    'trojan': 3005
}

# 创建运行文件夹
file_path = Path(FILE_PATH)
file_path.mkdir(exist_ok=True, parents=True)
logger.info(f"工作目录: {FILE_PATH}")

@dataclass
class Config:
    """配置类"""
    upload_url: str = UPLOAD_URL
    project_url: str = PROJECT_URL
    auto_access: bool = AUTO_ACCESS
    file_path: Path = file_path
    sub_path: str = SUB_PATH
    port: int = PORT
    uuid: str = UUID
    nezha_server: str = NEZHA_SERVER
    nezha_port: str = NEZHA_PORT
    nezha_key: str = NEZHA_KEY
    argo_domain: str = ARGO_DOMAIN
    argo_auth: str = ARGO_AUTH
    argo_port: int = ARGO_PORT
    cfip: str = CFIP
    cfport: str = CFPORT
    name: str = NAME
    monitor_key: str = MONITOR_KEY
    monitor_server: str = MONITOR_SERVER
    monitor_url: str = MONITOR_URL

config = Config()

# 全局状态
class GlobalState:
    def __init__(self):
        self.sub_encoded = ""
        self.argo_domain = ""
        self.sub_txt = ""
        self.is_ready = False
        self.monitor_process = None
        self.processes = []
        self.proxy_running = False
        self.xray_ready = False
        
    def set_ready(self):
        self.is_ready = True
        logger.info("系统已就绪")

state = GlobalState()

class ProcessManager:
    """进程管理器"""
    def __init__(self):
        self.processes = []
        self.lock = threading.Lock()
    
    def add_process(self, process: subprocess.Popen) -> str:
        """添加进程并返回进程ID"""
        with self.lock:
            pid = str(process.pid)
            self.processes.append({
                'pid': pid,
                'process': process,
                'cmd': process.args if hasattr(process, 'args') else '',
                'start_time': time.time()
            })
            return pid
    
    def run_background(self, cmd: List[str], name: str = "", **kwargs) -> Optional[subprocess.Popen]:
        """在后台运行进程"""
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                **kwargs
            )
            
            pid = self.add_process(process)
            logger.info(f"{name or cmd[0]} 已启动 (PID: {pid})")
            return process
        except Exception as e:
            logger.error(f"启动 {name or cmd[0]} 失败: {e}")
            return None
    
    def run_detached(self, cmd: str, name: str = "") -> Optional[str]:
        """运行分离的shell命令"""
        try:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            
            pid = self.add_process(process)
            logger.info(f"{name or cmd[:50]} 已启动 (PID: {pid})")
            return pid
        except Exception as e:
            logger.error(f"启动 {name or cmd[:50]} 失败: {e}")
            return None
    
    def cleanup(self):
        """清理所有进程"""
        with self.lock:
            for proc_info in self.processes[:]:
                try:
                    process = proc_info['process']
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                    self.processes.remove(proc_info)
                    logger.info(f"已停止进程 {proc_info['pid']}")
                except Exception as e:
                    logger.error(f"停止进程 {proc_info.get('pid', 'unknown')} 时出错: {e}")

process_manager = ProcessManager()

class FileManager:
    """文件管理器"""
    
    @staticmethod
    def generate_random_name(length: int = 6) -> str:
        """生成随机文件名"""
        return ''.join(random.choices(string.ascii_lowercase, k=length))
    
    @staticmethod
    def get_architecture() -> str:
        """获取系统架构"""
        arch = os.uname().machine.lower() if hasattr(os, 'uname') else os.environ.get('HOSTTYPE', '')
        if 'arm' in arch or 'aarch64' in arch:
            return 'arm'
        return 'amd'
    
    @staticmethod
    def download_file(url: str, filepath: Path, timeout: int = 30) -> bool:
        """下载文件"""
        try:
            response = requests.get(url, stream=True, timeout=timeout)
            response.raise_for_status()
            
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            filepath.chmod(0o755)
            logger.info(f"下载成功: {filepath.name}")
            return True
        except Exception as e:
            logger.error(f"下载失败 {url}: {e}")
            return False
    
    @staticmethod
    def cleanup_old_files():
        """清理历史文件"""
        try:
            for file in config.file_path.iterdir():
                try:
                    if file.is_file():
                        file.unlink()
                except Exception:
                    pass
            logger.info("已清理旧文件")
        except Exception as e:
            logger.error(f"清理旧文件时出错: {e}")

class XrayManager:
    """Xray管理器"""
    
    @staticmethod
    def generate_config() -> Dict[str, Any]:
        """生成Xray配置文件"""
        return {
            "log": {
                "access": "/dev/null",
                "error": "/dev/null",
                "loglevel": "none"
            },
            "dns": {
                "servers": [
                    "https+local://8.8.8.8/dns-query",
                    "https+local://1.1.1.1/dns-query",
                    "8.8.8.8",
                    "1.1.1.1"
                ],
                "queryStrategy": "UseIP",
                "disableCache": False
            },
            "inbounds": [
                {
                    "port": XRAY_PORT,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{
                            "id": config.uuid,
                            "flow": "xtls-rprx-vision"
                        }],
                        "decryption": "none",
                        "fallbacks": [
                            {"dest": 3002},
                            {"path": "/vless-argo", "dest": WS_PORTS['vless']},
                            {"path": "/vmess-argo", "dest": WS_PORTS['vmess']},
                            {"path": "/trojan-argo", "dest": WS_PORTS['trojan']}
                        ]
                    },
                    "streamSettings": {
                        "network": "tcp"
                    }
                },
                {
                    "port": 3002,
                    "listen": "127.0.0.1",
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": config.uuid}],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "none"
                    }
                },
                {
                    "port": WS_PORTS['vless'],
                    "listen": "127.0.0.1",
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": config.uuid, "level": 0}],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "none",
                        "wsSettings": {
                            "path": "/vless-argo"
                        }
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                        "metadataOnly": False
                    }
                },
                {
                    "port": WS_PORTS['vmess'],
                    "listen": "127.0.0.1",
                    "protocol": "vmess",
                    "settings": {
                        "clients": [{"id": config.uuid, "alterId": 0}]
                    },
                    "streamSettings": {
                        "network": "ws",
                        "wsSettings": {
                            "path": "/vmess-argo"
                        }
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                        "metadataOnly": False
                    }
                },
                {
                    "port": WS_PORTS['trojan'],
                    "listen": "127.0.0.1",
                    "protocol": "trojan",
                    "settings": {
                        "clients": [{"password": config.uuid}]
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "none",
                        "wsSettings": {
                            "path": "/trojan-argo"
                        }
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                        "metadataOnly": False
                    }
                }
            ],
            "outbounds": [
                {
                    "protocol": "freedom",
                    "tag": "direct",
                    "settings": {
                        "domainStrategy": "UseIP"
                    }
                },
                {
                    "protocol": "blackhole",
                    "tag": "block",
                    "settings": {}
                }
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": []
            }
        }
    
    @staticmethod
    def save_config(config_data: Dict[str, Any]):
        """保存配置文件"""
        config_path = config.file_path / 'config.json'
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        logger.info(f"Xray配置已保存: {config_path}")
        return config_path

class ArgoManager:
    """Argo隧道管理器"""
    
    @staticmethod
    def create_tunnel_config():
        """创建隧道配置"""
        if not config.argo_auth or not config.argo_domain:
            logger.info("使用快速隧道")
            return None
        
        if 'TunnelSecret' in config.argo_auth:
            try:
                # 写入隧道JSON
                tunnel_json = config.file_path / 'tunnel.json'
                with open(tunnel_json, 'w', encoding='utf-8') as f:
                    f.write(config.argo_auth)
                
                # 解析隧道配置
                tunnel_config = json.loads(config.argo_auth)
                tunnel_id = tunnel_config.get('TunnelID', '')
                
                # 生成YAML配置
                tunnel_yaml = config.file_path / 'tunnel.yml'
                yaml_content = f"""tunnel: {tunnel_id}
credentials-file: {tunnel_json}
protocol: http2

ingress:
  - hostname: {config.argo_domain}
    service: http://localhost:{config.argo_port}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
                with open(tunnel_yaml, 'w', encoding='utf-8') as f:
                    f.write(yaml_content)
                
                logger.info('固定隧道配置生成成功')
                return tunnel_yaml
            except Exception as e:
                logger.error(f'生成隧道配置错误: {e}')
                return None
        else:
            logger.info("使用Token连接隧道")
            return None
    
    @staticmethod
    def extract_domain() -> Optional[str]:
        """提取隧道域名"""
        boot_log = config.file_path / 'boot.log'
        
        if config.argo_domain:
            logger.info(f'使用固定域名: {config.argo_domain}')
            return config.argo_domain
        
        if not boot_log.exists():
            return None
        
        try:
            with open(boot_log, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 查找所有可能的域名
            domains = re.findall(r'https?://([^/\s]+\.(?:trycloudflare\.com|cloudflare\.net))', content)
            
            if domains:
                domain = domains[-1]  # 使用最后一个找到的域名
                logger.info(f'找到隧道域名: {domain}')
                return domain
        except Exception as e:
            logger.error(f'读取boot.log错误: {e}')
        
        return None

class NodeManager:
    """节点管理器"""
    
    @staticmethod
    async def get_isp_info() -> str:
        """获取ISP信息"""
        try:
            async with ClientSession() as session:
                # 尝试第一个API
                try:
                    async with session.get('https://ipapi.co/json/', timeout=3) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get('country_code') and data.get('org'):
                                return f"{data['country_code']}_{data['org']}"
                except:
                    pass
                
                # 尝试第二个API
                try:
                    async with session.get('http://ip-api.com/json/', timeout=3) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get('status') == 'success':
                                return f"{data.get('countryCode', 'Unknown')}_{data.get('org', 'Unknown')}"
                except:
                    pass
        except:
            pass
        return 'Unknown'
    
    @staticmethod
    def generate_subscription(domain: str) -> Tuple[str, str]:
        """生成订阅内容"""
        # 获取ISP信息
        isp_info = asyncio.run(NodeManager.get_isp_info())
        node_name = f"{config.name}-{isp_info}" if config.name else isp_info
        
        # 生成VMESS配置
        vmess_config = {
            "v": "2",
            "ps": node_name,
            "add": config.cfip,
            "port": config.cfport,
            "id": config.uuid,
            "aid": "0",
            "scy": "none",
            "net": "ws",
            "type": "none",
            "host": domain,
            "path": "/vmess-argo?ed=2560",
            "tls": "tls",
            "sni": domain,
            "alpn": "",
            "fp": "firefox"
        }
        
        vmess_base64 = base64.b64encode(json.dumps(vmess_config).encode()).decode()
        
        sub_content = f"""vless://{config.uuid}@{config.cfip}:{config.cfport}?encryption=none&security=tls&sni={domain}&fp=firefox&type=ws&host={domain}&path=%2Fvless-argo%3Fed%3D2560#{node_name}

vmess://{vmess_base64}

trojan://{config.uuid}@{config.cfip}:{config.cfport}?security=tls&sni={domain}&fp=firefox&type=ws&host={domain}&path=%2Ftrojan-argo%3Fed%3D2560#{node_name}"""
        
        sub_encoded = base64.b64encode(sub_content.encode()).decode()
        
        # 保存到文件
        sub_file = config.file_path / 'sub.txt'
        with open(sub_file, 'w', encoding='utf-8') as f:
            f.write(sub_encoded)
        
        logger.info(f"订阅已生成: {sub_file}")
        print(f"\n{'='*60}")
        print("订阅内容 (base64):")
        print(sub_encoded)
        print(f"{'='*60}\n")
        
        return sub_content, sub_encoded

class DownloadManager:
    """下载管理器"""
    
    @staticmethod
    def get_file_urls() -> List[Tuple[Path, str]]:
        """获取要下载的文件URL"""
        architecture = FileManager.get_architecture()
        base_url = "https://arm64.ssss.nyc.mn" if architecture == 'arm' else "https://amd64.ssss.nyc.mn"
        
        # 生成随机文件名
        web_name = FileManager.generate_random_name()
        bot_name = FileManager.generate_random_name()
        npm_name = FileManager.generate_random_name() if config.nezha_port else None
        php_name = FileManager.generate_random_name() if not config.nezha_port else None
        
        files = [
            (config.file_path / web_name, f"{base_url}/web"),
            (config.file_path / bot_name, f"{base_url}/bot")
        ]
        
        if config.nezha_server and config.nezha_key:
            if config.nezha_port:
                files.insert(0, (config.file_path / npm_name, f"{base_url}/agent"))
            else:
                files.insert(0, (config.file_path / php_name, f"{base_url}/v1"))
        
        return files
    
    @staticmethod
    def download_files(files: List[Tuple[Path, str]]) -> bool:
        """下载文件"""
        success = True
        for filepath, url in files:
            if not FileManager.download_file(url, filepath):
                success = False
                logger.error(f"下载失败: {filepath.name}")
        
        return success

class ServiceManager:
    """服务管理器"""
    
    @staticmethod
    def run_nezha():
        """运行哪吒监控"""
        if not config.nezha_server or not config.nezha_key:
            logger.info("哪吒监控未配置，跳过")
            return
        
        # 查找哪吒二进制文件
        nezha_files = list(config.file_path.glob("[a-z]*"))
        nezha_bin = None
        
        for file in nezha_files:
            if file.is_file() and os.access(file, os.X_OK):
                # 检查文件类型
                try:
                    result = subprocess.run(['file', str(file)], capture_output=True, text=True)
                    if 'ELF' in result.stdout or 'executable' in result.stdout.lower():
                        nezha_bin = file
                        break
                except:
                    pass
        
        if not nezha_bin:
            logger.error("未找到哪吒可执行文件")
            return
        
        if config.nezha_port:
            # 哪吒v0
            args = [str(nezha_bin), "-s", f"{config.nezha_server}:{config.nezha_port}",
                   "-p", config.nezha_key, "--disable-auto-update", "--report-delay", "4",
                   "--skip-conn", "--skip-procs"]
            
            tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
            if config.nezha_port in tls_ports:
                args.append("--tls")
            
            process_manager.run_background(args, name="哪吒监控")
        else:
            # 哪吒v1
            port = config.nezha_server.split(':')[-1] if ':' in config.nezha_server else ''
            tls_ports = {'443', '8443', '2096', '2087', '2083', '2053'}
            nezha_tls = 'true' if port in tls_ports else 'false'
            
            # 生成配置
            config_yaml = f"""client_secret: {config.nezha_key}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: {config.nezha_server}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: {nezha_tls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {config.uuid}"""
            
            config_file = config.file_path / 'nezha_config.yaml'
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(config_yaml)
            
            args = [str(nezha_bin), "-c", str(config_file)]
            process_manager.run_background(args, name="哪吒监控v1")
    
    @staticmethod
    def run_xray():
        """运行Xray"""
        # 查找Xray二进制文件
        xray_files = list(config.file_path.glob("[a-z]*"))
        xray_bin = None
        
        for file in xray_files:
            if file.is_file() and os.access(file, os.X_OK):
                try:
                    result = subprocess.run(['file', str(file)], capture_output=True, text=True)
                    if 'ELF' in result.stdout or 'executable' in result.stdout.lower():
                        xray_bin = file
                        break
                except:
                    pass
        
        if not xray_bin:
            logger.error("未找到Xray可执行文件")
            return
        
        config_file = config.file_path / 'config.json'
        args = [str(xray_bin), "-c", str(config_file)]
        process = process_manager.run_background(args, name="Xray")
        
        # 检查Xray是否启动成功
        if process:
            state.xray_ready = True
            logger.info("Xray已启动")
    
    @staticmethod
    def run_cloudflared():
        """运行Cloudflared"""
        # 查找Cloudflared二进制文件
        cf_files = list(config.file_path.glob("[a-z]*"))
        cf_bin = None
        
        for file in cf_files:
            if file.is_file() and os.access(file, os.X_OK):
                # 排除已知的其他二进制文件
                if file.name.startswith(('nezha', 'xray', 'agent')):
                    continue
                cf_bin = file
                break
        
        if not cf_bin:
            logger.error("未找到Cloudflared可执行文件")
            return
        
        args = [str(cf_bin), "tunnel", "--edge-ip-version", "auto", 
               "--no-autoupdate", "--protocol", "http2"]
        
        if config.argo_auth and len(config.argo_auth.strip()) >= 120:
            # Token模式
            args.extend(["run", "--token", config.argo_auth.strip()])
        else:
            # 快速隧道模式
            args.extend([
                "--logfile", str(config.file_path / 'boot.log'),
                "--loglevel", "info",
                "--url", f"http://localhost:{config.argo_port}"
            ])
        
        process_manager.run_background(args, name="Cloudflared")
    
    @staticmethod
    def run_monitor():
        """运行监控脚本"""
        if not all([config.monitor_key, config.monitor_server, config.monitor_url]):
            logger.info("监控未配置，跳过")
            return
        
        monitor_url = "https://raw.githubusercontent.com/mimaldq/cf-vps-monitor/main/cf-vps-monitor.sh"
        monitor_file = config.file_path / 'monitor.sh'
        
        if FileManager.download_file(monitor_url, monitor_file):
            monitor_file.chmod(0o755)
            
            cmd = [
                str(monitor_file),
                '-i',
                '-k', config.monitor_key,
                '-s', config.monitor_server,
                '-u', config.monitor_url
            ]
            
            state.monitor_process = process_manager.run_background(cmd, name="监控脚本")

class ProxyServer:
    """代理服务器"""
    
    def __init__(self):
        self.is_running = False
        self.server = None
    
    async def handle_http(self, request: web.Request) -> web.Response:
        """处理HTTP请求"""
        path = request.path
        
        # 订阅路由
        if path == f"/{config.sub_path}":
            if not state.sub_encoded:
                return web.Response(status=503, text="订阅尚未准备好")
            return web.Response(
                text=state.sub_encoded,
                content_type='text/plain; charset=utf-8'
            )
        
        # 健康检查
        elif path == "/health":
            return web.Response(text="OK")
        
        # WebSocket路径（转发到Xray）
        elif path.startswith(('/vless-argo', '/vmess-argo', '/trojan-argo')):
            # 这些路径应该由Xray处理，如果直接访问，返回提示
            return web.Response(
                status=400,
                text="This path is for WebSocket connections only. Use a compatible client."
            )
        
        # 首页
        elif path == "/":
            index_file = Path(__file__).parent / 'index.html'
            if index_file.exists():
                return web.FileResponse(index_file)
            return web.Response(text="Xray Server is running!")
        
        # 其他路由
        else:
            return web.Response(status=404, text="Not Found")
    
    async def handle_websocket(self, request: web.Request) -> web.WebSocketResponse:
        """处理WebSocket请求 - 转发到Xray"""
        path = request.path
        
        # 确定目标端口
        if path.startswith('/vless-argo'):
            target_port = WS_PORTS['vless']
        elif path.startswith('/vmess-argo'):
            target_port = WS_PORTS['vmess']
        elif path.startswith('/trojan-argo'):
            target_port = WS_PORTS['trojan']
        else:
            return web.Response(status=404, text="Invalid WebSocket path")
        
        # 检查Xray是否就绪
        if not state.xray_ready:
            return web.Response(status=503, text="Xray is not ready")
        
        # 建立WebSocket连接
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        # 连接目标服务器
        target_url = f"ws://127.0.0.1:{target_port}{path}"
        
        try:
            async with ClientSession() as session:
                async with session.ws_connect(target_url) as target_ws:
                    
                    # 双向转发消息
                    async def forward(source, dest):
                        try:
                            async for msg in source:
                                if msg.type == aiohttp.WSMsgType.TEXT:
                                    await dest.send_str(msg.data)
                                elif msg.type == aiohttp.WSMsgType.BINARY:
                                    await dest.send_bytes(msg.data)
                                elif msg.type == aiohttp.WSMsgType.CLOSE:
                                    await dest.close()
                                elif msg.type == aiohttp.WSMsgType.ERROR:
                                    break
                        except Exception as e:
                            logger.debug(f"WebSocket转发错误: {e}")
                    
                    # 同时转发两个方向的消息
                    await asyncio.gather(
                        forward(ws, target_ws),
                        forward(target_ws, ws)
                    )
                    
        except Exception as e:
            logger.error(f"WebSocket代理错误: {e}")
        
        return ws
    
    async def start(self):
        """启动代理服务器"""
        app = web.Application()
        
        # 添加路由
        app.router.add_get('/health', self.handle_http)
        app.router.add_get(f'/{config.sub_path}', self.handle_http)
        app.router.add_get('/', self.handle_http)
        
        # WebSocket路由
        app.router.add_get('/vless-argo', self.handle_websocket)
        app.router.add_get('/vless-argo/', self.handle_websocket)
        app.router.add_get('/vmess-argo', self.handle_websocket)
        app.router.add_get('/vmess-argo/', self.handle_websocket)
        app.router.add_get('/trojan-argo', self.handle_websocket)
        app.router.add_get('/trojan-argo/', self.handle_websocket)
        
        # 其他路由
        app.router.add_route('*', '/{path:.*}', self.handle_http)
        
        # 启动服务器
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', config.argo_port)
        
        await site.start()
        self.is_running = True
        state.proxy_running = True
        
        logger.info(f"代理服务器已启动，监听端口: {config.argo_port}")
        print(f"\n{'='*60}")
        print(f"服务器状态:")
        print(f"订阅地址: http://localhost:{config.argo_port}/{config.sub_path}")
        print(f"WebSocket路径: /vless-argo, /vmess-argo, /trojan-argo")
        print(f"健康检查: http://localhost:{config.argo_port}/health")
        print(f"{'='*60}\n")
        
        return runner

class SystemManager:
    """系统管理器"""
    
    @staticmethod
    def init_system():
        """初始化系统"""
        logger.info("开始系统初始化...")
        
        # 清理旧文件
        FileManager.cleanup_old_files()
        
        # 生成Xray配置
        xray_config = XrayManager.generate_config()
        XrayManager.save_config(xray_config)
        
        # 创建Argo隧道配置
        ArgoManager.create_tunnel_config()
        
        # 下载文件
        files = DownloadManager.get_file_urls()
        if not DownloadManager.download_files(files):
            logger.error("文件下载失败，退出")
            return False
        
        return True
    
    @staticmethod
    def start_services():
        """启动服务"""
        logger.info("启动服务...")
        
        # 启动哪吒监控
        ServiceManager.run_nezha()
        time.sleep(2)
        
        # 启动Xray
        ServiceManager.run_xray()
        time.sleep(3)
        
        # 启动Cloudflared
        ServiceManager.run_cloudflared()
        time.sleep(5)
        
        # 等待隧道域名
        domain = None
        for _ in range(10):  # 最多尝试10次
            domain = ArgoManager.extract_domain()
            if domain:
                break
            logger.info("等待隧道域名...")
            time.sleep(3)
        
        if not domain:
            logger.error("无法获取隧道域名")
            return False
        
        state.argo_domain = domain
        
        # 生成订阅
        sub_txt, sub_encoded = NodeManager.generate_subscription(domain)
        state.sub_txt = sub_txt
        state.sub_encoded = sub_encoded
        
        # 启动监控脚本
        ServiceManager.run_monitor()
        
        # 上传节点（异步）
        if config.upload_url:
            threading.Thread(target=SystemManager.upload_nodes, daemon=True).start()
        
        # 添加自动访问任务
        if config.auto_access and config.project_url:
            threading.Thread(target=SystemManager.add_visit_task, daemon=True).start()
        
        # 清理临时文件
        threading.Thread(target=SystemManager.cleanup_files, daemon=True).start()
        
        state.set_ready()
        return True
    
    @staticmethod
    def upload_nodes():
        """上传节点"""
        if not config.upload_url:
            return
        
        try:
            if config.project_url:
                subscription_url = f"{config.project_url}/{config.sub_path}"
                data = {"subscription": [subscription_url]}
                
                response = requests.post(
                    f"{config.upload_url}/api/add-subscriptions",
                    json=data,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                if response.status_code == 200:
                    logger.info("订阅上传成功")
                elif response.status_code == 400:
                    logger.info("订阅已存在")
                else:
                    logger.error(f"订阅上传失败: {response.status_code}")
        except Exception as e:
            logger.error(f"上传节点错误: {e}")
    
    @staticmethod
    def add_visit_task():
        """添加自动访问任务"""
        if not config.auto_access or not config.project_url:
            return
        
        try:
            response = requests.post(
                'https://oooo.serv00.net/add-url',
                json={'url': config.project_url},
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            logger.info("自动访问任务添加成功")
        except Exception as e:
            logger.error(f"添加自动访问任务失败: {e}")
    
    @staticmethod
    def cleanup_files():
        """清理临时文件"""
        time.sleep(90)  # 90秒后清理
        
        try:
            # 清理下载的二进制文件
            for file in config.file_path.glob("[a-z]*"):
                if file.is_file():
                    try:
                        file.unlink()
                    except:
                        pass
            
            # 清理配置文件
            for pattern in ['*.json', '*.yaml', '*.yml', '*.log']:
                for file in config.file_path.glob(pattern):
                    try:
                        file.unlink()
                    except:
                        pass
            
            logger.info("临时文件已清理")
            logger.info("系统运行中...")
            
        except Exception as e:
            logger.error(f"清理文件错误: {e}")

def signal_handler(signum, frame):
    """信号处理"""
    logger.info(f"收到信号 {signum}，正在清理...")
    
    # 停止监控进程
    if state.monitor_process:
        try:
            state.monitor_process.terminate()
            state.monitor_process.wait(timeout=5)
        except:
            pass
    
    # 清理所有进程
    process_manager.cleanup()
    
    logger.info("程序退出")
    sys.exit(0)

async def main():
    """主函数"""
    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 初始化系统
    if not SystemManager.init_system():
        logger.error("系统初始化失败")
        return
    
    # 在后台启动服务
    def start_services_async():
        if not SystemManager.start_services():
            logger.error("服务启动失败")
            os._exit(1)
    
    service_thread = threading.Thread(target=start_services_async, daemon=True)
    service_thread.start()
    
    # 等待服务准备就绪
    logger.info("等待服务就绪...")
    for _ in range(30):  # 最多等待30秒
        if state.is_ready:
            break
        time.sleep(1)
    
    if not state.is_ready:
        logger.warning("服务尚未完全就绪，继续启动代理服务器...")
    
    # 启动代理服务器
    proxy = ProxyServer()
    try:
        runner = await proxy.start()
        
        # 保持运行
        while True:
            await asyncio.sleep(3600)
            
    except KeyboardInterrupt:
        logger.info("用户中断")
    except Exception as e:
        logger.error(f"服务器错误: {e}")
    finally:
        # 清理
        if proxy.server:
            await proxy.server.shutdown()
        
        process_manager.cleanup()

if __name__ == '__main__':
    # 检查依赖
    try:
        import requests
        import aiohttp
    except ImportError as e:
        logger.error(f"缺少依赖: {e}")
        logger.info("请安装依赖: pip install requests aiohttp pyyaml")
        sys.exit(1)
    
    # 运行主函数
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("程序被用户中断")
    except Exception as e:
        logger.error(f"程序错误: {e}")
        import traceback
        traceback.print_exc()
