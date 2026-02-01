import os
import sys
import json
import asyncio
import aiohttp
import subprocess
import random
import string
import time
import logging
import base64
import threading
import socket
import platform
import urllib.parse
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor
import signal

# ==================== 环境变量配置 ====================
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

# ==================== 日志配置 ====================
# 修复日志配置：避免handlers中包含None
log_handlers = [logging.StreamHandler()]
if os.getenv('LOG_TO_FILE', 'false').lower() == 'true':
    log_handlers.append(logging.FileHandler('app.log'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=log_handlers
)
logger = logging.getLogger(__name__)

# ==================== 全局变量 ====================
file_manager = None
process_manager = None
proxy_server = None
monitor_process = None
http_server = None
sub_content = ""
running = True

# ==================== 数据类定义 ====================
@dataclass
class FilePaths:
    """文件路径配置"""
    base: str
    npm: str
    web: str
    bot: str
    php: str
    monitor: str
    sub: str
    list: str
    boot_log: str
    config: str
    tunnel_json: str
    tunnel_yaml: str
    nezha_config: str
    
    def __post_init__(self):
        """初始化后处理"""
        self.base = Path(self.base)
        self.npm = str(self.base / self.npm)
        self.web = str(self.base / self.web)
        self.bot = str(self.base / self.bot)
        self.php = str(self.base / self.php)
        self.monitor = str(self.base / self.monitor)
        self.sub = str(self.base / self.sub)
        self.list = str(self.base / self.list)
        self.boot_log = str(self.base / self.boot_log)
        self.config = str(self.base / self.config)
        self.tunnel_json = str(self.base / self.tunnel_json)
        self.tunnel_yaml = str(self.base / self.tunnel_yaml)
        self.nezha_config = str(self.base / self.nezha_config)

# ==================== 辅助函数 ====================
def generate_random_name(length: int = 6) -> str:
    """生成随机名称"""
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def get_system_architecture() -> str:
    """获取系统架构"""
    arch = platform.machine().lower()
    if 'arm' in arch or 'aarch' in arch:
        return 'arm'
    return 'amd'

def get_base_url(arch: str) -> str:
    """获取基础URL"""
    if arch == 'arm':
        return 'https://arm64.ssss.nyc.mn'
    else:
        return 'https://amd64.ssss.nyc.mn'

# ==================== HTTP 请求处理器 ====================
class SimpleHTTPHandler(BaseHTTPRequestHandler):
    """简单的HTTP请求处理器"""
    
    def do_GET(self):
        """处理GET请求"""
        try:
            # 处理根路径
            if self.path == '/':
                # 检查是否存在 index.html
                index_path = os.path.join(os.path.dirname(__file__), 'index.html')
                if os.path.exists(index_path):
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    with open(index_path, 'rb') as f:
                        self.wfile.write(f.read())
                else:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b"Hello world!")
            
            # 处理订阅路径
            elif self.path == f'/{SUB_PATH}':
                self.send_response(200)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.end_headers()
                if sub_content:
                    self.wfile.write(sub_content.encode())
                else:
                    self.wfile.write(b"Subscription not available")
            
            # 处理其他路径
            else:
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"Not Found")
        
        except Exception as e:
            logger.error(f"HTTP处理错误: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
    
    def log_message(self, format, *args):
        """自定义日志消息格式"""
        logger.debug(f"HTTP请求: {self.address_string()} - {format % args}")

# ==================== 文件管理器 ====================
class FileManager:
    """文件管理器"""
    
    def __init__(self, base_path: str):
        self.base_path = Path(base_path)
        self.paths = None
        self.init_paths()
    
    def init_paths(self):
        """初始化文件路径"""
        self.paths = FilePaths(
            base=FILE_PATH,
            npm=generate_random_name(),
            web=generate_random_name(),
            bot=generate_random_name(),
            php=generate_random_name(),
            monitor='cf-vps-monitor.sh',
            sub='sub.txt',
            list='list.txt',
            boot_log='boot.log',
            config='config.json',
            tunnel_json='tunnel.json',
            tunnel_yaml='tunnel.yml',
            nezha_config='config.yaml'
        )
    
    def ensure_directories(self):
        """确保目录存在"""
        self.base_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"目录 {self.base_path} 已创建或已存在")
    
    def cleanup_old_files(self):
        """清理旧文件"""
        try:
            for file in self.base_path.glob('*'):
                try:
                    if file.is_file():
                        file.unlink()
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"清理文件时出错: {e}")
    
    def write_file(self, path: str, content: str, mode: str = 'w'):
        """写入文件"""
        with open(path, mode) as f:
            f.write(content)
    
    def read_file(self, path: str) -> Optional[str]:
        """读取文件"""
        try:
            with open(path, 'r') as f:
                return f.read()
        except Exception:
            return None

# ==================== 进程管理器 ====================
class ProcessManager:
    """进程管理器"""
    
    def __init__(self):
        self.processes = []
        self.executor = ThreadPoolExecutor(max_workers=10)
    
    def run_background(self, cmd: List[str], cwd: str = None) -> Optional[subprocess.Popen]:
        """在后台运行进程"""
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=cwd,
                start_new_session=True
            )
            self.processes.append(process)
            return process
        except Exception as e:
            logger.error(f"运行命令失败: {' '.join(cmd)}: {e}")
            return None
    
    def run_command(self, cmd: str, shell: bool = True) -> Optional[subprocess.CompletedProcess]:
        """运行命令并等待完成"""
        try:
            result = subprocess.run(
                cmd if shell else cmd.split(),
                shell=shell,
                capture_output=True,
                text=True
            )
            return result
        except Exception as e:
            logger.error(f"执行命令失败: {cmd}: {e}")
            return None
    
    def kill_process(self, process_name: str):
        """杀死进程"""
        try:
            if platform.system() == 'Windows':
                subprocess.run(f'taskkill /f /im {process_name}', shell=True)
            else:
                subprocess.run(f'pkill -f {process_name}', shell=True)
        except Exception:
            pass
    
    def cleanup(self):
        """清理所有进程"""
        for process in self.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        self.processes.clear()

# ==================== 下载管理器 ====================
class DownloadManager:
    """下载管理器"""
    
    @staticmethod
    async def download_file_async(url: str, dest: str) -> bool:
        """异步下载文件"""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.read()
                        with open(dest, 'wb') as f:
                            f.write(content)
                        
                        # 设置权限
                        os.chmod(dest, 0o755)
                        logger.info(f"下载成功: {url} -> {dest}")
                        return True
                    else:
                        logger.error(f"下载失败，状态码: {response.status}: {url}")
        except Exception as e:
            logger.error(f"下载失败: {url}: {e}")
        return False
    
    @staticmethod
    def download_file_sync(url: str, dest: str) -> bool:
        """同步下载文件"""
        try:
            import urllib.request
            urllib.request.urlretrieve(url, dest)
            os.chmod(dest, 0o755)
            logger.info(f"同步下载成功: {url} -> {dest}")
            return True
        except Exception as e:
            logger.error(f"同步下载失败: {url}: {e}")
        return False

# ==================== Xray 配置生成器 ====================
class XrayConfigGenerator:
    """Xray配置生成器"""
    
    @staticmethod
    def generate_config(uuid: str) -> dict:
        """生成Xray配置"""
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
                    "port": 3001,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{
                            "id": uuid,
                            "flow": "xtls-rprx-vision"
                        }],
                        "decryption": "none",
                        "fallbacks": [
                            {"dest": 3002},
                            {"path": "/vless-argo", "dest": 3003},
                            {"path": "/vmess-argo", "dest": 3004},
                            {"path": "/trojan-argo", "dest": 3005}
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
                        "clients": [{"id": uuid}],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "none"
                    }
                },
                {
                    "port": 3003,
                    "listen": "127.0.0.1",
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": uuid, "level": 0}],
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
                    "port": 3004,
                    "listen": "127.0.0.1",
                    "protocol": "vmess",
                    "settings": {
                        "clients": [{"id": uuid, "alterId": 0}]
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
                    "port": 3005,
                    "listen": "127.0.0.1",
                    "protocol": "trojan",
                    "settings": {
                        "clients": [{"password": uuid}]
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

# ==================== Argo 隧道管理器 ====================
class ArgoTunnelManager:
    """Argo隧道管理器"""
    
    def __init__(self, file_manager: FileManager):
        self.file_manager = file_manager
    
    def create_tunnel_config(self):
        """创建隧道配置"""
        if not ARGO_AUTH or not ARGO_DOMAIN:
            logger.info("ARGO_DOMAIN 或 ARGO_AUTH 为空，使用临时隧道")
            return
        
        try:
            if 'TunnelSecret' in ARGO_AUTH:
                # 写入JSON配置
                self.file_manager.write_file(
                    self.file_manager.paths.tunnel_json,
                    ARGO_AUTH
                )
                
                # 解析JSON获取隧道ID
                config = json.loads(ARGO_AUTH)
                tunnel_id = config.get('TunnelID', '')
                
                # 创建YAML配置
                yaml_content = f"""tunnel: {tunnel_id}
credentials-file: {self.file_manager.paths.tunnel_json}
protocol: http2

ingress:
  - hostname: {ARGO_DOMAIN}
    service: http://localhost:{ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
                self.file_manager.write_file(
                    self.file_manager.paths.tunnel_yaml,
                    yaml_content
                )
                logger.info("隧道YAML配置生成成功")
            else:
                logger.info("ARGO_AUTH 不是TunnelSecret格式，使用token连接隧道")
        except Exception as e:
            logger.error(f"生成隧道配置错误: {e}")
    
    def extract_domain_from_log(self) -> Optional[str]:
        """从日志中提取域名"""
        log_content = self.file_manager.read_file(self.file_manager.paths.boot_log)
        if not log_content:
            return None
        
        import re
        lines = log_content.split('\n')
        for line in lines:
            match = re.search(r'https?://([^ ]*trycloudflare\.com)', line)
            if match:
                return match.group(1)
        return None

# ==================== 节点生成器 ====================
class NodeGenerator:
    """节点生成器"""
    
    @staticmethod
    async def get_isp_info() -> str:
        """获取ISP信息"""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
                # 尝试第一个API
                try:
                    async with session.get('https://ipapi.co/json/') as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get('country_code') and data.get('org'):
                                return f"{data['country_code']}_{data['org']}"
                except Exception:
                    pass
                
                # 尝试第二个API
                try:
                    async with session.get('http://ip-api.com/json/') as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get('status') == 'success' and data.get('countryCode'):
                                return f"{data['countryCode']}_{data.get('org', 'Unknown')}"
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"获取ISP信息失败: {e}")
        
        return 'Unknown'
    
    @staticmethod
    def generate_sub_content(uuid: str, cfip: str, cfport: int, 
                           domain: str, name: str) -> str:
        """生成订阅内容"""
        # 生成VMess配置
        vmess_config = {
            "v": "2",
            "ps": name,
            "add": cfip,
            "port": cfport,
            "id": uuid,
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
        
        vmess_base64 = base64.b64encode(
            json.dumps(vmess_config).encode()
        ).decode()
        
        # 生成订阅文本
        return f"""vless://{uuid}@{cfip}:{cfport}?encryption=none&security=tls&sni={domain}&fp=firefox&type=ws&host={domain}&path=%2Fvless-argo%3Fed%3D2560#{name}

vmess://{vmess_base64}

trojan://{uuid}@{cfip}:{cfport}?security=tls&sni={domain}&fp=firefox&type=ws&host={domain}&path=%2Ftrojan-argo%3Fed%3D2560#{name}
"""

# ==================== 上传管理器 ====================
class UploadManager:
    """上传管理器"""
    
    @staticmethod
    async def delete_nodes():
        """删除节点"""
        if not UPLOAD_URL:
            return
        
        sub_path = file_manager.paths.sub
        if not os.path.exists(sub_path):
            return
        
        try:
            content = file_manager.read_file(sub_path)
            if not content:
                return
            
            # 解码base64
            decoded = base64.b64decode(content).decode('utf-8')
            nodes = [
                line for line in decoded.split('\n')
                if any(proto in line for proto in 
                      ['vless://', 'vmess://', 'trojan://', 
                       'hysteria2://', 'tuic://'])
            ]
            
            if nodes:
                async with aiohttp.ClientSession() as session:
                    await session.post(
                        f"{UPLOAD_URL}/api/delete-nodes",
                        json={"nodes": nodes}
                    )
        except Exception as e:
            logger.debug(f"删除节点失败: {e}")
    
    @staticmethod
    async def upload_subscription():
        """上传订阅"""
        if not UPLOAD_URL:
            return
        
        if PROJECT_URL:
            # 上传订阅URL
            subscription_url = f"{PROJECT_URL}/{SUB_PATH}"
            data = {"subscription": [subscription_url]}
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{UPLOAD_URL}/api/add-subscriptions",
                        json=data
                    ) as response:
                        if response.status == 200:
                            logger.info("订阅上传成功")
                        elif response.status == 400:
                            logger.info("订阅已存在")
                        else:
                            logger.error(f"订阅上传失败: {response.status}")
            except Exception as e:
                logger.error(f"订阅上传失败: {e}")
        else:
            # 上传节点
            list_path = file_manager.paths.list
            if not os.path.exists(list_path):
                return
            
            content = file_manager.read_file(list_path)
            if not content:
                return
            
            nodes = [
                line for line in content.split('\n')
                if any(proto in line for proto in 
                      ['vless://', 'vmess://', 'trojan://', 
                       'hysteria2://', 'tuic://'])
            ]
            
            if nodes:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            f"{UPLOAD_URL}/api/add-nodes",
                            json={"nodes": nodes}
                        ) as response:
                            if response.status == 200:
                                logger.info("节点上传成功")
                except Exception as e:
                    logger.error(f"节点上传失败: {e}")

# ==================== 监控脚本管理器 ====================
class MonitorManager:
    """监控脚本管理器"""
    
    def __init__(self, file_manager: FileManager, process_manager: ProcessManager):
        self.file_manager = file_manager
        self.process_manager = process_manager
        self.process = None
    
    async def download_monitor_script(self) -> bool:
        """下载监控脚本"""
        if not all([MONITOR_KEY, MONITOR_SERVER, MONITOR_URL]):
            logger.info("监控环境变量不完整，跳过监控脚本启动")
            return False
        
        monitor_url = "https://raw.githubusercontent.com/mimaldq/cf-vps-monitor/main/cf-vps-monitor.sh"
        
        logger.info(f"从 {monitor_url} 下载监控脚本")
        
        success = await DownloadManager.download_file_async(
            monitor_url,
            self.file_manager.paths.monitor
        )
        
        if success:
            logger.info("监控脚本下载完成")
        
        return success
    
    def start_monitor(self):
        """启动监控脚本"""
        if not all([MONITOR_KEY, MONITOR_SERVER, MONITOR_URL]):
            return
        
        if not os.path.exists(self.file_manager.paths.monitor):
            logger.error("监控脚本不存在")
            return
        
        args = [
            self.file_manager.paths.monitor,
            '-i',
            '-k', MONITOR_KEY,
            '-s', MONITOR_SERVER,
            '-u', MONITOR_URL
        ]
        
        logger.info(f"运行监控脚本: {' '.join(args)}")
        
        self.process = self.process_manager.run_background(args)
        
        # 检查进程是否运行
        if self.process and self.process.poll() is None:
            logger.info("监控脚本已启动")
        else:
            logger.error("监控脚本启动失败")
    
    def stop_monitor(self):
        """停止监控脚本"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None
            logger.info("监控脚本已停止")

# ==================== 哪吒监控管理器 ====================
class NeZhaManager:
    """哪吒监控管理器"""
    
    def __init__(self, file_manager: FileManager, process_manager: ProcessManager):
        self.file_manager = file_manager
        self.process_manager = process_manager
        self.process = None
    
    def create_v1_config(self) -> str:
        """创建哪吒v1配置"""
        # 检测TLS端口
        port = NEZHA_SERVER.split(':')[-1] if ':' in NEZHA_SERVER else ''
        tls_ports = {'443', '8443', '2096', '2087', '2083', '2053'}
        nezha_tls = 'true' if port in tls_ports else 'false'
        
        return f"""
client_secret: {NEZHA_KEY}
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
server: {NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: {nezha_tls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {UUID}
"""
    
    def start(self):
        """启动哪吒监控"""
        if not NEZHA_SERVER or not NEZHA_KEY:
            logger.info('哪吒监控变量为空，跳过运行')
            return
        
        if not NEZHA_PORT:
            # 运行哪吒v1
            config_content = self.create_v1_config()
            self.file_manager.write_file(
                self.file_manager.paths.nezha_config,
                config_content
            )
            
            if os.path.exists(self.file_manager.paths.php):
                self.process = self.process_manager.run_background([
                    self.file_manager.paths.php,
                    "-c", self.file_manager.paths.nezha_config
                ])
                if self.process:
                    logger.info(f"{os.path.basename(self.file_manager.paths.php)} 运行中")
            else:
                logger.error(f"哪吒v1客户端不存在: {self.file_manager.paths.php}")
        else:
            # 运行哪吒v0
            args = [
                "-s", f"{NEZHA_SERVER}:{NEZHA_PORT}",
                "-p", NEZHA_KEY
            ]
            
            tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
            if NEZHA_PORT in tls_ports:
                args.append("--tls")
            
            args.extend([
                "--disable-auto-update",
                "--report-delay", "4",
                "--skip-conn",
                "--skip-procs"
            ])
            
            if os.path.exists(self.file_manager.paths.npm):
                self.process = self.process_manager.run_background([
                    self.file_manager.paths.npm
                ] + args)
                if self.process:
                    logger.info(f"{os.path.basename(self.file_manager.paths.npm)} 运行中")
            else:
                logger.error(f"哪吒v0客户端不存在: {self.file_manager.paths.npm}")
    
    def stop(self):
        """停止哪吒监控"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None
            logger.info("哪吒监控已停止")

# ==================== 简化的代理服务器 ====================
class SimpleProxyServer:
    """简化的代理服务器，直接转发到对应端口"""
    
    def __init__(self):
        self.http_server = None
    
    def start(self):
        """启动代理服务器"""
        def run_proxy_server():
            import socketserver
            import http.server
            
            class ProxyHandler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    # 根据路径转发到不同端口
                    path = self.path
                    
                    # 如果是WebSocket请求
                    if self.headers.get('Upgrade', '').lower() == 'websocket':
                        self.handle_websocket(path)
                    else:
                        self.handle_http(path)
                
                def handle_websocket(self, path):
                    """处理WebSocket请求"""
                    # 删除Sec-WebSocket-Protocol头
                    if 'Sec-WebSocket-Protocol' in self.headers:
                        del self.headers['Sec-WebSocket-Protocol']
                    
                    # 根据路径确定目标端口
                    target_port = self.get_target_port(path)
                    if not target_port:
                        self.send_response(404)
                        self.end_headers()
                        return
                    
                    # 建立到目标端口的连接
                    try:
                        import socket
                        import base64
                        import hashlib
                        
                        # 获取WebSocket key
                        ws_key = self.headers.get('Sec-WebSocket-Key', '')
                        
                        # 发送101 Switching Protocols响应
                        self.send_response(101)
                        self.send_header('Upgrade', 'websocket')
                        self.send_header('Connection', 'Upgrade')
                        self.send_header('Sec-WebSocket-Accept', 
                                        base64.b64encode(hashlib.sha1(
                                            (ws_key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()
                                        ).digest()).decode())
                        self.end_headers()
                        
                        # 建立到目标端口的socket连接
                        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        target_socket.connect(('127.0.0.1', target_port))
                        
                        # 双向转发数据
                        self.forward_sockets(self.connection, target_socket)
                        
                    except Exception as e:
                        logger.error(f"WebSocket代理错误: {e}")
                
                def handle_http(self, path):
                    """处理HTTP请求"""
                    # 根据路径确定目标端口
                    if (path.startswith('/vless-argo') or 
                        path.startswith('/vmess-argo') or 
                        path.startswith('/trojan-argo') or
                        path in ['/vless', '/vmess', '/trojan']):
                        # 转发到Xray
                        target_port = 3001
                    else:
                        # 转发到HTTP服务器
                        target_port = PORT
                    
                    # 转发请求
                    try:
                        import http.client
                        
                        # 连接到目标服务器
                        conn = http.client.HTTPConnection('127.0.0.1', target_port)
                        
                        # 转发请求头
                        headers = {}
                        for key, value in self.headers.items():
                            if key.lower() not in ['host', 'connection']:
                                headers[key] = value
                        
                        # 转发请求
                        conn.request(self.command, path, self.rfile.read(int(self.headers.get('Content-Length', 0))) 
                                    if self.command in ['POST', 'PUT'] else None, headers)
                        
                        # 获取响应
                        resp = conn.getresponse()
                        
                        # 转发响应
                        self.send_response(resp.status)
                        for header, value in resp.getheaders():
                            self.send_header(header, value)
                        self.end_headers()
                        
                        # 转发响应体
                        self.wfile.write(resp.read())
                        
                    except Exception as e:
                        logger.error(f"HTTP代理错误: {e}")
                        self.send_response(502)
                        self.end_headers()
                
                def get_target_port(self, path):
                    """根据路径获取目标端口"""
                    if path.startswith('/vless-argo'):
                        return 3003
                    elif path.startswith('/vmess-argo'):
                        return 3004
                    elif path.startswith('/trojan-argo'):
                        return 3005
                    elif path in ['/vless', '/vmess', '/trojan']:
                        return 3001
                    else:
                        return None
                
                def forward_sockets(self, client_socket, target_socket):
                    """双向转发socket数据"""
                    import select
                    
                    sockets = [client_socket, target_socket]
                    while True:
                        try:
                            read_sockets, _, _ = select.select(sockets, [], [])
                            
                            for sock in read_sockets:
                                data = sock.recv(4096)
                                if not data:
                                    return
                                
                                if sock is client_socket:
                                    target_socket.send(data)
                                else:
                                    client_socket.send(data)
                        except:
                            break
                    
                    # 关闭连接
                    client_socket.close()
                    target_socket.close()
                
                def log_message(self, format, *args):
                    """不记录访问日志"""
                    pass
            
            try:
                self.http_server = socketserver.TCPServer(('0.0.0.0', ARGO_PORT), ProxyHandler)
                logger.info(f"代理服务器启动在端口: {ARGO_PORT}")
                logger.info(f"HTTP流量 -> localhost:{PORT}")
                logger.info(f"Xray流量 -> localhost:3001")
                self.http_server.serve_forever()
            except Exception as e:
                logger.error(f"代理服务器启动失败: {e}")
        
        proxy_thread = threading.Thread(target=run_proxy_server, daemon=True)
        proxy_thread.start()
    
    def stop(self):
        """停止代理服务器"""
        if self.http_server:
            self.http_server.shutdown()

# ==================== 主应用类 ====================
class CloudflareVPS:
    """Cloudflare VPS 主应用"""
    
    def __init__(self):
        self.file_manager = FileManager(FILE_PATH)
        self.process_manager = ProcessManager()
        self.argo_tunnel = ArgoTunnelManager(self.file_manager)
        self.ne_zha_manager = NeZhaManager(self.file_manager, self.process_manager)
        self.monitor_manager = MonitorManager(self.file_manager, self.process_manager)
        self.proxy_server = SimpleProxyServer()
        self.http_server = None
    
    async def initialize(self):
        """初始化应用"""
        logger.info("开始服务器初始化...")
        
        # 确保目录存在
        self.file_manager.ensure_directories()
        
        # 删除节点
        await UploadManager.delete_nodes()
        
        # 清理旧文件
        self.file_manager.cleanup_old_files()
        
        # 创建隧道配置
        self.argo_tunnel.create_tunnel_config()
        
        # 生成Xray配置
        try:
            config = XrayConfigGenerator.generate_config(UUID)
            self.file_manager.write_file(
                self.file_manager.paths.config,
                json.dumps(config, indent=2)
            )
            logger.info("Xray配置文件生成完成")
        except Exception as e:
            logger.error(f"生成Xray配置失败: {e}")
            return
        
        # 下载并运行依赖文件
        await self.download_and_run_files()
        
        # 启动HTTP服务器
        self.start_http_server()
        
        # 启动代理服务器
        self.proxy_server.start()
        
        # 等待隧道启动
        logger.info("等待隧道启动...")
        await asyncio.sleep(5)
        
        # 提取域名并生成订阅
        await self.generate_subscription()
        
        # 添加访问任务
        await self.add_visit_task()
        
        # 启动监控脚本（延迟启动）
        asyncio.create_task(self.start_monitor_delayed())
        
        logger.info("服务器初始化完成")
        
        # 清理临时文件
        asyncio.create_task(self.cleanup_files_delayed())
    
    async def download_and_run_files(self):
        """下载并运行依赖文件"""
        arch = get_system_architecture()
        base_url = get_base_url(arch)
        
        # 下载文件列表
        files_to_download = []
        
        if NEZHA_SERVER and NEZHA_KEY:
            if NEZHA_PORT:
                # 哪吒v0
                files_to_download.append({
                    'url': f"{base_url}/agent",
                    'dest': self.file_manager.paths.npm
                })
            else:
                # 哪吒v1
                files_to_download.append({
                    'url': f"{base_url}/v1",
                    'dest': self.file_manager.paths.php
                })
        
        # Xray和Cloudflared
        files_to_download.extend([
            {
                'url': f"{base_url}/web",
                'dest': self.file_manager.paths.web
            },
            {
                'url': f"{base_url}/bot",
                'dest': self.file_manager.paths.bot
            }
        ])
        
        # 下载所有文件
        download_tasks = []
        for file_info in files_to_download:
            download_tasks.append(
                DownloadManager.download_file_async(
                    file_info['url'],
                    file_info['dest']
                )
            )
        
        results = await asyncio.gather(*download_tasks, return_exceptions=True)
        
        # 检查下载结果
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"下载失败: {files_to_download[i]['url']}: {result}")
        
        # 启动哪吒监控
        self.ne_zha_manager.start()
        await asyncio.sleep(1)
        
        # 启动Xray
        if os.path.exists(self.file_manager.paths.web):
            self.process_manager.run_background([
                self.file_manager.paths.web,
                "-c", self.file_manager.paths.config
            ])
            logger.info(f"{os.path.basename(self.file_manager.paths.web)} 运行中")
            await asyncio.sleep(1)
        else:
            logger.error(f"Xray客户端不存在: {self.file_manager.paths.web}")
        
        # 启动Cloudflared
        await self.start_cloudflared()
        
        await asyncio.sleep(2)
    
    async def start_cloudflared(self):
        """启动Cloudflared"""
        if not os.path.exists(self.file_manager.paths.bot):
            logger.error("Cloudflared客户端不存在")
            return
        
        args = [
            "tunnel",
            "--edge-ip-version", "auto",
            "--no-autoupdate",
            "--protocol", "http2"
        ]
        
        if ARGO_AUTH and ARGO_AUTH.isalnum() and len(ARGO_AUTH) >= 120:
            # Token认证
            args.extend(["run", "--token", ARGO_AUTH])
        elif ARGO_AUTH and 'TunnelSecret' in ARGO_AUTH:
            # 配置文件认证
            args.extend(["--config", self.file_manager.paths.tunnel_yaml, "run"])
        else:
            # 临时隧道
            args.extend([
                "--logfile", self.file_manager.paths.boot_log,
                "--loglevel", "info",
                "--url", f"http://localhost:{ARGO_PORT}"
            ])
        
        self.process_manager.run_background([
            self.file_manager.paths.bot
        ] + args)
        logger.info(f"{os.path.basename(self.file_manager.paths.bot)} 运行中")
        
        # 等待隧道启动
        await asyncio.sleep(5)
    
    def start_http_server(self):
        """启动HTTP服务器"""
        def run_http_server():
            global http_server
            try:
                http_server = HTTPServer(('0.0.0.0', PORT), SimpleHTTPHandler)
                logger.info(f"HTTP服务运行在端口: {PORT}")
                http_server.serve_forever()
            except Exception as e:
                logger.error(f"HTTP服务器启动失败: {e}")
        
        http_thread = threading.Thread(target=run_http_server, daemon=True)
        http_thread.start()
    
    async def generate_subscription(self):
        """生成订阅"""
        global sub_content
        
        # 获取域名
        domain = ARGO_DOMAIN
        if not domain:
            domain = self.argo_tunnel.extract_domain_from_log()
        
        if not domain:
            logger.warning("未找到域名，重新运行bot以获取Argo域名")
            await self.restart_cloudflared()
            await asyncio.sleep(3)
            domain = self.argo_tunnel.extract_domain_from_log()
        
        if not domain:
            logger.error("无法获取域名")
            return
        
        logger.info(f"使用域名: {domain}")
        
        # 获取ISP信息
        isp_info = await NodeGenerator.get_isp_info()
        node_name = f"{NAME}-{isp_info}" if NAME else isp_info
        
        # 生成订阅内容
        sub_text = NodeGenerator.generate_sub_content(UUID, CFIP, CFPORT, domain, node_name)
        
        # 编码并保存
        encoded_content = base64.b64encode(sub_text.encode()).decode()
        self.file_manager.write_file(self.file_manager.paths.sub, encoded_content)
        
        # 保存原始文本用于HTTP服务器
        sub_content = encoded_content
        
        logger.info(f"订阅文件保存成功: {self.file_manager.paths.sub}")
        
        # 打印订阅内容
        print(f"\n{'='*60}")
        print("订阅内容 (base64):")
        print(encoded_content)
        print(f"{'='*60}\n")
        
        # 上传节点
        await UploadManager.upload_subscription()
    
    async def restart_cloudflared(self):
        """重启Cloudflared"""
        logger.info("重启Cloudflared...")
        
        # 停止现有进程
        self.process_manager.kill_process(os.path.basename(self.file_manager.paths.bot))
        await asyncio.sleep(2)
        
        # 重新启动
        await self.start_cloudflared()
    
    async def add_visit_task(self):
        """添加访问任务"""
        if not AUTO_ACCESS or not PROJECT_URL:
            logger.info("跳过添加自动访问任务")
            return
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    'https://oooo.serv00.net/add-url',
                    json={'url': PROJECT_URL}
                ) as response:
                    if response.status == 200:
                        logger.info("自动访问任务添加成功")
        except Exception as e:
            logger.error(f"添加自动访问任务失败: {e}")
    
    async def start_monitor_delayed(self):
        """延迟启动监控脚本"""
        await asyncio.sleep(10)
        
        if all([MONITOR_KEY, MONITOR_SERVER, MONITOR_URL]):
            success = await self.monitor_manager.download_monitor_script()
            if success:
                self.monitor_manager.start_monitor()
    
    async def cleanup_files_delayed(self):
        """延迟清理文件"""
        await asyncio.sleep(90)
        
        files_to_delete = [
            self.file_manager.paths.boot_log,
            self.file_manager.paths.config,
            self.file_manager.paths.web,
            self.file_manager.paths.bot,
            self.file_manager.paths.monitor
        ]
        
        if NEZHA_PORT and os.path.exists(self.file_manager.paths.npm):
            files_to_delete.append(self.file_manager.paths.npm)
        elif NEZHA_SERVER and NEZHA_KEY and os.path.exists(self.file_manager.paths.php):
            files_to_delete.append(self.file_manager.paths.php)
        
        for file_path in files_to_delete:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception:
                pass
        
        logger.info("应用正在运行")
        logger.info("感谢使用此脚本，享受吧！")
    
    async def cleanup(self):
        """清理资源"""
        logger.info("正在清理资源...")
        
        # 停止监控脚本
        self.monitor_manager.stop_monitor()
        
        # 停止哪吒监控
        self.ne_zha_manager.stop()
        
        # 停止进程管理器
        self.process_manager.cleanup()
        
        # 停止代理服务器
        self.proxy_server.stop()
        
        # 停止HTTP服务器
        if self.http_server:
            self.http_server.shutdown()
        
        logger.info("资源清理完成")

# ==================== 信号处理 ====================
def signal_handler(signum, frame):
    """信号处理器"""
    logger.info(f"收到信号 {signum}，正在清理...")
    
    # 这里需要异步清理，但由于信号处理器不能是async
    # 我们设置一个标志，让主循环退出
    global running
    running = False

# ==================== 主函数 ====================
async def main():
    """主函数"""
    global running, file_manager, process_manager
    
    # 初始化全局管理器
    file_manager = FileManager(FILE_PATH)
    process_manager = ProcessManager()
    
    # 创建应用实例
    app = CloudflareVPS()
    
    try:
        # 初始化应用
        await app.initialize()
        
        # 主循环
        running = True
        while running:
            await asyncio.sleep(1)
            
            # 可以在这里添加定期任务
            # 例如：检查进程状态、更新统计等
    
    except KeyboardInterrupt:
        logger.info("收到键盘中断信号")
    except Exception as e:
        logger.error(f"应用运行错误: {e}")
    finally:
        # 清理资源
        await app.cleanup()
        logger.info("程序退出")

if __name__ == "__main__":
    # 设置信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 检查Python版本
    if sys.version_info < (3, 7):
        print("需要Python 3.7或更高版本")
        sys.exit(1)
    
    # 运行主函数
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n程序被用户中断")
    except Exception as e:
        print(f"程序运行错误: {e}")
        sys.exit(1)
