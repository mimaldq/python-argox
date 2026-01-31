import os
import sys
import json
import base64
import random
import string
import subprocess
import asyncio
import signal
import logging
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from contextlib import asynccontextmanager

import httpx
import aiofiles
from websockets import connect as websocket_connect
from websockets.exceptions import ConnectionClosed
import websockets

from sanic import Sanic, Request, Websocket, HTTPResponse, text, file, response
from sanic.response import ResponseStream
from sanic.handlers import ErrorHandler

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
CFPORT = os.getenv('CFPORT', '443')
NAME = os.getenv('NAME', '')
MONITOR_KEY = os.getenv('MONITOR_KEY', '')
MONITOR_SERVER = os.getenv('MONITOR_SERVER', '')
MONITOR_URL = os.getenv('MONITOR_URL', '')

# ==================== 日志配置 ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== 文件路径配置 ====================
file_path = Path(FILE_PATH)
file_path.mkdir(exist_ok=True, parents=True)
logger.info(f"{FILE_PATH} 目录已创建或已存在")

def generate_random_name(length=6):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

# 生成文件名
npm_name = generate_random_name()
web_name = generate_random_name()
bot_name = generate_random_name()
php_name = generate_random_name()
monitor_name = 'cf-vps-monitor.sh'

# 文件路径
npm_path = file_path / npm_name
php_path = file_path / php_name
web_path = file_path / web_name
bot_path = file_path / bot_name
monitor_path = file_path / monitor_name
sub_path = file_path / 'sub.txt'
list_path = file_path / 'list.txt'
boot_log_path = file_path / 'boot.log'
config_path = file_path / 'config.json'
tunnel_json_path = file_path / 'tunnel.json'
tunnel_yaml_path = file_path / 'tunnel.yml'

# ==================== 全局变量 ====================
monitor_process = None
argo_domain = ""
sub_content = ""
is_running = True
xray_process = None
nezha_process = None
cloudflared_process = None
sub_lock = asyncio.Lock()
websocket_connections: Set[Websocket] = set()
ws_connection_lock = asyncio.Lock()

# ==================== 进程管理器 ====================
class ProcessManager:
    def __init__(self):
        self.processes: List[subprocess.Popen] = []
    
    def add_process(self, process: subprocess.Popen):
        self.processes.append(process)
    
    def cleanup(self):
        for process in self.processes:
            try:
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
            except Exception as e:
                logger.error(f"终止进程错误: {e}")
        self.processes.clear()

process_manager = ProcessManager()

# ==================== 核心功能函数 ====================
def delete_nodes():
    try:
        if not UPLOAD_URL or not sub_path.exists():
            return
        
        with open(sub_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
        
        decoded = base64.b64decode(file_content).decode('utf-8')
        nodes = [line for line in decoded.split('\n') 
                if re.search(r'(vless|vmess|trojan|hysteria2|tuic)://', line)]
        
        if not nodes:
            return
        
        try:
            httpx.post(
                f"{UPLOAD_URL}/api/delete-nodes",
                json={"nodes": nodes},
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
        except Exception:
            pass
    except Exception:
        pass

def cleanup_old_files():
    try:
        for file in file_path.iterdir():
            try:
                if file.is_file():
                    file.unlink()
            except Exception:
                pass
    except Exception:
        pass

def generate_config():
    config = {
        "log": {"access": "/dev/null", "error": "/dev/null", "loglevel": "none"},
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
                    "clients": [{"id": UUID, "flow": "xtls-rprx-vision"}],
                    "decryption": "none",
                    "fallbacks": [
                        {"dest": 3002},
                        {"path": "/vless-argo", "dest": 3003},
                        {"path": "/vmess-argo", "dest": 3004},
                        {"path": "/trojan-argo", "dest": 3005}
                    ]
                },
                "streamSettings": {"network": "tcp"}
            },
            {
                "port": 3002,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                "streamSettings": {"network": "tcp", "security": "none"}
            },
            {
                "port": 3003,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {"clients": [{"id": UUID, "level": 0}], "decryption": "none"},
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {"path": "/vless-argo"}
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
                "settings": {"clients": [{"id": UUID, "alterId": 0}]},
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {"path": "/vmess-argo"}
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
                "settings": {"clients": [{"password": UUID}]},
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {"path": "/trojan-argo"}
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
                "settings": {"domainStrategy": "UseIP"}
            },
            {"protocol": "blackhole", "tag": "block", "settings": {}}
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": []}
    }
    
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)
    logger.info("Xray 配置文件生成完成")

def get_system_architecture():
    try:
        import platform
        arch = platform.machine().lower()
        if arch in ['arm', 'arm64', 'aarch64', 'armv8l', 'armv7l']:
            return 'arm'
        return 'amd'
    except:
        return 'amd'

async def download_file(url: str, filepath: Path) -> bool:
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(url)
            response.raise_for_status()
            
            async with aiofiles.open(filepath, 'wb') as f:
                await f.write(response.content)
            
            filepath.chmod(0o775)
            logger.info(f"下载 {filepath.name} 成功")
            return True
    except Exception as e:
        logger.error(f"下载 {url} 失败: {e}")
        return False

async def download_files_and_run():
    architecture = get_system_architecture()
    files_to_download = []
    
    if architecture == 'arm':
        files_to_download = [
            (web_path, "https://arm64.ssss.nyc.mn/web"),
            (bot_path, "https://arm64.ssss.nyc.mn/bot")
        ]
        if NEZHA_SERVER and NEZHA_KEY:
            if NEZHA_PORT:
                files_to_download.insert(0, (npm_path, "https://arm64.ssss.nyc.mn/agent"))
            else:
                files_to_download.insert(0, (php_path, "https://arm64.ssss.nyc.mn/v1"))
    else:
        files_to_download = [
            (web_path, "https://amd64.ssss.nyc.mn/web"),
            (bot_path, "https://amd64.ssss.nyc.mn/bot")
        ]
        if NEZHA_SERVER and NEZHA_KEY:
            if NEZHA_PORT:
                files_to_download.insert(0, (npm_path, "https://amd64.ssss.nyc.mn/agent"))
            else:
                files_to_download.insert(0, (php_path, "https://amd64.ssss.nyc.mn/v1"))
    
    if not files_to_download:
        logger.error("未找到适合当前架构的文件")
        return
    
    # 下载文件
    for filepath, url in files_to_download:
        if not await download_file(url, filepath):
            logger.error(f"下载 {filepath.name} 失败")
            return
    
    # 运行哪吒监控
    global nezha_process
    if NEZHA_SERVER and NEZHA_KEY:
        if not NEZHA_PORT:
            port = NEZHA_SERVER.split(':')[-1] if ':' in NEZHA_SERVER else ''
            tls_ports = {'443', '8443', '2096', '2087', '2083', '2053'}
            nezhatls = 'true' if port in tls_ports else 'false'
            
            config_yaml = f"""client_secret: {NEZHA_KEY}
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
tls: {nezhatls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {UUID}"""
            
            config_yaml_path = file_path / 'config.yaml'
            async with aiofiles.open(config_yaml_path, 'w', encoding='utf-8') as f:
                await f.write(config_yaml)
            
            cmd = [str(php_path), "-c", str(config_yaml_path)]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                stdin=asyncio.subprocess.DEVNULL
            )
            nezha_process = process
            process_manager.add_process(process)
            logger.info(f"{php_name} 运行中")
            await asyncio.sleep(1)
        else:
            args = ["-s", f"{NEZHA_SERVER}:{NEZHA_PORT}", "-p", NEZHA_KEY]
            tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
            if NEZHA_PORT in tls_ports:
                args.append("--tls")
            args.extend(["--disable-auto-update", "--report-delay", "4", "--skip-conn", "--skip-procs"])
            
            cmd = [str(npm_path)] + args
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                stdin=asyncio.subprocess.DEVNULL
            )
            nezha_process = process
            process_manager.add_process(process)
            logger.info(f"{npm_name} 运行中")
            await asyncio.sleep(1)
    else:
        logger.info("哪吒监控变量为空，跳过运行")
    
    # 运行Xray
    global xray_process
    cmd = [str(web_path), "-c", str(config_path)]
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        stdin=asyncio.subprocess.DEVNULL
    )
    xray_process = process
    process_manager.add_process(process)
    logger.info(f"{web_name} 运行中")
    await asyncio.sleep(1)
    
    # 运行cloudflared
    global cloudflared_process
    if await aiofiles.os.path.exists(str(bot_path)):
        args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2"]
        
        if ARGO_AUTH and re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
            args.extend(["run", "--token", ARGO_AUTH])
        elif ARGO_AUTH and 'TunnelSecret' in ARGO_AUTH:
            if await aiofiles.os.path.exists(str(tunnel_yaml_path)):
                args.extend(["--config", str(tunnel_yaml_path), "run"])
            else:
                logger.info("等待隧道配置文件生成...")
                await asyncio.sleep(1)
                if await aiofiles.os.path.exists(str(tunnel_yaml_path)):
                    args.extend(["--config", str(tunnel_yaml_path), "run"])
                else:
                    args.extend([
                        "--logfile", str(boot_log_path),
                        "--loglevel", "info",
                        "--url", f"http://localhost:{ARGO_PORT}"
                    ])
        else:
            args.extend([
                "--logfile", str(boot_log_path),
                "--loglevel", "info",
                "--url", f"http://localhost:{ARGO_PORT}"
            ])
        
        cmd = [str(bot_path)] + args
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.DEVNULL
        )
        cloudflared_process = process
        process_manager.add_process(process)
        logger.info(f"{bot_name} 运行中")
        await asyncio.sleep(5)
    
    await asyncio.sleep(2)

def argo_type():
    if not ARGO_AUTH or not ARGO_DOMAIN:
        logger.info("ARGO_DOMAIN 或 ARGO_AUTH 为空，使用快速隧道")
        return
    
    if 'TunnelSecret' in ARGO_AUTH:
        try:
            with open(tunnel_json_path, 'w', encoding='utf-8') as f:
                f.write(ARGO_AUTH)
            
            tunnel_config = json.loads(ARGO_AUTH)
            tunnel_id = tunnel_config.get('TunnelID', '')
            
            tunnel_yaml = f"""tunnel: {tunnel_id}
credentials-file: {tunnel_json_path}
protocol: http2

ingress:
  - hostname: {ARGO_DOMAIN}
    service: http://localhost:{ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
            with open(tunnel_yaml_path, 'w', encoding='utf-8') as f:
                f.write(tunnel_yaml)
            logger.info('隧道YAML配置生成成功')
        except Exception as e:
            logger.error(f'生成隧道配置错误: {e}')
    else:
        logger.info("ARGO_AUTH 不是TunnelSecret格式，使用token连接隧道")

async def extract_domains():
    global argo_domain
    
    if ARGO_AUTH and ARGO_DOMAIN:
        argo_domain = ARGO_DOMAIN
        logger.info(f'使用固定域名: {argo_domain}')
        await generate_links(argo_domain)
    else:
        try:
            if not await aiofiles.os.path.exists(str(boot_log_path)):
                logger.error("boot.log 未找到，等待隧道启动...")
                await asyncio.sleep(3)
                if await aiofiles.os.path.exists(str(boot_log_path)):
                    return await extract_domains()
                return
            
            async with aiofiles.open(boot_log_path, 'r', encoding='utf-8') as f:
                content = await f.read()
            
            domains = re.findall(r'https?://([^ ]*trycloudflare\.com)/?', content)
            
            if domains:
                argo_domain = domains[0]
                logger.info(f'找到临时域名: {argo_domain}')
                await generate_links(argo_domain)
            else:
                logger.info('未找到域名，重启bot以获取Argo域名')
                await aiofiles.os.remove(str(boot_log_path))
                
                # 停止cloudflared进程
                await kill_bot_process()
                await asyncio.sleep(3)
                
                # 重新启动cloudflared
                cmd = f"nohup {bot_path} tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {boot_log_path} --loglevel info --url http://localhost:{ARGO_PORT} >/dev/null 2>&1 &"
                process = await asyncio.create_subprocess_shell(cmd)
                await process.wait()
                logger.info(f"{bot_name} 重新运行中")
                await asyncio.sleep(3)
                await extract_domains()
        except Exception as e:
            logger.error(f'读取boot.log错误: {e}')

async def kill_bot_process():
    try:
        if sys.platform == 'win32':
            process = await asyncio.create_subprocess_shell(
                f"taskkill /f /im {bot_name}.exe",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await process.wait()
        else:
            process = await asyncio.create_subprocess_shell(
                f"pkill -f '[{bot_name[0]}]{bot_name[1:]}'",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await process.wait()
    except Exception:
        pass

async def get_meta_info():
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            response = await client.get('https://ipapi.co/json/')
            if response.status_code == 200:
                data = response.json()
                if data.get('country_code') and data.get('org'):
                    return f"{data['country_code']}_{data['org']}"
    except Exception:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                response = await client.get('http://ip-api.com/json/')
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success' and data.get('countryCode') and data.get('org'):
                        return f"{data['countryCode']}_{data['org']}"
        except Exception:
            pass
    return '未知'

async def generate_links(domain: str):
    global argo_domain, sub_content
    argo_domain = domain
    
    ISP = await get_meta_info()
    node_name = f"{NAME}-{ISP}" if NAME else ISP
    
    vmess_config = {
        "v": "2",
        "ps": node_name,
        "add": CFIP,
        "port": CFPORT,
        "id": UUID,
        "aid": "0",
        "scy": "none",
        "net": "ws",
        "type": "none",
        "host": argo_domain,
        "path": "/vmess-argo?ed=2560",
        "tls": "tls",
        "sni": argo_domain,
        "alpn": "",
        "fp": "firefox"
    }
    
    vmess_base64 = base64.b64encode(json.dumps(vmess_config).encode()).decode()
    
    sub_content = f"""vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{node_name}

vmess://{vmess_base64}

trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{node_name}
    """
    
    encoded_content = base64.b64encode(sub_content.encode()).decode()
    print(encoded_content)
    
    async with aiofiles.open(sub_path, 'w', encoding='utf-8') as f:
        await f.write(encoded_content)
    logger.info(f"{sub_path} 保存成功")
    
    await upload_nodes()
    
    return sub_content

async def upload_nodes():
    if UPLOAD_URL and PROJECT_URL:
        subscription_url = f"{PROJECT_URL}/{SUB_PATH}"
        json_data = {"subscription": [subscription_url]}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"{UPLOAD_URL}/api/add-subscriptions",
                    json=json_data,
                    headers={'Content-Type': 'application/json'}
                )
                if response.status_code == 200:
                    logger.info('订阅上传成功')
                    return response
                else:
                    if response.status_code == 400:
                        logger.error('订阅已存在')
                    return None
        except Exception as e:
            logger.error(f'上传订阅失败: {e}')
            return None
    elif UPLOAD_URL:
        if not await aiofiles.os.path.exists(str(list_path)):
            return None
        
        try:
            async with aiofiles.open(list_path, 'r', encoding='utf-8') as f:
                content = await f.read()
            
            nodes = [line for line in content.split('\n') 
                    if re.search(r'(vless|vmess|trojan|hysteria2|tuic)://', line)]
            
            if not nodes:
                return None
            
            json_data = json.dumps({"nodes": nodes})
            
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"{UPLOAD_URL}/api/add-nodes",
                    content=json_data,
                    headers={'Content-Type': 'application/json'}
                )
                if response.status_code == 200:
                    logger.info('节点上传成功')
                    return response
                else:
                    return None
        except Exception:
            return None
    else:
        return None

def clean_files():
    async def cleanup():
        await asyncio.sleep(90)
        
        files_to_delete = [boot_log_path, config_path, web_path, bot_path, monitor_path]
        
        if NEZHA_PORT:
            files_to_delete.append(npm_path)
        elif NEZHA_SERVER and NEZHA_KEY:
            files_to_delete.append(php_path)
        
        for file in files_to_delete:
            try:
                if file.exists():
                    await aiofiles.os.remove(str(file))
            except Exception:
                pass
        
        logger.info('应用正在运行')
        logger.info('感谢使用此脚本，享受吧！')
    
    asyncio.create_task(cleanup())

async def add_visit_task():
    if not AUTO_ACCESS or not PROJECT_URL:
        logger.info("跳过添加自动访问任务")
        return None
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                'https://oooo.serv00.net/add-url',
                json={'url': PROJECT_URL},
                headers={'Content-Type': 'application/json'}
            )
            logger.info("自动访问任务添加成功")
            return response
    except Exception as e:
        logger.error(f"添加自动访问任务失败: {e}")
        return None

async def download_monitor_script() -> bool:
    if not MONITOR_KEY or not MONITOR_SERVER or not MONITOR_URL:
        logger.info("监控环境变量不完整，跳过监控脚本启动")
        return False
    
    monitor_url = "https://raw.githubusercontent.com/mimaldq/cf-vps-monitor/main/cf-vps-monitor.sh"
    logger.info(f"从 {monitor_url} 下载监控脚本")
    
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(monitor_url)
            response.raise_for_status()
            
            async with aiofiles.open(monitor_path, 'wb') as f:
                await f.write(response.content)
            
            monitor_path.chmod(0o755)
            logger.info("监控脚本下载完成")
            return True
    except Exception as e:
        logger.error(f"下载监控脚本失败: {e}")
        return False

async def run_monitor_script():
    if not MONITOR_KEY or not MONITOR_SERVER or not MONITOR_URL:
        return
    
    cmd = [
        str(monitor_path),
        '-i',
        '-k', MONITOR_KEY,
        '-s', MONITOR_SERVER,
        '-u', MONITOR_URL
    ]
    
    logger.info(f"运行监控脚本: {' '.join(cmd)}")
    
    try:
        global monitor_process
        monitor_process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        process_manager.add_process(monitor_process)
        
        async def read_output():
            while True:
                if monitor_process.stdout:
                    try:
                        output = await monitor_process.stdout.readline()
                        if output:
                            logger.info(f"监控脚本输出: {output.decode().strip()}")
                    except Exception:
                        pass
                
                if monitor_process.returncode is not None:
                    code = monitor_process.returncode
                    logger.info(f"监控脚本退出，代码: {code}")
                    if code != 0:
                        logger.info("将在30秒后重启监控脚本...")
                        await asyncio.sleep(30)
                        await run_monitor_script()
                    break
                await asyncio.sleep(0.1)
        
        asyncio.create_task(read_output())
        
    except Exception as e:
        logger.error(f"运行监控脚本错误: {e}")

# ==================== WebSocket 代理实现 (修复弃用问题) ====================
class WebSocketProxy:
    """WebSocket 代理类，专门处理 WebSocket 到 WebSocket 的转发"""
    
    def __init__(self):
        self.active_connections: Dict[str, Any] = {}
        self.connection_counter = 0
    
    async def proxy_websocket(self, request: Request, client_ws: Websocket, target_host: str = "localhost", target_port: int = 3001):
        """代理 WebSocket 连接"""
        connection_id = f"ws_{self.connection_counter}"
        self.connection_counter += 1
        
        # 构建目标 WebSocket URL - 使用 request 对象获取路径
        target_path = request.path
        target_query = request.query_string
        
        target_url = f"ws://{target_host}:{target_port}{target_path}"
        if target_query:
            target_url += f"?{target_query}"
        
        logger.info(f"[{connection_id}] 代理 WebSocket 到: {target_url}")
        
        try:
            # 接受客户端 WebSocket 连接
            await client_ws.accept()
            
            async with ws_connection_lock:
                websocket_connections.add(client_ws)
            
            # 连接到目标 WebSocket 服务器
            target_ws = await websocket_connect(
                target_url,
                extra_headers=dict(request.headers),
                ping_interval=20,
                ping_timeout=20,
                close_timeout=5
            )
            
            self.active_connections[connection_id] = target_ws
            
            # 创建双向转发任务
            client_to_target = asyncio.create_task(
                self.forward_client_to_target(connection_id, client_ws, target_ws)
            )
            target_to_client = asyncio.create_task(
                self.forward_target_to_client(connection_id, client_ws, target_ws)
            )
            
            # 等待任意一个任务完成
            await asyncio.wait(
                [client_to_target, target_to_client],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # 清理
            client_to_target.cancel()
            target_to_client.cancel()
            
        except Exception as e:
            logger.error(f"[{connection_id}] WebSocket 代理错误: {e}")
        finally:
            # 清理连接
            if connection_id in self.active_connections:
                try:
                    await self.active_connections[connection_id].close()
                except:
                    pass
                del self.active_connections[connection_id]
            
            async with ws_connection_lock:
                if client_ws in websocket_connections:
                    websocket_connections.remove(client_ws)
            
            logger.info(f"[{connection_id}] WebSocket 连接已关闭")
    
    async def forward_client_to_target(self, conn_id: str, client_ws: Websocket, target_ws: Any):
        """转发客户端消息到目标服务器"""
        try:
            while True:
                # 接收客户端消息
                try:
                    client_message = await client_ws.recv()
                except Exception as e:
                    logger.debug(f"[{conn_id}] 客户端接收错误: {e}")
                    break
                
                # 转发到目标服务器
                try:
                    if isinstance(client_message, str):
                        await target_ws.send(client_message)
                    else:
                        await target_ws.send(client_message)
                except Exception as e:
                    logger.error(f"[{conn_id}] 目标发送错误: {e}")
                    break
        except Exception as e:
            logger.debug(f"[{conn_id}] 客户端到目标转发错误: {e}")
    
    async def forward_target_to_client(self, conn_id: str, client_ws: Websocket, target_ws: Any):
        """转发目标服务器消息到客户端"""
        try:
            while True:
                # 接收目标服务器消息
                try:
                    target_message = await target_ws.recv()
                except ConnectionClosed:
                    logger.debug(f"[{conn_id}] 目标连接已关闭")
                    break
                except Exception as e:
                    logger.debug(f"[{conn_id}] 目标接收错误: {e}")
                    break
                
                # 转发到客户端
                try:
                    if isinstance(target_message, str):
                        await client_ws.send(target_message)
                    else:
                        await client_ws.send(target_message)
                except Exception as e:
                    logger.error(f"[{conn_id}] 客户端发送错误: {e}")
                    break
        except Exception as e:
            logger.debug(f"[{conn_id}] 目标到客户端转发错误: {e}")

# 创建 WebSocket 代理实例
ws_proxy = WebSocketProxy()

# ==================== Sanic 应用配置 ====================
app = Sanic("XrayProxyServer")

@app.before_server_start
async def setup_server(app, loop):
    """服务器启动前初始化"""
    logger.info("开始服务器初始化...")
    
    # 在后台运行初始化任务
    asyncio.create_task(start_server_init())

async def start_server_init():
    """异步启动所有服务"""
    delete_nodes()
    cleanup_old_files()
    
    argo_type()
    generate_config()
    
    # 下载并运行文件
    await download_files_and_run()
    
    # 等待隧道启动并提取域名
    logger.info('等待隧道启动...')
    await asyncio.sleep(5)
    await extract_domains()
    
    # 添加自动访问任务
    await add_visit_task()
    
    logger.info('服务器初始化完成')
    
    # 启动监控脚本
    await asyncio.sleep(10)
    if await download_monitor_script():
        await run_monitor_script()
    
    # 清理文件
    clean_files()

@app.after_server_start
async def after_start(app, loop):
    """服务器启动后"""
    logger.info(f"Sanic 服务器已启动在端口 {ARGO_PORT}")
    logger.info(f"HTTP 流量 -> localhost:{ARGO_PORT}")
    logger.info(f"Xray WebSocket 流量 -> localhost:3001")
    logger.info(f"WebSocket 代理已就绪")

@app.before_server_stop
async def cleanup_server(app, loop):
    """服务器停止前清理"""
    logger.info("正在关闭应用...")
    global is_running
    is_running = False
    
    # 关闭所有 WebSocket 连接
    logger.info("正在关闭所有 WebSocket 连接...")
    async with ws_connection_lock:
        for ws in websocket_connections:
            try:
                await ws.close()
            except:
                pass
        websocket_connections.clear()
    
    if monitor_process:
        logger.info("正在停止监控脚本...")
        monitor_process.terminate()
    
    process_manager.cleanup()

# ==================== 路由处理 ====================
@app.get("/")
async def serve_index(request: Request):
    """根路由 - 返回 index.html"""
    index_path = Path(__file__).parent / "index.html"
    if index_path.exists():
        return await file(str(index_path))
    return text("Hello world!")

@app.get(f"/{SUB_PATH}")
async def serve_subscription(request: Request):
    """订阅路由"""
    global sub_content
    async with sub_lock:
        if not sub_content:
            # 等待订阅内容生成
            for _ in range(10):
                if sub_content:
                    break
                await asyncio.sleep(1)
            
            if not sub_content:
                return text("订阅未就绪", status=404)
        
        encoded_content = base64.b64encode(sub_content.encode()).decode()
        return text(encoded_content, content_type="text/plain; charset=utf-8")

# Xray WebSocket 相关路径
xray_ws_paths = ["/vless-argo", "/vmess-argo", "/trojan-argo"]

# WebSocket 代理到 Xray - 只有这些路径才进行代理
@app.websocket("/<path:path>")
async def websocket_proxy_handler(request: Request, ws: Websocket, path: str):
    """代理 WebSocket 连接到 Xray"""
    # 检查是否为 Xray 路径
    full_path = f"/{path}"
    if any(full_path.startswith(xray_path) for xray_path in xray_ws_paths):
        await ws_proxy.proxy_websocket(request, ws, "localhost", 3001)
    else:
        await ws.close()

# 健康检查路由
@app.get("/health")
async def health_check(request: Request):
    return text(f"健康\n{time.time()}")

# 状态路由
@app.get("/status")
async def status_check(request: Request):
    global argo_domain, sub_content
    status_info = {
        "status": "运行中",
        "argo_domain": argo_domain,
        "subscription_ready": bool(sub_content),
        "xray_running": xray_process is not None and xray_process.returncode is None,
        "cloudflared_running": cloudflared_process is not None and cloudflared_process.returncode is None,
        "active_websocket_connections": len(websocket_connections),
        "port": ARGO_PORT
    }
    return text(json.dumps(status_info, indent=2, ensure_ascii=False))

# WebSocket 连接统计
@app.get("/ws-stats")
async def websocket_stats(request: Request):
    stats = {
        "active_connections": len(websocket_connections),
        "connection_ids": list(ws_proxy.active_connections.keys())
    }
    return text(json.dumps(stats, indent=2, ensure_ascii=False))

# ==================== 主入口 ====================
if __name__ == "__main__":
    # 信号处理
    def signal_handler(sig, frame):
        logger.info("收到关闭信号，正在清理...")
        global is_running
        is_running = False
        
        if monitor_process:
            monitor_process.terminate()
        
        process_manager.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info(f"正在启动 Sanic 服务器在端口 {ARGO_PORT}")
    logger.info(f"HTTP 服务运行在内部端口: {PORT}")
    logger.info(f"WebSocket 代理已就绪，处理 Xray 流量")
    logger.info(f"Xray WebSocket 路径: {', '.join(xray_ws_paths)}")
    
    # 运行 Sanic 应用
    app.run(
        host="0.0.0.0",
        port=ARGO_PORT,
        debug=False,
        access_log=False,
        auto_reload=False,
        workers=1
    )
