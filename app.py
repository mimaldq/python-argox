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
import re
import platform
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any

import aiohttp
from aiohttp import web, WSMsgType
import yaml
import psutil
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# 添加应用启动标志
print(f"\n{'='*60}")
print(f"Application Startup at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'='*60}\n")

# 环境变量配置
UPLOAD_URL = os.getenv('UPLOAD_URL', '')
PROJECT_URL = os.getenv('PROJECT_URL', '')
AUTO_ACCESS = os.getenv('AUTO_ACCESS', 'false').lower() == 'true'
FILE_PATH = os.getenv('FILE_PATH', './tmp')
SUB_PATH = os.getenv('SUB_PATH', 'sub')
# 删除 PORT 环境变量，统一使用 ARGO_PORT
ARGO_PORT = int(os.getenv('ARGO_PORT', '7860'))
UUID = os.getenv('UUID', 'e2cae6af-5cdd-fa48-4137-ad3e617fbab0')
NEZHA_SERVER = os.getenv('NEZHA_SERVER', '')
NEZHA_PORT = os.getenv('NEZHA_PORT', '')
NEZHA_KEY = os.getenv('NEZHA_KEY', '')
ARGO_DOMAIN = os.getenv('ARGO_DOMAIN', '')
ARGO_AUTH = os.getenv('ARGO_AUTH', '')
CFIP = os.getenv('CFIP', 'cdns.doon.eu.org')
CFPORT = os.getenv('CFPORT', '443')
NAME = os.getenv('NAME', '')
MONITOR_KEY = os.getenv('MONITOR_KEY', '')
MONITOR_SERVER = os.getenv('MONITOR_SERVER', '')
MONITOR_URL = os.getenv('MONITOR_URL', '')

# 创建运行文件夹
file_path = Path(FILE_PATH)
file_path.mkdir(exist_ok=True, parents=True)
logger.info(f"{FILE_PATH} created or already exists")

# 全局变量
monitor_process = None
argo_domain_cache = None
sub_content_cache = None
xray_port = 3001  # Xray 服务端口
server_port = ARGO_PORT  # aiohttp 服务端口

class ProcessManager:
    """进程管理器"""
    def __init__(self):
        self.processes: List[subprocess.Popen] = []
    
    def add_process(self, process: subprocess.Popen) -> None:
        """添加进程到管理器"""
        self.processes.append(process)
    
    def cleanup(self) -> None:
        """清理所有进程"""
        for process in self.processes:
            try:
                if process.poll() is None:  # 进程还在运行
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
            except Exception as e:
                logger.error(f"Error killing process: {e}")

process_manager = ProcessManager()

def generate_random_name(length: int = 6) -> str:
    """生成随机文件名"""
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

def cleanup_old_files() -> None:
    """清理历史文件"""
    try:
        for file in file_path.iterdir():
            try:
                if file.is_file() and file.name not in ['app.log', '.env']:
                    file.unlink()
                    logger.debug(f"Deleted old file: {file}")
            except Exception:
                pass  # 忽略错误
    except Exception as e:
        logger.error(f"Error cleaning old files: {e}")

def generate_config() -> None:
    """生成Xray配置文件"""
    config = {
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
                "port": xray_port,
                "protocol": "vless",
                "settings": {
                    "clients": [{
                        "id": UUID,
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
                    "clients": [{"id": UUID}],
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
                    "clients": [{"id": UUID, "level": 0}],
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
                    "clients": [{"id": UUID, "alterId": 0}]
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
                    "clients": [{"password": UUID}]
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
    
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)
    logger.info("Xray config file generated")

def get_system_architecture() -> str:
    """获取系统架构"""
    arch = platform.machine().lower()
    if 'arm' in arch or 'aarch64' in arch:
        return 'arm'
    return 'amd'

async def download_file(url: str, filepath: Path) -> bool:
    """异步下载文件"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                response.raise_for_status()
                
                with open(filepath, 'wb') as f:
                    while True:
                        chunk = await response.content.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)
                
                # 设置可执行权限
                filepath.chmod(0o755)
                logger.info(f"Downloaded {filepath.name} successfully")
                return True
    except Exception as e:
        logger.error(f"Failed to download {url}: {e}")
        return False

def get_files_for_architecture(architecture: str) -> List[Tuple[Path, str]]:
    """根据架构获取要下载的文件列表"""
    base_files = []
    
    if architecture == 'arm':
        base_files = [
            (web_path, "https://arm64.ssss.nyc.mn/web"),
            (bot_path, "https://arm64.ssss.nyc.mn/bot")
        ]
    else:
        base_files = [
            (web_path, "https://amd64.ssss.nyc.mn/web"),
            (bot_path, "https://amd64.ssss.nyc.mn/bot")
        ]
    
    if NEZHA_SERVER and NEZHA_KEY:
        if NEZHA_PORT:
            url = "https://arm64.ssss.nyc.mn/agent" if architecture == 'arm' else "https://amd64.ssss.nyc.mn/agent"
            base_files.insert(0, (npm_path, url))
        else:
            url = "https://arm64.ssss.nyc.mn/v1" if architecture == 'arm' else "https://amd64.ssss.nyc.mn/v1"
            base_files.insert(0, (php_path, url))
    
    return base_files

def run_process(cmd: List[str], detach: bool = False) -> Optional[subprocess.Popen]:
    """运行进程"""
    try:
        if detach:
            # 分离进程运行
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            process_manager.add_process(process)
            return process
        else:
            # 阻塞运行
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result
    except Exception as e:
        logger.error(f"Error running command {cmd}: {e}")
        return None

async def download_files_and_run() -> None:
    """下载并运行依赖文件"""
    architecture = get_system_architecture()
    files_to_download = get_files_for_architecture(architecture)
    
    if not files_to_download:
        logger.error("No files found for current architecture")
        return
    
    # 异步下载所有文件
    download_tasks = []
    for filepath, url in files_to_download:
        download_tasks.append(download_file(url, filepath))
    
    results = await asyncio.gather(*download_tasks, return_exceptions=True)
    
    # 检查下载结果
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Failed to download {files_to_download[i][1]}: {result}")
            return
        elif not result:
            logger.error(f"Failed to download {files_to_download[i][1]}")
            return
    
    # 运行哪吒监控
    if NEZHA_SERVER and NEZHA_KEY:
        if not NEZHA_PORT:
            # 哪吒v1
            port = NEZHA_SERVER.split(':')[-1] if ':' in NEZHA_SERVER else ''
            tls_ports = {'443', '8443', '2096', '2087', '2083', '2053'}
            nezhatls = 'true' if port in tls_ports else 'false'
            
            # 生成config.yaml
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
            
            with open(file_path / 'config.yaml', 'w', encoding='utf-8') as f:
                f.write(config_yaml)
            
            # 运行哪吒v1
            cmd = [str(php_path), "-c", str(file_path / 'config.yaml')]
            run_process(cmd, detach=True)
            logger.info(f"{php_name} is running")
            await asyncio.sleep(1)
        else:
            # 哪吒v0
            args = [
                str(npm_path),
                "-s", f"{NEZHA_SERVER}:{NEZHA_PORT}",
                "-p", NEZHA_KEY
            ]
            
            tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
            if NEZHA_PORT in tls_ports:
                args.append("--tls")
            
            args.extend(["--disable-auto-update", "--report-delay", "4", "--skip-conn", "--skip-procs"])
            
            run_process(args, detach=True)
            logger.info(f"{npm_name} is running")
            await asyncio.sleep(1)
    else:
        logger.info("Nezha variables are empty, skipping")
    
    # 运行Xray
    cmd = [str(web_path), "-c", str(config_path)]
    run_process(cmd, detach=True)
    logger.info(f"{web_name} is running")
    await asyncio.sleep(1)

def argo_type() -> None:
    """配置Argo隧道类型"""
    if not ARGO_AUTH or not ARGO_DOMAIN:
        logger.info("ARGO_DOMAIN or ARGO_AUTH is empty, using quick tunnel")
        return
    
    if 'TunnelSecret' in ARGO_AUTH:
        try:
            # 写入隧道JSON
            with open(tunnel_json_path, 'w', encoding='utf-8') as f:
                f.write(ARGO_AUTH)
            
            # 解析隧道配置
            tunnel_config = json.loads(ARGO_AUTH)
            tunnel_id = tunnel_config.get('TunnelID', '')
            
            # 生成YAML配置
            tunnel_yaml = f"""tunnel: {tunnel_id}
credentials-file: {tunnel_json_path}
protocol: http2

ingress:
  - hostname: {ARGO_DOMAIN}
    service: http://localhost:{server_port}  # 连接到aiohttp服务
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
            with open(tunnel_yaml_path, 'w', encoding='utf-8') as f:
                f.write(tunnel_yaml)
            logger.info('Tunnel YAML config generated successfully')
        except Exception as e:
            logger.error(f'Error generating tunnel config: {e}')
    else:
        logger.info("ARGO_AUTH is not TunnelSecret format, using token connection")

async def extract_domains() -> Optional[str]:
    """异步提取隧道域名"""
    global argo_domain_cache
    
    if argo_domain_cache:
        return argo_domain_cache
    
    if ARGO_AUTH and ARGO_DOMAIN:
        argo_domain_cache = ARGO_DOMAIN
        logger.info(f'Using fixed domain: {argo_domain_cache}')
        return argo_domain_cache
    else:
        try:
            # 启动cloudflared隧道（连接到aiohttp服务端口）
            args = [str(bot_path), "tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2"]
            
            if ARGO_AUTH and ARGO_AUTH.strip() and len(ARGO_AUTH.strip()) >= 120 and len(ARGO_AUTH.strip()) <= 250:
                args.extend(["run", "--token", ARGO_AUTH.strip()])
            elif ARGO_AUTH and 'TunnelSecret' in ARGO_AUTH:
                if not tunnel_yaml_path.exists():
                    logger.info("Waiting for tunnel config file generation...")
                    await asyncio.sleep(1)
                args.extend(["--config", str(tunnel_yaml_path), "run"])
            else:
                args.extend([
                    "--logfile", str(boot_log_path),
                    "--loglevel", "info",
                    "--url", f"http://localhost:{server_port}"  # 连接到aiohttp服务
                ])
            
            run_process(args, detach=True)
            logger.info(f"{bot_name} is running")
            
            # 读取日志文件获取域名（如果是快速隧道）
            if not ARGO_AUTH or not ARGO_DOMAIN:
                await asyncio.sleep(5)
                
                if not boot_log_path.exists():
                    logger.error("boot.log not found")
                    return None
                
                # 读取日志文件获取域名
                max_attempts = 10
                for attempt in range(max_attempts):
                    if boot_log_path.exists():
                        with open(boot_log_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        domains = re.findall(r'https?://([^ ]*trycloudflare\.com)', content)
                        
                        if domains:
                            argo_domain_cache = domains[0]
                            logger.info(f'Found temporary domain: {argo_domain_cache}')
                            return argo_domain_cache
                    
                    logger.info(f"Waiting for domain... attempt {attempt + 1}/{max_attempts}")
                    await asyncio.sleep(2)
                
                logger.error("Failed to extract domain after multiple attempts")
                return None
            
            return argo_domain_cache
            
        except Exception as e:
            logger.error(f'Error extracting domains: {e}')
            return None

async def get_meta_info() -> str:
    """异步获取ISP信息"""
    try:
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get('https://ipapi.co/json/', timeout=3) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('country_code') and data.get('org'):
                            return f"{data['country_code']}_{data['org']}"
            except:
                try:
                    async with session.get('http://ip-api.com/json/', timeout=3) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get('status') == 'success' and data.get('countryCode') and data.get('org'):
                                return f"{data['countryCode']}_{data['org']}"
                except:
                    pass
    except:
        pass
    
    return 'Unknown'

async def generate_links() -> str:
    """异步生成订阅链接"""
    global argo_domain_cache, sub_content_cache
    
    if not argo_domain_cache:
        argo_domain_cache = await extract_domains()
    
    if not argo_domain_cache:
        logger.error("Cannot generate links without domain")
        return ""
    
    ISP = await get_meta_info()
    node_name = f"{NAME}-{ISP}" if NAME else ISP
    
    # 生成VMESS配置
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
        "host": argo_domain_cache,
        "path": "/vless-argo",
        "tls": "tls",
        "sni": argo_domain_cache,
        "alpn": "",
        "fp": "firefox"
    }
    
    vmess_base64 = base64.b64encode(json.dumps(vmess_config).encode()).decode()
    
    sub_txt = f"""
vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain_cache}&fp=firefox&type=ws&host={argo_domain_cache}&path=%2Fvless-argo#{node_name}

vmess://{vmess_base64}

trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain_cache}&fp=firefox&type=ws&host={argo_domain_cache}&path=%2Ftrojan-argo#{node_name}
    """
    
    # 打印base64编码的订阅内容
    encoded_content = base64.b64encode(sub_txt.encode()).decode()
    logger.info(f"Subscription content (base64): {encoded_content}")
    
    # 保存到文件
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(encoded_content)
    logger.info(f"{sub_path} saved successfully")
    
    # 缓存订阅内容
    sub_content_cache = encoded_content
    
    return sub_txt

async def start_server() -> None:
    """异步启动服务器主流程"""
    logger.info('Starting server initialization...')
    
    cleanup_old_files()
    
    argo_type()
    generate_config()
    await download_files_and_run()
    
    # 等待服务启动
    logger.info('Waiting for services startup...')
    await asyncio.sleep(5)
    
    # 生成订阅链接
    await generate_links()
    
    logger.info('Server initialization complete')

async def websocket_proxy(request):
    """WebSocket代理到Xray"""
    ws_to_xray = web.WebSocketResponse()
    await ws_to_xray.prepare(request)
    
    # 目标Xray WebSocket地址
    xray_ws_url = f"ws://127.0.0.1:{xray_port}{request.path}"
    
    logger.info(f"Proxying WebSocket to Xray: {xray_ws_url}")
    
    try:
        # 连接到Xray的WebSocket服务
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(xray_ws_url) as xray_ws:
                
                async def forward_to_xray():
                    async for msg in ws_to_xray:
                        if msg.type == WSMsgType.TEXT:
                            await xray_ws.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY:
                            await xray_ws.send_bytes(msg.data)
                        elif msg.type == WSMsgType.ERROR:
                            break
                        elif msg.type == WSMsgType.CLOSE:
                            await xray_ws.close()
                            break
                
                async def forward_to_client():
                    async for msg in xray_ws:
                        if msg.type == WSMsgType.TEXT:
                            await ws_to_xray.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY:
                            await ws_to_xray.send_bytes(msg.data)
                        elif msg.type == WSMsgType.ERROR:
                            break
                        elif msg.type == WSMsgType.CLOSE:
                            await ws_to_xray.close()
                            break
                
                # 同时转发两个方向的消息
                await asyncio.gather(
                    forward_to_xray(),
                    forward_to_client()
                )
                
    except Exception as e:
        logger.error(f"WebSocket proxy error: {e}")
    
    return ws_to_xray

async def handle_index(request):
    """处理根路由，如果没有index.html则返回Hello world!"""
    index_path = Path(__file__).parent / 'index.html'
    if index_path.exists():
        return web.FileResponse(index_path)
    
    # 如果没有index.html，返回"Hello world!"
    return web.Response(text="Hello world!", content_type='text/plain')

async def handle_subscription(request):
    """处理订阅请求"""
    global sub_content_cache
    
    if sub_content_cache:
        return web.Response(text=sub_content_cache, content_type='text/plain')
    elif sub_path.exists():
        with open(sub_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return web.Response(text=content, content_type='text/plain')
    else:
        return web.Response(
            text="Subscription not ready yet. Please try again in a few seconds.",
            status=503,
            content_type='text/plain'
        )

async def handle_health(request):
    """健康检查端点"""
    health_data = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "xray": web_path.exists(),
            "cloudflared": bot_path.exists() and argo_domain_cache is not None,
            "subscription": sub_path.exists(),
            "aiohttp": True
        },
        "domain": argo_domain_cache,
        "server_port": server_port,
        "xray_port": xray_port,
        "subscription_available": sub_path.exists() or sub_content_cache is not None
    }
    
    return web.json_response(health_data)

def clean_files() -> None:
    """清理文件"""
    def cleanup():
        time.sleep(90)  # 90秒后清理
        
        files_to_delete = [boot_log_path, config_path, monitor_path]
        
        if NEZHA_PORT:
            files_to_delete.append(npm_path)
        elif NEZHA_SERVER and NEZHA_KEY:
            files_to_delete.append(php_path)
        
        # 删除文件（保留web和bot进程文件）
        for file in files_to_delete:
            try:
                if file.exists():
                    file.unlink()
                    logger.debug(f"Cleaned file: {file}")
            except Exception:
                pass  # 忽略错误
        
        logger.info('Application is running')
        logger.info('Thank you for using this script, enjoy!')
    
    # 在新线程中运行清理
    threading.Thread(target=cleanup, daemon=True).start()

def signal_handler(signum, frame):
    """信号处理"""
    logger.info(f"Received shutdown signal {signum}, cleaning up...")
    
    if monitor_process and monitor_process.poll() is None:
        logger.info("Stopping monitor script...")
        monitor_process.terminate()
    
    process_manager.cleanup()
    
    logger.info("Program exited")
    sys.exit(0)

async def start_aiohttp_server():
    """启动aiohttp服务器"""
    app = web.Application()
    
    # 路由配置
    app.router.add_get('/', handle_index)
    app.router.add_get('/health', handle_health)
    app.router.add_get(f'/{SUB_PATH}', handle_subscription)
    
    # WebSocket代理路由
    app.router.add_get('/vless-argo', websocket_proxy)
    app.router.add_get('/vmess-argo', websocket_proxy)
    app.router.add_get('/trojan-argo', websocket_proxy)
    
    # 静态文件服务（可选）
    static_path = Path(__file__).parent / 'static'
    if static_path.exists():
        app.router.add_static('/static/', static_path)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', server_port)
    await site.start()
    
    logger.info(f"HTTP/WebSocket server running on port: {server_port}")
    logger.info(f"Subscription endpoint: /{SUB_PATH}")
    logger.info(f"WebSocket endpoints: /vless-argo, /vmess-argo, /trojan-argo")
    
    return runner

async def main():
    """主异步函数"""
    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 启动服务器初始化
    init_task = asyncio.create_task(start_server())
    
    # 启动aiohttp服务器
    runner = await start_aiohttp_server()
    
    # 等待初始化完成
    await init_task
    
    # 启动清理任务
    clean_files()
    
    # 保持运行
    try:
        while True:
            await asyncio.sleep(3600)  # 每小时检查一次
    except asyncio.CancelledError:
        pass
    finally:
        # 清理
        await runner.cleanup()
        process_manager.cleanup()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
