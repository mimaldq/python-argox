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
import socket
import re
import platform
from pathlib import Path
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime

import requests
from aiohttp import web, ClientSession, ClientTimeout, WSMsgType

# ==================== 配置和日志 ====================

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

@dataclass
class Config:
    """配置类，对应Node.js的环境变量"""
    UPLOAD_URL: str = os.environ.get('UPLOAD_URL', '')
    PROJECT_URL: str = os.environ.get('PROJECT_URL', '')
    AUTO_ACCESS: bool = os.environ.get('AUTO_ACCESS', 'false').lower() == 'true'
    FILE_PATH: str = os.environ.get('FILE_PATH', './tmp')
    SUB_PATH: str = os.environ.get('SUB_PATH', 'sub')
    PORT: int = int(os.environ.get('SERVER_PORT', os.environ.get('PORT', '3000')))
    UUID: str = os.environ.get('UUID', 'e2cae6af-5cdd-fa48-4137-ad3e617fbab0')
    NEZHA_SERVER: str = os.environ.get('NEZHA_SERVER', '')
    NEZHA_PORT: str = os.environ.get('NEZHA_PORT', '')
    NEZHA_KEY: str = os.environ.get('NEZHA_KEY', '')
    ARGO_DOMAIN: str = os.environ.get('ARGO_DOMAIN', '')
    ARGO_AUTH: str = os.environ.get('ARGO_AUTH', '')
    ARGO_PORT: int = int(os.environ.get('ARGO_PORT', '7860'))
    CFIP: str = os.environ.get('CFIP', 'cdns.doon.eu.org')
    CFPORT: int = int(os.environ.get('CFPORT', '443'))
    NAME: str = os.environ.get('NAME', '')
    MONITOR_KEY: str = os.environ.get('MONITOR_KEY', '')
    MONITOR_SERVER: str = os.environ.get('MONITOR_SERVER', '')
    MONITOR_URL: str = os.environ.get('MONITOR_URL', '')

config = Config()

# ==================== 全局变量 ====================

# 文件路径
FILE_PATH = Path(config.FILE_PATH)

# 随机文件名
npm_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
web_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
bot_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
php_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(6))

npm_path = FILE_PATH / npm_name
web_path = FILE_PATH / web_name
bot_path = FILE_PATH / bot_name
php_path = FILE_PATH / php_name
monitor_path = FILE_PATH / 'cf-vps-monitor.sh'
sub_path = FILE_PATH / 'sub.txt'
list_path = FILE_PATH / 'list.txt'
boot_log_path = FILE_PATH / 'boot.log'
config_path = FILE_PATH / 'config.json'
nezha_config_path = FILE_PATH / 'config.yaml'
tunnel_json_path = FILE_PATH / 'tunnel.json'
tunnel_yaml_path = FILE_PATH / 'tunnel.yml'

# 全局状态
subscription = ""
argo_domain = ""
monitor_process: Optional[subprocess.Popen] = None
xray_process: Optional[subprocess.Popen] = None
cloudflared_process: Optional[subprocess.Popen] = None
nezha_process: Optional[subprocess.Popen] = None
proxy_server: Optional[web.AppRunner] = None
internal_server: Optional[web.AppRunner] = None

# 监控重启计数
monitor_restart_count = 0
MAX_RESTART_ATTEMPTS = 10
RESTART_DELAY = 30

# ==================== 工具函数 ====================

def create_directories():
    """创建运行文件夹"""
    if not FILE_PATH.exists():
        FILE_PATH.mkdir(parents=True)
        logger.info(f"{FILE_PATH} is created")
    else:
        logger.info(f"{FILE_PATH} already exists")

def generate_random_name(length=6):
    """生成随机6位字符文件名"""
    characters = 'abcdefghijklmnopqrstuvwxyz'
    return ''.join(random.choice(characters) for _ in range(length))

def get_system_architecture():
    """判断系统架构"""
    arch = platform.machine().lower()
    if 'arm' in arch or 'arm64' in arch or 'aarch64' in arch:
        return 'arm'
    return 'amd'

# ==================== 核心功能函数 ====================

def delete_nodes():
    """如果订阅器上存在历史运行节点则先删除"""
    try:
        if not config.UPLOAD_URL:
            return
        if not sub_path.exists():
            return
        
        file_content = sub_path.read_text(encoding='utf-8')
        decoded = base64.b64decode(file_content).decode('utf-8')
        nodes = [line for line in decoded.split('\n') 
                if re.search(r'(vless|vmess|trojan|hysteria2|tuic)://', line)]
        
        if not nodes:
            return
        
        data = json.dumps({'nodes': nodes})
        headers = {'Content-Type': 'application/json'}
        
        requests.post(f'{config.UPLOAD_URL}/api/delete-nodes', 
                     data=data, headers=headers, timeout=10)
    except Exception as e:
        logger.debug(f"删除历史节点失败: {e}")

def cleanup_old_files():
    """清理历史文件"""
    try:
        for item in FILE_PATH.iterdir():
            if item.is_file():
                try:
                    item.unlink()
                except:
                    pass
    except:
        pass

def generate_config():
    """生成xray配置文件"""
    config_data = {
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
                        "id": config.UUID,
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
                    "clients": [{"id": config.UUID}],
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
                    "clients": [{"id": config.UUID, "level": 0}],
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
                    "clients": [{"id": config.UUID, "alterId": 0}]
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
                    "clients": [{"password": config.UUID}]
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
        json.dump(config_data, f, indent=2)
    
    logger.info("Xray配置文件生成完成")

def download_file(url: str, file_path: Path) -> bool:
    """下载文件"""
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        
        # 设置执行权限
        os.chmod(file_path, 0o775)
        logger.info(f"下载成功: {file_path.name}")
        return True
    except Exception as e:
        logger.error(f"下载失败 {file_path.name}: {e}")
        return False

def get_files_for_architecture(architecture: str) -> List[Dict[str, Any]]:
    """根据系统架构返回对应的url"""
    base_files = []
    
    if architecture == 'arm':
        base_files = [
            {'path': web_path, 'url': "https://arm64.ssss.nyc.mn/web"},
            {'path': bot_path, 'url': "https://arm64.ssss.nyc.mn/bot"}
        ]
    else:
        base_files = [
            {'path': web_path, 'url': "https://amd64.ssss.nyc.mn/web"},
            {'path': bot_path, 'url': "https://amd64.ssss.nyc.mn/bot"}
        ]
    
    if config.NEZHA_SERVER and config.NEZHA_KEY:
        if config.NEZHA_PORT:
            npm_url = "https://arm64.ssss.nyc.mn/agent" if architecture == 'arm' else "https://amd64.ssss.nyc.mn/agent"
            base_files.insert(0, {'path': npm_path, 'url': npm_url})
        else:
            php_url = "https://arm64.ssss.nyc.mn/v1" if architecture == 'arm' else "https://amd64.ssss.nyc.mn/v1"
            base_files.insert(0, {'path': php_path, 'url': php_url})
    
    return base_files

def authorize_files(file_paths: List[Path]):
    """授权文件"""
    for file_path in file_paths:
        if file_path.exists():
            os.chmod(file_path, 0o775)
            logger.info(f"设置权限成功: {file_path.name}")

def run_process(command: List[str], name: str, detach: bool = True) -> Optional[subprocess.Popen]:
    """运行进程"""
    try:
        if detach:
            process = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
        else:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        
        logger.info(f"{name} 运行中 (PID: {process.pid})")
        time.sleep(1)
        return process
    except Exception as e:
        logger.error(f"运行 {name} 错误: {e}")
        return None

def argo_type():
    """获取固定隧道json"""
    if not config.ARGO_AUTH or not config.ARGO_DOMAIN:
        logger.info("ARGO_DOMAIN 或 ARGO_AUTH 为空，使用快速隧道")
        return
    
    if 'TunnelSecret' in config.ARGO_AUTH:
        try:
            with open(tunnel_json_path, 'w', encoding='utf-8') as f:
                f.write(config.ARGO_AUTH)
            
            tunnel_config = json.loads(config.ARGO_AUTH)
            tunnel_id = tunnel_config.get('TunnelID', '')
            
            tunnel_yaml = f"""tunnel: {tunnel_id}
credentials-file: {tunnel_json_path}
protocol: http2

ingress:
  - hostname: {config.ARGO_DOMAIN}
    service: http://localhost:{config.ARGO_PORT}
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

def get_meta_info():
    """获取isp信息"""
    try:
        response = requests.get('https://ipapi.co/json/', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('country_code') and data.get('org'):
                return f"{data['country_code']}_{data['org']}"
    except:
        try:
            response = requests.get('http://ip-api.com/json/', timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success' and data.get('countryCode') and data.get('org'):
                    return f"{data['countryCode']}_{data['org']}"
        except:
            pass
    
    return 'Unknown'

async def extract_domains():
    """获取临时隧道domain"""
    global argo_domain
    
    if config.ARGO_AUTH and config.ARGO_DOMAIN:
        argo_domain = config.ARGO_DOMAIN
        logger.info(f'使用固定域名: {argo_domain}')
        await generate_links(argo_domain)
        return
    
    try:
        if not boot_log_path.exists():
            logger.error('boot.log文件不存在')
            await restart_cloudflared()
            return
        
        with open(boot_log_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        domain_match = re.search(r'https?://([^ ]*trycloudflare\.com)/?', content)
        if domain_match:
            argo_domain = domain_match.group(1)
            logger.info(f'找到临时域名: {argo_domain}')
            await generate_links(argo_domain)
        else:
            logger.info('未找到域名，重新运行bot以获取Argo域名')
            boot_log_path.unlink(missing_ok=True)
            await kill_bot_process()
            await asyncio.sleep(3)
            
            args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", 
                   "--protocol", "http2", "--logfile", str(boot_log_path), 
                   "--loglevel", "info", "--url", f"http://localhost:{config.ARGO_PORT}"]
            
            global cloudflared_process
            cloudflared_process = run_process([str(bot_path)] + args, bot_name)
            if cloudflared_process:
                logger.info(f'{bot_name} 重新运行中')
                await asyncio.sleep(3)
                await extract_domains()
    except Exception as e:
        logger.error(f'读取boot.log错误: {e}')

async def kill_bot_process():
    """停止bot进程"""
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['cmdline'] and bot_name in ' '.join(proc.info['cmdline']):
                    proc.terminate()
                    proc.wait(timeout=5)
            except:
                pass
    except:
        # 如果psutil不可用，使用系统命令
        if platform.system() == 'Windows':
            subprocess.run(f'taskkill /f /im {bot_name} > nul 2>&1', shell=True)
        else:
            subprocess.run(f'pkill -f "[{bot_name[0]}]{bot_name[1:]}" > /dev/null 2>&1', shell=True)

async def generate_links(domain: str):
    """生成 list 和 sub 信息"""
    global subscription
    
    isp = await asyncio.get_event_loop().run_in_executor(None, get_meta_info)
    node_name = f"{config.NAME}-{isp}" if config.NAME else isp
    
    vmess_config = {
        "v": "2",
        "ps": node_name,
        "add": config.CFIP,
        "port": config.CFPORT,
        "id": config.UUID,
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
    
    sub_txt = f"""vless://{config.UUID}@{config.CFIP}:{config.CFPORT}?encryption=none&security=tls&sni={domain}&fp=firefox&type=ws&host={domain}&path=%2Fvless-argo%3Fed%3D2560#{node_name}

vmess://{vmess_base64}

trojan://{config.UUID}@{config.CFIP}:{config.CFPORT}?security=tls&sni={domain}&fp=firefox&type=ws&host={domain}&path=%2Ftrojan-argo%3Fed%3D2560#{node_name}
"""
    
    # 打印 sub.txt 内容到控制台
    encoded = base64.b64encode(sub_txt.encode()).decode()
    logger.info("订阅内容 (base64):")
    logger.info(encoded)
    
    # 保存到文件
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(encoded)
    
    logger.info(f"{sub_path} 保存成功")
    
    # 上传节点
    await upload_nodes()
    
    # 更新全局订阅变量
    subscription = sub_txt

async def upload_nodes():
    """自动上传节点或订阅"""
    if config.UPLOAD_URL and config.PROJECT_URL:
        subscription_url = f"{config.PROJECT_URL}/{config.SUB_PATH}"
        json_data = json.dumps({"subscription": [subscription_url]})
        
        try:
            response = requests.post(f'{config.UPLOAD_URL}/api/add-subscriptions', 
                                   data=json_data, 
                                   headers={'Content-Type': 'application/json'},
                                   timeout=10)
            if response.status_code == 200:
                logger.info('订阅上传成功')
            elif response.status_code == 400:
                logger.info('订阅已存在')
            else:
                logger.error(f'订阅上传失败: {response.status_code}')
        except Exception as e:
            logger.error(f'订阅上传失败: {e}')
    elif config.UPLOAD_URL:
        if not list_path.exists():
            return
        
        try:
            content = list_path.read_text(encoding='utf-8')
        except:
            return
        
        nodes = [line for line in content.split('\n') 
                if re.search(r'(vless|vmess|trojan|hysteria2|tuic)://', line)]
        
        if not nodes:
            return
        
        json_data = json.dumps({"nodes": nodes})
        
        try:
            response = requests.post(f'{config.UPLOAD_URL}/api/add-nodes', 
                                   data=json_data,
                                   headers={'Content-Type': 'application/json'},
                                   timeout=10)
            if response.status_code == 200:
                logger.info('节点上传成功')
        except:
            pass

async def add_visit_task():
    """自动访问项目URL"""
    if not config.AUTO_ACCESS or not config.PROJECT_URL:
        logger.info("跳过添加自动访问任务")
        return
    
    try:
        data = json.dumps({"url": config.PROJECT_URL})
        headers = {'Content-Type': 'application/json'}
        
        response = requests.post('https://oooo.serv00.net/add-url', 
                               data=data, headers=headers, timeout=10)
        logger.info(f"自动访问任务添加成功")
    except Exception as e:
        logger.error(f"添加自动访问任务失败: {e}")

# ==================== 监控脚本相关 ====================

async def download_monitor_script() -> bool:
    """下载监控脚本"""
    if not config.MONITOR_KEY or not config.MONITOR_SERVER or not config.MONITOR_URL:
        logger.info("监控环境变量不完整，跳过监控脚本启动")
        return False
    
    monitor_url = "https://raw.githubusercontent.com/mimaldq/cf-vps-monitor/main/cf-vps-monitor.sh"
    
    logger.info(f"从 {monitor_url} 下载监控脚本")
    
    try:
        response = requests.get(monitor_url, timeout=30)
        response.raise_for_status()
        
        with open(monitor_path, 'wb') as f:
            f.write(response.content)
        
        os.chmod(monitor_path, 0o755)
        logger.info("监控脚本下载完成")
        return True
    except Exception as e:
        logger.error(f"下载监控脚本失败: {e}")
        return False

def run_monitor_script():
    """运行监控脚本"""
    global monitor_process, monitor_restart_count
    
    if not config.MONITOR_KEY or not config.MONITOR_SERVER or not config.MONITOR_URL:
        return
    
    args = [
        '-i',
        '-k', config.MONITOR_KEY,
        '-s', config.MONITOR_SERVER,
        '-u', config.MONITOR_URL
    ]
    
    logger.info(f"运行监控脚本: {monitor_path} {' '.join(args)}")
    
    try:
        monitor_process = subprocess.Popen(
            [str(monitor_path)] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
            start_new_session=True
        )
        
        logger.info(f"监控脚本启动成功，PID: {monitor_process.pid}")
        
        # 监听输出
        def read_output():
            try:
                for line in monitor_process.stdout:
                    logger.info(f"监控脚本输出: {line.strip()}")
            except:
                pass
        
        threading.Thread(target=read_output, daemon=True).start()
        
        # 等待进程退出并重启
        def wait_and_restart():
            nonlocal monitor_restart_count
            returncode = monitor_process.wait()
            logger.info(f"监控脚本退出，代码: {returncode}")
            
            if returncode != 0 and monitor_restart_count < MAX_RESTART_ATTEMPTS:
                monitor_restart_count += 1
                logger.info(f"监控脚本异常退出，将在{RESTART_DELAY}秒后重启")
                time.sleep(RESTART_DELAY)
                run_monitor_script()
        
        threading.Thread(target=wait_and_restart, daemon=True).start()
        
    except Exception as e:
        logger.error(f"运行监控脚本失败: {e}")

async def start_monitor_script():
    """启动监控脚本"""
    if not config.MONITOR_KEY or not config.MONITOR_SERVER or not config.MONITOR_URL:
        logger.info("监控脚本未配置，跳过")
        return
    
    # 等待其他服务启动
    await asyncio.sleep(10)
    
    downloaded = await download_monitor_script()
    if downloaded:
        await asyncio.get_event_loop().run_in_executor(None, run_monitor_script)

# ==================== HTTP服务器和代理 ====================

async def http_handler(request: web.Request) -> web.Response:
    """处理HTTP请求"""
    path = request.path
    
    # 订阅路径
    if path == f"/{config.SUB_PATH}":
        global subscription
        if subscription:
            encoded = base64.b64encode(subscription.encode()).decode()
            return web.Response(text=encoded, content_type='text/plain; charset=utf-8')
        return web.Response(text="订阅尚未生成", status=503)
    
    # 根路径
    if path == "/":
        index_path = Path('index.html')
        if index_path.exists():
            return web.FileResponse(index_path)
        return web.Response(text="Hello world!")
    
    # 其他请求
    return web.Response(text="Not Found", status=404)

async def proxy_handler(request: web.Request) -> web.Response:
    """代理处理器"""
    path = request.path
    
    # 确定目标端口
    if (path.startswith('/vless-argo') or 
        path.startswith('/vmess-argo') or 
        path.startswith('/trojan-argo') or
        path in ['/vless', '/vmess', '/trojan']):
        target_port = 3001  # Xray端口
    else:
        target_port = config.PORT  # HTTP服务器端口
    
    target_url = f'http://localhost:{target_port}{path}'
    
    try:
        # 准备请求数据
        data = await request.read() if request.can_read_body else None
        headers = dict(request.headers)
        headers.pop('Host', None)
        
        timeout = ClientTimeout(total=30)
        async with ClientSession(timeout=timeout) as session:
            async with session.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=data,
                allow_redirects=False
            ) as resp:
                # 创建响应
                response = web.StreamResponse(
                    status=resp.status,
                    reason=resp.reason
                )
                
                # 复制头部
                for name, value in resp.headers.items():
                    if name.lower() not in ('transfer-encoding', 'content-encoding'):
                        response.headers[name] = value
                
                await response.prepare(request)
                
                # 流式传输响应体
                async for chunk in resp.content.iter_any():
                    await response.write(chunk)
                
                await response.write_eof()
                return response
                
    except Exception as e:
        logger.error(f"代理错误: {e}")
        return web.Response(text=f"代理错误: {str(e)}", status=500)

async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
    """WebSocket代理处理器"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    path = request.path
    
    # 确定目标端口
    if (path.startswith('/vless-argo') or 
        path.startswith('/vmess-argo') or 
        path.startswith('/trojan-argo')):
        target_port = 3001
    else:
        await ws.close()
        return ws
    
    target_url = f'ws://localhost:{target_port}{path}'
    
    logger.debug(f"WebSocket代理: {path} -> {target_url}")
    
    try:
        timeout = ClientTimeout(total=30)
        async with ClientSession(timeout=timeout) as session:
            async with session.ws_connect(target_url) as target_ws:
                # 双向转发消息
                async def forward(source, dest):
                    try:
                        async for msg in source:
                            if msg.type == WSMsgType.TEXT:
                                await dest.send_str(msg.data)
                            elif msg.type == WSMsgType.BINARY:
                                await dest.send_bytes(msg.data)
                            elif msg.type == WSMsgType.ERROR:
                                logger.error(f'WebSocket错误: {source.exception()}')
                                break
                            elif msg.type == WSMsgType.CLOSE:
                                await dest.close()
                                break
                    except Exception as e:
                        logger.error(f"转发错误: {e}")
                
                # 同时处理两个方向的转发
                await asyncio.gather(
                    forward(ws, target_ws),
                    forward(target_ws, ws)
                )
                
    except Exception as e:
        logger.error(f"WebSocket代理错误: {e}")
    
    return ws

async def start_internal_server():
    """启动内部HTTP服务器"""
    app = web.Application()
    app.router.add_get("/", http_handler)
    app.router.add_get(f"/{config.SUB_PATH}", http_handler)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', config.PORT)
    await site.start()
    
    global internal_server
    internal_server = runner
    
    logger.info(f"HTTP服务运行在内部端口: {config.PORT}")
    return runner

async def start_proxy_server():
    """启动代理服务器"""
    app = web.Application()
    
    # WebSocket路由
    app.router.add_get('/vless-argo', websocket_handler)
    app.router.add_get('/vmess-argo', websocket_handler)
    app.router.add_get('/trojan-argo', websocket_handler)
    
    # 其他HTTP请求
    app.router.add_route('*', '/{path:.*}', proxy_handler)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', config.ARGO_PORT)
    await site.start()
    
    global proxy_server
    proxy_server = runner
    
    logger.info(f"代理服务器启动在端口: {config.ARGO_PORT}")
    logger.info(f"HTTP流量 -> localhost:{config.PORT}")
    logger.info(f"Xray流量 -> localhost:3001")
    return runner

# ==================== 主运行逻辑 ====================

async def download_files_and_run():
    """下载并运行依赖文件"""
    architecture = get_system_architecture()
    files_to_download = get_files_for_architecture(architecture)
    
    if not files_to_download:
        logger.error(f"无法找到适合当前架构的文件")
        return
    
    # 下载文件
    for file_info in files_to_download:
        await asyncio.get_event_loop().run_in_executor(
            None, download_file, file_info['url'], file_info['path']
        )
    
    # 授权文件
    files_to_authorize = [npm_path, web_path, bot_path, php_path]
    await asyncio.get_event_loop().run_in_executor(
        None, authorize_files, 
        [f['path'] for f in files_to_download if f['path'].exists()]
    )
    
    # 运行哪吒监控
    global nezha_process
    if config.NEZHA_SERVER and config.NEZHA_KEY:
        if not config.NEZHA_PORT:
            # 检测哪吒是否开启TLS
            port = config.NEZHA_SERVER.split(':')[-1] if ':' in config.NEZHA_SERVER else ''
            tls_ports = {'443', '8443', '2096', '2087', '2083', '2053'}
            nezhatls = 'true' if port in tls_ports else 'false'
            
            # 生成 config.yaml
            config_yaml = f"""
client_secret: {config.NEZHA_KEY}
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
server: {config.NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: {nezhatls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {config.UUID}"""
            
            with open(nezha_config_path, 'w', encoding='utf-8') as f:
                f.write(config_yaml)
            
            # 运行 v1
            nezha_process = run_process([str(php_path), "-c", str(nezha_config_path)], php_name)
            await asyncio.sleep(1)
        else:
            args = [
                "-s", f"{config.NEZHA_SERVER}:{config.NEZHA_PORT}",
                "-p", config.NEZHA_KEY
            ]
            
            tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
            if config.NEZHA_PORT in tls_ports:
                args.append("--tls")
            
            args.extend(["--disable-auto-update", "--report-delay", "4", "--skip-conn", "--skip-procs"])
            
            nezha_process = run_process([str(npm_path)] + args, npm_name)
            await asyncio.sleep(1)
    else:
        logger.info('哪吒监控变量为空，跳过运行')
    
    # 运行Xray
    global xray_process
    xray_process = run_process([str(web_path), "-c", str(config_path)], web_name)
    await asyncio.sleep(1)
    
    # 运行cloudflared
    global cloudflared_process
    if bot_path.exists():
        args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2"]
        
        if config.ARGO_AUTH and re.match(r'^[A-Z0-9a-z=]{120,250}$', config.ARGO_AUTH):
            args.extend(["run", "--token", config.ARGO_AUTH])
        elif config.ARGO_AUTH and 'TunnelSecret' in config.ARGO_AUTH:
            if not tunnel_yaml_path.exists():
                logger.info('等待隧道配置文件生成...')
                await asyncio.sleep(1)
            args.extend(["--config", str(tunnel_yaml_path), "run"])
        else:
            args.extend(["--logfile", str(boot_log_path), "--loglevel", "info",
                        "--url", f"http://localhost:{config.ARGO_PORT}"])
        
        cloudflared_process = run_process([str(bot_path)] + args, bot_name)
        
        # 等待隧道启动
        logger.info('等待隧道启动...')
        await asyncio.sleep(5)
    
    await asyncio.sleep(2)

def clean_files():
    """90s后删除相关文件"""
    def cleanup():
        time.sleep(90)
        
        files_to_delete = [
            boot_log_path,
            config_path,
            web_path,
            bot_path,
            monitor_path
        ]
        
        if config.NEZHA_PORT:
            files_to_delete.append(npm_path)
        elif config.NEZHA_SERVER and config.NEZHA_KEY:
            files_to_delete.append(php_path)
        
        # 删除文件
        for file_path in files_to_delete:
            if file_path.exists():
                try:
                    file_path.unlink()
                except:
                    pass
        
        logger.info('应用正在运行')
        logger.info('感谢使用此脚本，享受吧！')
    
    threading.Thread(target=cleanup, daemon=True).start()

async def start_server():
    """主运行逻辑"""
    try:
        logger.info('开始服务器初始化...')
        
        # 在后台线程中执行阻塞操作
        def run_blocking_tasks():
            delete_nodes()
            cleanup_old_files()
            argo_type()
            generate_config()
        
        await asyncio.get_event_loop().run_in_executor(None, run_blocking_tasks)
        
        # 启动服务
        await download_files_and_run()
        
        # 等待隧道启动并获取域名
        await extract_domains()
        
        # 添加访问任务
        await add_visit_task()
        
        logger.info('服务器初始化完成')
        
    except Exception as e:
        logger.error(f'启动过程中错误: {e}')

async def cleanup():
    """清理资源"""
    logger.info("正在清理资源...")
    
    # 停止进程
    processes = [
        (monitor_process, "监控脚本"),
        (xray_process, "Xray"),
        (cloudflared_process, "Cloudflared"),
        (nezha_process, "哪吒监控")
    ]
    
    for process, name in processes:
        if process:
            try:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except:
                    process.kill()
            except:
                pass
    
    # 停止服务器
    if proxy_server:
        await proxy_server.cleanup()
    if internal_server:
        await internal_server.cleanup()
    
    logger.info("清理完成")

# ==================== 主函数 ====================

async def main():
    """主函数"""
    # 创建目录
    create_directories()
    
    # 注册信号处理
    def signal_handler(signum, frame):
        logger.info("收到关闭信号，正在清理...")
        asyncio.create_task(cleanup())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # 启动内部HTTP服务器
        internal_task = asyncio.create_task(start_internal_server())
        
        # 启动代理服务器
        proxy_task = asyncio.create_task(start_proxy_server())
        
        # 启动服务器初始化
        init_task = asyncio.create_task(start_server())
        
        # 启动监控脚本
        monitor_task = asyncio.create_task(start_monitor_script())
        
        # 清理文件
        clean_files()
        
        # 等待所有任务
        await asyncio.gather(internal_task, proxy_task, init_task, monitor_task)
        
        # 保持运行
        await asyncio.Future()  # 永远运行
        
    except asyncio.CancelledError:
        logger.info("服务器被取消")
    except Exception as e:
        logger.error(f"服务器错误: {e}")
    finally:
        await cleanup()

if __name__ == '__main__':
    # 检查Python版本
    if sys.version_info < (3, 7):
        logger.error("需要Python 3.7或更高版本")
        sys.exit(1)
    
    # 运行主程序
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("程序被用户中断")
    except Exception as e:
        logger.error(f"程序运行错误: {e}")
        sys.exit(1)
