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
from pathlib import Path
from urllib.parse import quote
import requests
import uuid as uuid_module
import yaml
from typing import Dict, Optional, Any, Union
from contextlib import asynccontextmanager

# FastAPI和Starlette
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# httpx作为HTTP客户端
import httpx

# WebSocket客户端（使用websockets库）
import websockets
from websockets.exceptions import ConnectionClosed

import uvicorn

# 设置日志 - 中文
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
CFPORT = os.getenv('CFPORT', '443')
NAME = os.getenv('NAME', '')
MONITOR_KEY = os.getenv('MONITOR_KEY', '')
MONITOR_SERVER = os.getenv('MONITOR_SERVER', '')
MONITOR_URL = os.getenv('MONITOR_URL', '')

# 创建运行文件夹
file_path = Path(FILE_PATH)
file_path.mkdir(exist_ok=True, parents=True)

# 全局变量
monitor_process = None
processes = []
sub_txt = ""
argo_domain = ""
sub_encoded = ""
app_started = False

# 连接管理器
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_counter = {
            "vless-argo": 0,
            "vmess-argo": 0,
            "trojan-argo": 0,
            "total": 0
        }
    
    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
    
    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
    
    def increment_counter(self, protocol: str):
        self.connection_counter[protocol] += 1
        self.connection_counter["total"] += 1
        
        # 每100个连接打印一次统计
        if self.connection_counter["total"] % 100 == 0:
            logger.info(
                f"连接统计: VLESS={self.connection_counter['vless-argo']}, "
                f"VMESS={self.connection_counter['vmess-argo']}, "
                f"Trojan={self.connection_counter['trojan-argo']}, "
                f"总计={self.connection_counter['total']}"
            )
    
    def decrement_counter(self, protocol: str):
        self.connection_counter[protocol] -= 1
        self.connection_counter["total"] -= 1

manager = ConnectionManager()

# 进程管理器
class ProcessManager:
    def __init__(self):
        self.processes = []
    
    def add_process(self, process):
        self.processes.append(process)
    
    def cleanup(self):
        for process in self.processes:
            try:
                if process.poll() is None:  # 进程还在运行
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
            except Exception as e:
                logger.error(f"杀死进程时出错: {e}")

process_manager = ProcessManager()

# 工具函数
def generate_random_name(length=6):
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

# ========== 服务器初始化函数 ==========
def cleanup_old_files():
    """清理历史文件"""
    try:
        for file in file_path.iterdir():
            try:
                if file.is_file():
                    file.unlink()
            except Exception:
                pass  # 忽略错误
    except Exception as e:
        logger.error(f"清理旧文件时出错: {e}")

def generate_config():
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
                "port": 3001,
                "protocol": "vless",
                "settings": {
                    "clients": [{
                        "id": UUID,
                        "flow": "xtls-rprx-vision"
                    }],
                    "decryption": "none",
                    "fallbacks": [
                        {"dest": 3002 },
                        {"path": "/vless-argo", "dest": 3003 },
                        {"path": "/vmess-argo", "dest": 3004 },
                        {"path": "/trojan-argo", "dest": 3005 }
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

def get_system_architecture():
    """获取系统架构"""
    arch = os.uname().machine.lower() if hasattr(os, 'uname') else os.environ.get('HOSTTYPE', '')
    if 'arm' in arch or 'aarch64' in arch:
        return 'arm'
    return 'amd'

def download_file(url, filepath):
    """下载文件"""
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        
        # 设置可执行权限
        filepath.chmod(0o755)
        return True
    except Exception as e:
        logger.error(f"下载 {url} 失败: {e}")
        return False

def get_files_for_architecture(architecture):
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

def run_process(cmd, detach=False):
    """运行进程"""
    try:
        if detach:
            # 分离进程运行
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            process_manager.add_process(process)
            return process
        else:
            # 阻塞运行
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result
    except Exception as e:
        logger.error(f"运行命令 {cmd} 出错: {e}")
        return None

def download_files_and_run():
    """下载并运行依赖文件"""
    architecture = get_system_architecture()
    files_to_download = get_files_for_architecture(architecture)
    
    if not files_to_download:
        logger.error("找不到适合当前架构的文件")
        return
    
    # 下载文件
    for filepath, url in files_to_download:
        if not download_file(url, filepath):
            logger.error(f"下载 {filepath.name} 失败")
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
            cmd = f"{php_path} -c {file_path / 'config.yaml'}"
            run_process(cmd, detach=True)
            time.sleep(1)
        else:
            # 哪吒v0
            args = [
                "-s", f"{NEZHA_SERVER}:{NEZHA_PORT}",
                "-p", NEZHA_KEY
            ]
            
            tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
            if NEZHA_PORT in tls_ports:
                args.append("--tls")
            
            args.extend(["--disable-auto-update", "--report-delay", "4", "--skip-conn", "--skip-procs"])
            
            cmd = f"{npm_path} {' '.join(args)}"
            run_process(cmd, detach=True)
            time.sleep(1)
    
    # 运行Xray
    cmd = f"{web_path} -c {config_path}"
    run_process(cmd, detach=True)
    time.sleep(1)
    
    # 运行cloudflared
    if bot_path.exists():
        args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2"]
        
        if ARGO_AUTH and ARGO_AUTH.strip() and len(ARGO_AUTH.strip()) >= 120 and len(ARGO_AUTH.strip()) <= 250:
            args.extend(["run", "--token", ARGO_AUTH.strip()])
        elif ARGO_AUTH and 'TunnelSecret' in ARGO_AUTH:
            # 确保隧道配置文件存在
            if not tunnel_yaml_path.exists():
                time.sleep(1)
            
            args.extend(["--config", str(tunnel_yaml_path), "run"])
        else:
            args.extend([
                "--logfile", str(boot_log_path),
                "--loglevel", "info",
                "--url", f"http://localhost:{ARGO_PORT}"
            ])
        
        cmd = f"{bot_path} {' '.join(args)}"
        run_process(cmd, detach=True)
        time.sleep(5)
    
    time.sleep(2)

def argo_type():
    """配置Argo隧道类型"""
    if not ARGO_AUTH or not ARGO_DOMAIN:
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
    service: http://localhost:{ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
            with open(tunnel_yaml_path, 'w', encoding='utf-8') as f:
                f.write(tunnel_yaml)
        except Exception as e:
            logger.error(f'生成隧道配置错误: {e}')

def extract_domains():
    """提取隧道域名"""
    global argo_domain
    
    if ARGO_AUTH and ARGO_DOMAIN:
        argo_domain = ARGO_DOMAIN
        logger.info(f'使用固定域名: {argo_domain}')
        generate_links(argo_domain)
    else:
        try:
            if not boot_log_path.exists():
                logger.error("boot.log 文件不存在")
                return
            
            with open(boot_log_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import re
            domains = re.findall(r'https?://([^ ]*trycloudflare\.com)', content)
            
            if domains:
                argo_domain = domains[0]
                logger.info(f'找到临时域名: {argo_domain}')
                generate_links(argo_domain)
            else:
                logger.info('未找到域名，重新运行bot以获取Argo域名')
                boot_log_path.unlink(missing_ok=True)
                
                # 停止现有的cloudflared进程
                kill_bot_process()
                time.sleep(3)
                
                # 重新启动cloudflared
                cmd = f"nohup {bot_path} tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {boot_log_path} --loglevel info --url http://localhost:{ARGO_PORT} >/dev/null 2>&1 &"
                run_process(cmd, detach=True)
                time.sleep(3)
                extract_domains()
        except Exception as e:
            logger.error(f'读取boot.log错误: {e}')

def kill_bot_process():
    """停止bot进程"""
    try:
        if sys.platform == 'win32':
            subprocess.run(f"taskkill /f /im {bot_name}.exe", 
                          shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(f"pkill -f '[{bot_name[0]}]{bot_name[1:]}'",
                          shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass  # 忽略错误

def get_meta_info_sync():
    """获取ISP信息（同步版本）- 根据Node.js代码修复"""
    try:
        # 尝试第一个API: ipapi.co
        response1 = requests.get('https://ipapi.co/json/', timeout=5)
        if response1.status_code == 200:
            data1 = response1.json()
            country_code = data1.get('country_code')
            org = data1.get('org')
            if country_code and org:
                # 清理org名称，移除特殊字符
                org_clean = org.replace(' ', '_').replace('.', '_').replace(',', '_')
                return f"{country_code}_{org_clean}"
    except Exception as e:
        logger.debug(f"ipapi.co请求失败: {e}")
        pass
    
    try:
        # 尝试第二个API: ip-api.com
        response2 = requests.get('http://ip-api.com/json/', timeout=5)
        if response2.status_code == 200:
            data2 = response2.json()
            if data2.get('status') == 'success':
                country_code = data2.get('countryCode')
                org = data2.get('org')
                if country_code and org:
                    # 清理org名称，移除特殊字符
                    org_clean = org.replace(' ', '_').replace('.', '_').replace(',', '_')
                    return f"{country_code}_{org_clean}"
    except Exception as e:
        logger.debug(f"ip-api.com请求失败: {e}")
        pass
    
    # 如果两个API都失败了，尝试获取主机名作为备用方案
    try:
        import socket
        hostname = socket.gethostname()
        return f"Host_{hostname}"
    except Exception:
        pass
    
    return 'Unknown'

def generate_links(domain):
    """生成订阅链接 - 修复格式问题"""
    global sub_txt, argo_domain, sub_encoded
    
    argo_domain = domain
    
    # 使用同步函数获取ISP信息
    ISP = get_meta_info_sync()
    logger.info(f"获取到ISP信息: {ISP}")
    
    # 节点名称生成逻辑与Node.js一致
    if NAME:
        node_name = f"{NAME}-{ISP}"
    else:
        node_name = ISP
    
    logger.info(f"节点名称: {node_name}")
    
    # 生成VMESS配置 - 完全按照Node.js格式
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
        "path": "/vmess-argo",
        "tls": "tls",
        "sni": argo_domain,
        "alpn": "",
        "fp": "firefox"
    }
    
    # 确保JSON格式与Node.js一致（没有额外的空格）
    vmess_json = json.dumps(vmess_config, separators=(',', ':'))
    vmess_base64 = base64.b64encode(vmess_json.encode()).decode()
    
    # URL编码路径参数
    vless_path = quote("/vless-argo?ed=2560")
    trojan_path = quote("/trojan-argo?ed=2560")
    
    # 生成三种协议的配置 - 修复URL编码问题
    # VLESS配置
    vless_config = f"vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path={vless_path}#{quote(node_name)}"
    
    # VMESS配置
    vmess_config_url = f"vmess://{vmess_base64}"
    
    # Trojan配置
    trojan_config = f"trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path={trojan_path}#{quote(node_name)}"
    
    # 组合订阅内容 - 确保格式正确
    sub_txt = f"{vless_config}\n\n{vmess_config_url}\n\n{trojan_config}"
    
    # 将订阅内容进行base64编码
    sub_encoded = base64.b64encode(sub_txt.encode()).decode()
    
    # 打印base64编码的订阅内容到控制台
    logger.info("订阅内容(base64编码):")
    print(sub_encoded)
    print("\n" + "="*60)
    
    # 保存到文件
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(sub_encoded)
    logger.info(f"订阅已保存到 {sub_path}")
    logger.info(f"节点域名: {argo_domain}")
    logger.info(f"节点名称: {node_name}")
    
    return sub_txt

def upload_nodes():
    """上传节点或订阅"""
    if UPLOAD_URL and PROJECT_URL:
        subscription_url = f"{PROJECT_URL}/{SUB_PATH}"
        json_data = {
            "subscription": [subscription_url]
        }
        try:
            response = requests.post(
                f"{UPLOAD_URL}/api/add-subscriptions",
                json=json_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            if response.status_code == 200:
                logger.info('订阅上传成功')
                return response
            else:
                logger.error(f'订阅上传失败，状态码: {response.status_code}')
                return None
        except Exception as e:
            logger.error(f'订阅上传失败: {e}')
            return None
    else:
        return None

def add_visit_task():
    """添加自动访问任务"""
    if not AUTO_ACCESS or not PROJECT_URL:
        logger.info("跳过自动访问任务")
        return None
    
    try:
        response = requests.post(
            'https://oooo.serv00.net/add-url',
            json={'url': PROJECT_URL},
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        logger.info("自动访问任务添加成功")
        return response
    except Exception as e:
        logger.error(f"添加自动访问任务失败: {e}")
        return None

# ========== 应用生命周期管理 ==========
async def startup():
    """应用启动时执行"""
    logger.info("开始服务器初始化...")
    
    # 创建文件夹
    logger.info(f"创建文件夹: {FILE_PATH}")
    
    # 清理旧文件
    cleanup_old_files()
    
    # 配置Argo隧道
    argo_type()
    
    # 生成Xray配置
    generate_config()
    logger.info("Xray配置文件生成完成")
    
    # 下载并运行依赖文件（在新线程中）
    thread = threading.Thread(target=download_files_and_run, daemon=True)
    thread.start()
    
    # 等待隧道启动
    logger.info("等待隧道启动...")
    await asyncio.sleep(5)
    
    # 提取域名
    extract_domains()
    
    # 添加上传任务
    if AUTO_ACCESS and PROJECT_URL:
        visit_thread = threading.Thread(target=add_visit_task, daemon=True)
        visit_thread.start()
    
    logger.info("服务器初始化完成")
    
    # 启动监控脚本（延迟10秒）
    async def start_monitor():
        await asyncio.sleep(10)
        await download_and_run_monitor()
    
    asyncio.create_task(start_monitor())

async def shutdown():
    """应用关闭时执行"""
    logger.info("服务器关闭，清理进程...")
    
    if monitor_process and monitor_process.poll() is None:
        logger.info("停止监控脚本...")
        monitor_process.terminate()
    
    process_manager.cleanup()
    
    logger.info("清理完成")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理器"""
    # 启动
    await startup()
    yield
    # 关闭
    await shutdown()

# ========== FastAPI应用 ==========
app = FastAPI(
    title="Proxy Server", 
    version="1.0.0",
    lifespan=lifespan
)

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== FastAPI路由 ==========

@app.get("/")
async def root():
    """根路径"""
    index_path = Path(__file__).parent / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    
    # 如果没有index.html，返回基本信息
    return JSONResponse({
        "message": "Proxy Server is running",
        "version": "1.0.0",
        "subscription": f"http://localhost:{ARGO_PORT}/{SUB_PATH}",
        "websocket_endpoints": [
            "/vless-argo",
            "/vmess-argo",
            "/trojan-argo"
        ]
    })

@app.get(f"/{SUB_PATH}")
async def get_subscription():
    """获取订阅内容"""
    global sub_encoded
    
    if not sub_encoded:
        # 如果没有订阅内容，尝试从文件读取
        try:
            if sub_path.exists():
                with open(sub_path, 'r', encoding='utf-8') as f:
                    sub_encoded = f.read()
                    logger.info(f"从文件读取订阅内容，长度: {len(sub_encoded)}")
            else:
                logger.warning("订阅文件不存在")
                return PlainTextResponse(
                    content="Subscription not ready yet. Please wait a moment and try again.",
                    status_code=503
                )
        except Exception as e:
            logger.error(f"读取订阅文件失败: {e}")
            return PlainTextResponse(
                content="Subscription not ready yet. Please wait a moment and try again.",
                status_code=503
            )
    
    # 验证sub_encoded是否为有效的base64
    try:
        test = base64.b64decode(sub_encoded)
        logger.info(f"返回订阅内容，长度: {len(sub_encoded)}")
        # 返回base64编码的内容
        return PlainTextResponse(content=sub_encoded)
    except Exception as e:
        logger.error(f"订阅内容base64解码失败: {e}")
        # 如果base64解码失败，返回原始文本作为备份
        if sub_txt:
            return PlainTextResponse(content=sub_txt)
        else:
            return PlainTextResponse(
                content="Subscription not ready yet. Please wait a moment and try again.",
                status_code=503
            )

@app.get("/stats")
async def get_stats():
    """获取统计信息"""
    return JSONResponse(manager.connection_counter)

@app.get("/health")
async def health_check():
    """健康检查"""
    return JSONResponse({"status": "healthy", "timestamp": time.time()})

@app.websocket("/vless-argo")
async def vless_websocket(websocket: WebSocket):
    """VLESS协议WebSocket代理"""
    await handle_proxy_websocket(websocket, "vless-argo", 3003)

@app.websocket("/vmess-argo")
async def vmess_websocket(websocket: WebSocket):
    """VMESS协议WebSocket代理"""
    await handle_proxy_websocket(websocket, "vmess-argo", 3004)

@app.websocket("/trojan-argo")
async def trojan_websocket(websocket: WebSocket):
    """Trojan协议WebSocket代理"""
    await handle_proxy_websocket(websocket, "trojan-argo", 3005)

async def handle_proxy_websocket(websocket: WebSocket, protocol: str, target_port: int):
    """处理WebSocket代理请求"""
    # 更新连接计数
    manager.increment_counter(protocol)
    
    try:
        # 接受WebSocket连接
        await websocket.accept()
        
        # 构建目标URL
        target_url = f"ws://localhost:{target_port}/{protocol}"
        
        # 使用websockets连接到Xray后端
        async with websockets.connect(
            target_url,
            ping_interval=None  # 禁用ping，由Xray处理
        ) as target_ws:
            
            # 双向转发数据
            await bidirectional_websocket_forward(websocket, target_ws)
            
    except ConnectionClosed:
        # 正常关闭连接
        pass
    except Exception as e:
        logger.debug(f"WebSocket连接异常 ({protocol}): {e}")
    finally:
        # 减少连接计数
        manager.decrement_counter(protocol)

async def bidirectional_websocket_forward(client_ws: WebSocket, target_ws: websockets.WebSocketClientProtocol):
    """双向转发WebSocket消息"""
    # 创建两个任务：客户端到目标和目标到客户端
    client_to_target = asyncio.create_task(forward_client_to_target(client_ws, target_ws))
    target_to_client = asyncio.create_task(forward_target_to_client(target_ws, client_ws))
    
    # 等待任意一个任务完成
    done, pending = await asyncio.wait(
        [client_to_target, target_to_client],
        return_when=asyncio.FIRST_COMPLETED
    )
    
    # 取消另一个任务
    for task in pending:
        task.cancel()
    
    # 等待被取消的任务结束
    for task in pending:
        try:
            await task
        except asyncio.CancelledError:
            pass

async def forward_client_to_target(client_ws: WebSocket, target_ws: websockets.WebSocketClientProtocol):
    """从客户端转发到目标"""
    try:
        while True:
            # 从客户端接收消息
            data = await client_ws.receive()
            
            if data["type"] == "websocket.receive":
                if "text" in data:
                    await target_ws.send(data["text"])
                elif "bytes" in data:
                    await target_ws.send(data["bytes"])
            elif data["type"] == "websocket.disconnect":
                await target_ws.close()
                break
    except WebSocketDisconnect:
        # 客户端断开连接
        try:
            await target_ws.close()
        except:
            pass
    except Exception as e:
        logger.debug(f"Forward from client error: {e}")

async def forward_target_to_client(target_ws: websockets.WebSocketClientProtocol, client_ws: WebSocket):
    """从目标转发到客户端"""
    try:
        while True:
            # 从目标接收消息
            try:
                message = await target_ws.recv()
                
                if isinstance(message, str):
                    await client_ws.send_text(message)
                elif isinstance(message, bytes):
                    await client_ws.send_bytes(message)
            except websockets.exceptions.ConnectionClosed:
                # 目标断开连接
                break
                
    except Exception as e:
        logger.debug(f"Forward from target error: {e}")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_to_xray(request: Request, path: str):
    """代理HTTP请求到Xray"""
    # 构建目标URL
    target_url = f"http://localhost:3001/{path}"
    query_string = str(request.query_params) if request.query_params else ""
    if query_string:
        target_url += f"?{query_string}"
    
    # 使用httpx转发请求
    try:
        # 获取请求方法和头
        method = request.method
        headers = dict(request.headers)
        
        # 移除不必要的头
        headers.pop('host', None)
        headers.pop('content-length', None)
        
        # 读取请求体
        body = await request.body() if request.method in ["POST", "PUT", "PATCH"] else None
        
        # 使用httpx发送请求到Xray
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.request(
                method=method,
                url=target_url,
                headers=headers,
                content=body,
                follow_redirects=False
            )
            
            # 返回响应
            return PlainTextResponse(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers)
            )
            
    except Exception as e:
        logger.error(f"代理HTTP请求失败: {e}")
        return PlainTextResponse(
            content=f"Bad Gateway: {e}",
            status_code=502
        )

# ========== 监控脚本相关 ==========

async def download_and_run_monitor():
    """下载并运行监控脚本"""
    if not MONITOR_KEY or not MONITOR_SERVER or not MONITOR_URL:
        logger.info("监控环境变量不完整，跳过监控脚本启动")
        return
    
    monitor_url = "https://raw.githubusercontent.com/mimaldq/cf-vps-monitor/main/cf-vps-monitor.sh"
    logger.info(f"从 {monitor_url} 下载监控脚本")
    
    try:
        # 下载监控脚本
        response = requests.get(monitor_url, timeout=30)
        response.raise_for_status()
        
        with open(monitor_path, 'wb') as f:
            f.write(response.content)
        
        monitor_path.chmod(0o755)
        logger.info("监控脚本下载完成")
        
        # 运行监控脚本
        cmd = [
            str(monitor_path),
            '-i',
            '-k', MONITOR_KEY,
            '-s', MONITOR_SERVER,
            '-u', MONITOR_URL
        ]
        
        logger.info("运行监控脚本")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        
        global monitor_process
        monitor_process = process
        
        logger.info("监控脚本已启动")
        
    except Exception as e:
        logger.error(f"下载或运行监控脚本失败: {e}")

# ========== 信号处理和主函数 ==========

def signal_handler(signum, frame):
    """信号处理"""
    logger.info("收到关闭信号，正在清理...")
    
    if monitor_process and monitor_process.poll() is None:
        logger.info("停止监控脚本...")
        monitor_process.terminate()
    
    process_manager.cleanup()
    
    logger.info("程序退出")
    sys.exit(0)

def main():
    """主函数"""
    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 运行FastAPI服务器
    logger.info(f"启动FastAPI服务器，端口: {ARGO_PORT}")
    
    # 打印服务器信息
    print(f"\n{'='*60}")
    print(f"服务器运行在端口 {ARGO_PORT}")
    print(f"订阅地址: http://localhost:{ARGO_PORT}/{SUB_PATH}")
    print(f"WebSocket路径: /vless-argo, /vmess-argo, /trojan-argo")
    print(f"状态统计: http://localhost:{ARGO_PORT}/stats")
    print(f"健康检查: http://localhost:{ARGO_PORT}/health")
    print(f"支持的协议: VLESS, VMESS, Trojan")
    print(f"传输协议: WebSocket over TLS")
    print(f"技术栈: FastAPI + Starlette + websockets + httpx")
    print(f"{'='*60}\n")
    
    # 启动UVicorn服务器
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=ARGO_PORT,
        log_level="info",
        access_log=True
    )

if __name__ == "__main__":
    # 检查依赖库
    try:
        import requests
        import fastapi
        import uvicorn
        import websockets
        import httpx
    except ImportError as e:
        logger.error(f"缺少依赖库: {e}")
        logger.info("请运行: pip install fastapi uvicorn websockets httpx requests pyyaml")
        sys.exit(1)
    
    main()
