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
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Any

import aiohttp
import yaml
import psutil
from flask import Flask, request, send_file, Response, jsonify
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

app = Flask(__name__)

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
logger.info(f"{FILE_PATH} created or already exists")

# 全局变量
monitor_process = None
processes = []
argo_domain_cache = None
http_session = None

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

async def get_http_session() -> aiohttp.ClientSession:
    """获取或创建HTTP会话"""
    global http_session
    if http_session is None or http_session.closed:
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(limit=100)
        http_session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
    return http_session

async def cleanup_http_session() -> None:
    """清理HTTP会话"""
    global http_session
    if http_session and not http_session.closed:
        await http_session.close()
        http_session = None

async def delete_nodes() -> None:
    """删除历史节点"""
    if not UPLOAD_URL or not sub_path.exists():
        return
    
    try:
        with open(sub_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
        
        decoded = base64.b64decode(file_content).decode('utf-8')
        protocols = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://']
        nodes = [line for line in decoded.split('\n') 
                if any(proto in line for proto in protocols)]
        
        if not nodes:
            return
        
        payload = {'nodes': nodes}
        session = await get_http_session()
        try:
            async with session.post(
                f"{UPLOAD_URL}/api/delete-nodes",
                json=payload,
                headers={'Content-Type': 'application/json'}
            ) as response:
                if response.status == 200:
                    logger.info("Nodes deleted successfully")
        except Exception as e:
            logger.error(f"Error deleting nodes: {e}")
    except Exception as e:
        logger.error(f"Error in delete_nodes: {e}")

async def cleanup_old_files() -> None:
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
                "port": 3001,
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
                        {"path": "/trojan-argo", dest: 3005}
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
    import platform
    arch = platform.machine().lower()
    if 'arm' in arch or 'aarch64' in arch:
        return 'arm'
    return 'amd'

async def download_file(url: str, filepath: Path) -> bool:
    """异步下载文件"""
    try:
        session = await get_http_session()
        async with session.get(url) as response:
            response.raise_for_status()
            
            # 使用普通文件写入，因为aiofiles不在requirements中
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
    
    # 运行cloudflared
    if bot_path.exists():
        args = [str(bot_path), "tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2"]
        
        if ARGO_AUTH and ARGO_AUTH.strip() and len(ARGO_AUTH.strip()) >= 120 and len(ARGO_AUTH.strip()) <= 250:
            args.extend(["run", "--token", ARGO_AUTH.strip()])
        elif ARGO_AUTH and 'TunnelSecret' in ARGO_AUTH:
            # 确保隧道配置文件存在
            if not tunnel_yaml_path.exists():
                logger.info("Waiting for tunnel config file generation...")
                await asyncio.sleep(1)
            
            args.extend(["--config", str(tunnel_yaml_path), "run"])
        else:
            args.extend([
                "--logfile", str(boot_log_path),
                "--loglevel", "info",
                "--url", f"http://localhost:{ARGO_PORT}"
            ])
        
        run_process(args, detach=True)
        logger.info(f"{bot_name} is running")
        await asyncio.sleep(5)
    
    await asyncio.sleep(2)

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
    service: http://localhost:{ARGO_PORT}
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

async def download_monitor_script() -> bool:
    """下载监控脚本"""
    if not MONITOR_KEY or not MONITOR_SERVER or not MONITOR_URL:
        logger.info("Monitor environment variables incomplete, skipping monitor script")
        return False
    
    monitor_url = "https://raw.githubusercontent.com/mimaldq/cf-vps-monitor/main/cf-vps-monitor.sh"
    logger.info(f"Downloading monitor script from {monitor_url}")
    
    try:
        session = await get_http_session()
        async with session.get(monitor_url) as response:
            response.raise_for_status()
            content = await response.read()
        
        with open(monitor_path, 'wb') as f:
            f.write(content)
        
        monitor_path.chmod(0o755)
        logger.info("Monitor script downloaded successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to download monitor script: {e}")
        return False

def run_monitor_script() -> None:
    """运行监控脚本"""
    if not MONITOR_KEY or not MONITOR_SERVER or not MONITOR_URL:
        return
    
    cmd = [
        str(monitor_path),
        '-i',
        '-k', MONITOR_KEY,
        '-s', MONITOR_SERVER,
        '-u', MONITOR_URL
    ]
    
    logger.info(f"Running monitor script: {' '.join(cmd)}")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        global monitor_process
        monitor_process = process
        process_manager.add_process(process)
        
        # 启动线程读取输出
        def read_output():
            while True:
                output = process.stdout.readline()
                if output:
                    logger.info(f"Monitor output: {output.strip()}")
                error = process.stderr.readline()
                if error:
                    logger.error(f"Monitor error: {error.strip()}")
                
                if process.poll() is not None:
                    break
                time.sleep(0.1)
        
        threading.Thread(target=read_output, daemon=True).start()
        
        # 监控进程状态
        def monitor_process_status():
            process.wait()
            code = process.returncode
            logger.info(f"Monitor script exited with code: {code}")
            if code != 0:
                logger.info("Restarting monitor script in 30 seconds...")
                time.sleep(30)
                run_monitor_script()
        
        threading.Thread(target=monitor_process_status, daemon=True).start()
        
    except Exception as e:
        logger.error(f"Error running monitor script: {e}")

async def extract_domains() -> Optional[str]:
    """提取隧道域名"""
    global argo_domain_cache
    
    if argo_domain_cache:
        return argo_domain_cache
    
    if ARGO_AUTH and ARGO_DOMAIN:
        argo_domain_cache = ARGO_DOMAIN
        logger.info(f'Using fixed domain: {argo_domain_cache}')
        await generate_links(argo_domain_cache)
        return argo_domain_cache
    else:
        try:
            if not boot_log_path.exists():
                logger.error("boot.log not found")
                return None
            
            with open(boot_log_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            domains = re.findall(r'https?://([^ ]*trycloudflare\.com)', content)
            
            if domains:
                argo_domain_cache = domains[0]
                logger.info(f'Found temporary domain: {argo_domain_cache}')
                await generate_links(argo_domain_cache)
                return argo_domain_cache
            else:
                logger.info('Domain not found, restarting bot to get Argo domain')
                boot_log_path.unlink(missing_ok=True)
                
                # 停止现有的cloudflared进程
                await kill_bot_process()
                await asyncio.sleep(3)
                
                # 重新启动cloudflared
                cmd = f"nohup {bot_path} tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {boot_log_path} --loglevel info --url http://localhost:{ARGO_PORT} >/dev/null 2>&1 &"
                subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info(f"{bot_name} restarted")
                await asyncio.sleep(3)
                return await extract_domains()
        except Exception as e:
            logger.error(f'Error reading boot.log: {e}')
            return None

async def kill_bot_process() -> None:
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

async def get_meta_info() -> str:
    """获取ISP信息"""
    session = await get_http_session()
    
    try:
        async with session.get('https://ipapi.co/json/', timeout=aiohttp.ClientTimeout(total=3)) as response:
            if response.status == 200:
                data = await response.json()
                if data.get('country_code') and data.get('org'):
                    return f"{data['country_code']}_{data['org']}"
    except Exception:
        try:
            async with session.get('http://ip-api.com/json/', timeout=aiohttp.ClientTimeout(total=3)) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('status') == 'success' and data.get('countryCode') and data.get('org'):
                        return f"{data['countryCode']}_{data['org']}"
        except Exception:
            pass
    
    return 'Unknown'

async def generate_links(argo_domain: str) -> str:
    """生成订阅链接"""
    ISP = await get_meta_info()
    node_name = f"{NAME}-{ISP}" if NAME else ISP
    
    await asyncio.sleep(2)
    
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
        "host": argo_domain,
        "path": "/vmess-argo?ed=2560",
        "tls": "tls",
        "sni": argo_domain,
        "alpn": "",
        "fp": "firefox"
    }
    
    vmess_base64 = base64.b64encode(json.dumps(vmess_config).encode()).decode()
    
    sub_txt = f"""
vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{node_name}

vmess://{vmess_base64}

trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{node_name}
    """
    
    # 打印base64编码的订阅内容
    encoded_content = base64.b64encode(sub_txt.encode()).decode()
    logger.info(f"Subscription content (base64): {encoded_content}")
    
    # 保存到文件
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(encoded_content)
    logger.info(f"{sub_path} saved successfully")
    
    # 上传节点
    await upload_nodes()
    
    return sub_txt

async def upload_nodes():
    """上传节点或订阅"""
    if UPLOAD_URL and PROJECT_URL:
        subscription_url = f"{PROJECT_URL}/{SUB_PATH}"
        json_data = {
            "subscription": [subscription_url]
        }
        session = await get_http_session()
        try:
            async with session.post(
                f"{UPLOAD_URL}/api/add-subscriptions",
                json=json_data,
                headers={'Content-Type': 'application/json'}
            ) as response:
                if response.status == 200:
                    logger.info('Subscription uploaded successfully')
                    return response
                else:
                    logger.error(f'Upload failed with status code: {response.status}')
                    return None
        except Exception as e:
            logger.error(f'Failed to upload subscription: {e}')
            return None
    elif UPLOAD_URL:
        if not list_path.exists():
            return None
        
        try:
            with open(list_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            protocols = ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://']
            nodes = [line for line in content.split('\n') 
                    if any(proto in line for proto in protocols)]
            
            if not nodes:
                return None
            
            json_data = json.dumps({"nodes": nodes})
            
            session = await get_http_session()
            async with session.post(
                f"{UPLOAD_URL}/api/add-nodes",
                data=json_data,
                headers={'Content-Type': 'application/json'}
            ) as response:
                if response.status == 200:
                    logger.info('Nodes uploaded successfully')
                    return response
                else:
                    logger.error(f'Upload failed with status code: {response.status}')
                    return None
        except Exception as e:
            logger.error(f'Failed to upload nodes: {e}')
            return None
    else:
        return None

def clean_files() -> None:
    """清理文件"""
    def cleanup():
        time.sleep(90)  # 90秒后清理
        
        files_to_delete = [boot_log_path, config_path, web_path, bot_path, monitor_path]
        
        if NEZHA_PORT:
            files_to_delete.append(npm_path)
        elif NEZHA_SERVER and NEZHA_KEY:
            files_to_delete.append(php_path)
        
        # 删除文件
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

async def add_visit_task() -> None:
    """添加自动访问任务"""
    if not AUTO_ACCESS or not PROJECT_URL:
        logger.info("Skipping auto-access task")
        return
    
    session = await get_http_session()
    try:
        async with session.post(
            'https://oooo.serv00.net/add-url',
            json={'url': PROJECT_URL},
            headers={'Content-Type': 'application/json'}
        ) as response:
            if response.status == 200:
                logger.info("Auto-access task added successfully")
            else:
                logger.error(f"Auto-access task failed with status: {response.status}")
    except Exception as e:
        logger.error(f"Failed to add auto-access task: {e}")

@app.route('/')
def index():
    """首页"""
    index_path = Path(__file__).parent / 'index.html'
    if index_path.exists():
        return send_file(index_path)
    return "Hello world!"

@app.route('/health')
def health():
    """健康检查接口"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "xray": web_path.exists(),
            "cloudflared": bot_path.exists(),
            "monitor": monitor_process is not None and monitor_process.poll() is None,
            "sub_file": sub_path.exists()
        }
    })

@app.route(f'/{SUB_PATH}')
def subscription():
    """订阅接口"""
    try:
        if sub_path.exists():
            with open(sub_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return Response(content, mimetype='text/plain; charset=utf-8')
        else:
            return Response("Subscription not ready yet", status=404, mimetype='text/plain')
    except Exception as e:
        logger.error(f"Error reading subscription: {e}")
        return Response(f"Error: {str(e)}", status=500, mimetype='text/plain')

async def start_server() -> None:
    """启动服务器主流程"""
    logger.info('Starting server initialization...')
    
    await delete_nodes()
    await cleanup_old_files()
    
    argo_type()
    generate_config()
    await download_files_and_run()
    
    # 等待隧道启动
    logger.info('Waiting for tunnel startup...')
    await asyncio.sleep(5)
    
    await extract_domains()
    await add_visit_task()
    
    logger.info('Server initialization complete')

def signal_handler(signum, frame):
    """信号处理"""
    logger.info(f"Received shutdown signal {signum}, cleaning up...")
    
    if monitor_process and monitor_process.poll() is None:
        logger.info("Stopping monitor script...")
        monitor_process.terminate()
    
    process_manager.cleanup()
    
    # 清理HTTP会话
    asyncio.run(cleanup_http_session())
    
    logger.info("Program exited")
    sys.exit(0)

def run_proxy_server():
    """运行代理服务器（简化版）"""
    logger.info(f"Proxy server would run on port: {ARGO_PORT}")
    logger.info(f"HTTP traffic -> localhost:{PORT}")
    logger.info(f"Xray traffic -> localhost:3001")

async def start_monitor():
    """启动监控脚本"""
    if not MONITOR_KEY or not MONITOR_SERVER or not MONITOR_URL:
        logger.info("Monitor script not configured, skipping")
        return
    
    # 等待其他服务启动
    await asyncio.sleep(10)
    
    downloaded = await download_monitor_script()
    if downloaded:
        run_monitor_script()

async def main_async():
    """异步主函数"""
    # 启动代理服务器（在新线程中）
    threading.Thread(target=run_proxy_server, daemon=True).start()
    
    # 启动主流程
    await start_server()
    
    # 启动监控脚本
    await start_monitor()
    
    # 清理文件
    clean_files()

def main():
    """主函数"""
    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 创建事件循环并运行异步主函数
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # 运行异步任务
    try:
        # 在后台运行异步任务
        asyncio_thread = threading.Thread(
            target=lambda: loop.run_until_complete(main_async()),
            daemon=True
        )
        asyncio_thread.start()
        
        # 启动Flask应用
        logger.info(f"HTTP service running on internal port: {PORT}")
        app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
        
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        # 清理
        loop.run_until_complete(cleanup_http_session())
        loop.close()

if __name__ == '__main__':
    main()
