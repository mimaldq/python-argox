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
import yaml
import requests
import re
import socket
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor

# 设置日志 - 使用中文
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
logger.info(f"{FILE_PATH} 已创建或已存在")

# 全局变量
monitor_process = None
processes = []
sub_txt = ""
argo_domain = ""
sub_encoded = ""

# WebSocket代理相关
xray_host = 'localhost'
xray_port = 3001
web_app = None
runner = None

class ProcessManager:
    def __init__(self):
        self.processes = []
    
    def add_process(self, process):
        self.processes.append(process)
    
    def cleanup(self):
        for process in self.processes:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
            except Exception as e:
                logger.error(f"终止进程时出错: {e}")

process_manager = ProcessManager()

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

def delete_nodes():
    """删除历史节点"""
    if not UPLOAD_URL or not sub_path.exists():
        return
    
    try:
        with open(sub_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
        
        decoded = base64.b64decode(file_content).decode('utf-8')
        nodes = [line for line in decoded.split('\n') 
                if any(proto in line for proto in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
        
        if not nodes:
            return
        
        payload = {'nodes': nodes}
        try:
            response = requests.post(
                f"{UPLOAD_URL}/api/delete-nodes",
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            if response.status_code == 200:
                logger.info("节点删除成功")
        except Exception as e:
            logger.error(f"删除节点时出错: {e}")
    except Exception as e:
        logger.error(f"删除节点函数出错: {e}")

def cleanup_old_files():
    """清理历史文件"""
    try:
        for file in file_path.iterdir():
            try:
                if file.is_file():
                    file.unlink()
            except Exception:
                pass
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
    logger.info("Xray配置文件已生成")

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
        logger.info(f"下载 {filepath.name} 成功")
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
        logger.error(f"运行命令 {cmd} 时出错: {e}")
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
            logger.info(f"{php_name} 正在运行")
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
            logger.info(f"{npm_name} 正在运行")
            time.sleep(1)
    else:
        logger.info("哪吒监控变量为空，跳过运行")
    
    # 运行Xray
    cmd = f"{web_path} -c {config_path}"
    run_process(cmd, detach=True)
    logger.info(f"{web_name} 正在运行")
    time.sleep(1)
    
    # 运行cloudflared
    if bot_path.exists():
        args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2"]
        
        if ARGO_AUTH and ARGO_AUTH.strip() and len(ARGO_AUTH.strip()) >= 120 and len(ARGO_AUTH.strip()) <= 250:
            args.extend(["run", "--token", ARGO_AUTH.strip()])
        elif ARGO_AUTH and 'TunnelSecret' in ARGO_AUTH:
            # 确保隧道配置文件存在
            if not tunnel_yaml_path.exists():
                logger.info("等待隧道配置文件生成...")
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
        logger.info(f"{bot_name} 正在运行")
        time.sleep(5)
    
    time.sleep(2)

def argo_type():
    """配置Argo隧道类型"""
    if not ARGO_AUTH or not ARGO_DOMAIN:
        logger.info("ARGO_DOMAIN 或 ARGO_AUTH 为空，使用快速隧道")
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
            logger.info('隧道YAML配置生成成功')
        except Exception as e:
            logger.error(f'生成隧道配置错误: {e}')
    else:
        logger.info("ARGO_AUTH 不是TunnelSecret格式，使用token连接隧道")

def download_monitor_script():
    """下载监控脚本"""
    if not MONITOR_KEY or not MONITOR_SERVER or not MONITOR_URL:
        logger.info("监控环境变量不完整，跳过监控脚本启动")
        return False
    
    monitor_url = "https://raw.githubusercontent.com/mimaldq/cf-vps-monitor/main/cf-vps-monitor.sh"
    logger.info(f"从 {monitor_url} 下载监控脚本")
    
    try:
        response = requests.get(monitor_url, timeout=30)
        response.raise_for_status()
        
        with open(monitor_path, 'wb') as f:
            f.write(response.content)
        
        monitor_path.chmod(0o755)
        logger.info("监控脚本下载完成")
        return True
    except Exception as e:
        logger.error(f"下载监控脚本失败: {e}")
        return False

def run_monitor_script():
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
    
    logger.info(f"运行监控脚本")
    
    try:
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
        logger.error(f"运行监控脚本时出错: {e}")

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
                logger.error("boot.log 文件未找到")
                return
            
            with open(boot_log_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
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
                logger.info(f"{bot_name} 重新运行中")
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
        pass

def get_meta_info():
    """获取ISP信息"""
    try:
        response = requests.get('https://ipapi.co/json/', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('country_code') and data.get('org'):
                return f"{data['country_code']}_{data['org']}"
    except Exception:
        try:
            # 备用 ip-api.com 获取isp
            response = requests.get('http://ip-api.com/json/', timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success' and data.get('countryCode') and data.get('org'):
                    return f"{data['countryCode']}_{data['org']}"
        except Exception:
            pass
    return 'Unknown'

def generate_links(domain):
    """生成订阅链接"""
    global sub_txt, argo_domain, sub_encoded
    argo_domain = domain
    
    ISP = get_meta_info()
    node_name = f"{NAME}-{ISP}" if NAME else ISP
    
    # 生成VMESS配置
    VMESS = { 
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
    
    sub_txt = f"""
vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{node_name}

vmess://{base64.b64encode(json.dumps(VMESS).encode()).decode()}

trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{node_name}
    """
    
    # 打印 sub.txt 内容到控制台
    sub_encoded = base64.b64encode(sub_txt.encode()).decode()
    print(f"\n订阅内容(base64):\n{sub_encoded}\n")
    
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(sub_encoded)
    logger.info(f"{sub_path} 保存成功")
    
    upload_nodes()
    
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
            
            if response and response.status_code == 200:
                logger.info('订阅上传成功')
                return response
            else:
                return None
        except Exception as e:
            if hasattr(e, 'response') and e.response:
                if e.response.status_code == 400:
                    logger.error('订阅已存在')
            else:
                logger.error(f'订阅上传失败: {e}')
    elif UPLOAD_URL:
        if not list_path.exists():
            return
        
        try:
            with open(list_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            nodes = [line for line in content.split('\n') 
                    if any(proto in line for proto in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
            
            if not nodes:
                return
            
            json_data = json.dumps({"nodes": nodes})
            
            try:
                response = requests.post(
                    f"{UPLOAD_URL}/api/add-nodes",
                    data=json_data,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                if response and response.status_code == 200:
                    logger.info('节点上传成功')
                    return response
                else:
                    return None
            except Exception:
                return None
        except Exception:
            return None
    else:
        return

def clean_files():
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
            except Exception:
                pass
        
        logger.info('应用正在运行')
        logger.info('感谢使用此脚本，享受吧！')
    
    # 在新线程中运行清理
    threading.Thread(target=cleanup, daemon=True).start()

def add_visit_task():
    """添加自动访问任务"""
    if not AUTO_ACCESS or not PROJECT_URL:
        logger.info("跳过添加自动访问任务")
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

# ========== WebSocket代理相关函数 ==========

async def handle_proxy(request):
    """处理代理请求 - 同时处理HTTP和WebSocket"""
    path = request.path
    headers = request.headers
    
    # 检查是否是WebSocket升级请求
    is_websocket = (
        headers.get('Upgrade', '').lower() == 'websocket' and
        headers.get('Connection', '').lower() == 'upgrade'
    )
    
    # 判断是否转发到Xray
    xray_paths = ['/vless-argo', '/vmess-argo', '/trojan-argo', '/vless', '/vmess', '/trojan']
    should_proxy_to_xray = any(path.startswith(p) for p in xray_paths)
    
    if should_proxy_to_xray:
        target_host = xray_host
        target_port = xray_port
    else:
        # 转发到HTTP服务器
        target_host = 'localhost'
        target_port = PORT
    
    # 构建目标URL
    target_url = f'http://{target_host}:{target_port}{path}'
    if request.query_string:
        target_url += f'?{request.query_string}'
    
    try:
        if is_websocket:
            return await websocket_proxy(request, target_url)
        else:
            return await http_proxy(request, target_url)
    except Exception as e:
        logger.error(f"代理请求失败: {e}")
        return web.Response(status=502, text="Bad Gateway")

async def websocket_proxy(request, target_url):
    """WebSocket代理"""
    ws_to_client = web.WebSocketResponse()
    await ws_to_client.prepare(request)
    
    try:
        # 连接到目标WebSocket服务器
        ws_to_target = await ClientSession().ws_connect(
            target_url.replace('http://', 'ws://').replace('https://', 'wss://'),
            headers=request.headers
        )
        
        async def forward(source_ws, dest_ws):
            async for msg in source_ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await dest_ws.send_str(msg.data)
                elif msg.type == aiohttp.WSMsgType.BINARY:
                    await dest_ws.send_bytes(msg.data)
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    break
        
        # 同时转发两个方向的数据
        await asyncio.gather(
            forward(ws_to_client, ws_to_target),
            forward(ws_to_target, ws_to_client)
        )
        
        return ws_to_client
    except Exception as e:
        logger.error(f"WebSocket代理错误: {e}")
        return web.Response(status=502, text="WebSocket proxy error")

async def http_proxy(request, target_url):
    """HTTP代理"""
    # 获取原始请求的数据
    data = await request.read() if request.method in ['POST', 'PUT', 'PATCH'] else None
    
    # 转发请求
    async with ClientSession() as session:
        try:
            async with session.request(
                method=request.method,
                url=target_url,
                headers=dict(request.headers),
                data=data,
                allow_redirects=False
            ) as response:
                # 创建响应
                resp = web.Response(
                    status=response.status,
                    headers=dict(response.headers)
                )
                
                # 读取响应体
                body = await response.read()
                resp.body = body
                
                return resp
        except Exception as e:
            logger.error(f"HTTP代理错误: {e}")
            return web.Response(status=502, text="Proxy error")

async def handle_index(request):
    """处理根路由"""
    index_path = Path(__file__).parent / 'index.html'
    if index_path.exists():
        return web.FileResponse(index_path)
    return web.Response(text="Hello world!")

async def handle_sub(request):
    """处理订阅路由"""
    global sub_encoded
    if not sub_encoded:
        return web.Response(status=503, text="订阅尚未准备好，请稍后重试")
    
    return web.Response(
        text=sub_encoded,
        content_type='text/plain; charset=utf-8'
    )

async def handle_health(request):
    """健康检查"""
    return web.Response(text="OK")

async def init_app():
    """初始化aiohttp应用 - 现在只处理特定路由，其他路由通过代理"""
    app = web.Application()
    
    # 直接处理的路由
    app.router.add_get('/', handle_index)
    app.router.add_get(f'/{SUB_PATH}', handle_sub)
    app.router.add_get('/health', handle_health)
    
    # 其他所有路由都走代理
    app.router.add_route('*', '/{path:.*}', handle_proxy)
    
    return app

async def start_proxy_server():
    """启动代理服务器"""
    global web_app, runner
    
    web_app = await init_app()
    runner = web.AppRunner(web_app)
    await runner.setup()
    
    # 启动在ARGO_PORT端口
    site = web.TCPSite(runner, '0.0.0.0', ARGO_PORT)
    await site.start()
    
    logger.info(f"代理服务器启动在端口: {ARGO_PORT}")
    logger.info(f"HTTP流量 -> localhost:{PORT}")
    logger.info(f"Xray流量 -> localhost:{xray_port}")
    
    return runner

def start_server():
    """启动服务器"""
    logger.info('开始服务器初始化...')
    
    delete_nodes()
    cleanup_old_files()
    
    argo_type()
    generate_config()
    download_files_and_run()
    
    # 等待隧道启动
    logger.info('等待隧道启动...')
    time.sleep(5)
    
    extract_domains()
    add_visit_task()
    
    logger.info('服务器初始化完成')

def signal_handler(signum, frame):
    """信号处理"""
    logger.info("收到关闭信号，正在清理...")
    
    if monitor_process and monitor_process.poll() is None:
        logger.info("停止监控脚本...")
        monitor_process.terminate()
    
    process_manager.cleanup()
    
    logger.info("程序退出")
    sys.exit(0)

async def main_async():
    """异步主函数"""
    # 启动代理服务器
    runner = await start_proxy_server()
    
    # 在新的线程中启动主服务
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # 启动监控脚本（延迟10秒）
    async def start_monitor_delayed():
        await asyncio.sleep(10)
        if download_monitor_script():
            run_monitor_script()
    
    asyncio.create_task(start_monitor_delayed())
    
    # 清理文件（延迟90秒）
    async def clean_files_delayed():
        await asyncio.sleep(90)
        clean_files()
    
    asyncio.create_task(clean_files_delayed())
    
    # 打印信息
    print(f"\n{'='*60}")
    print(f"服务器正在运行!")
    print(f"代理端口: {ARGO_PORT}")
    print(f"订阅地址: http://localhost:{ARGO_PORT}/{SUB_PATH}")
    print(f"WebSocket路径: /vless-argo, /vmess-argo, /trojan-argo")
    print(f"健康检查: http://localhost:{ARGO_PORT}/health")
    print(f"{'='*60}\n")
    
    try:
        # 保持运行
        await asyncio.Future()
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()

def main():
    """主函数"""
    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 确保requests库可用
    try:
        import requests
    except ImportError:
        logger.error("请安装requests库: pip install requests aiohttp")
        sys.exit(1)
    
    try:
        # 创建事件循环并运行
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(main_async())
    except KeyboardInterrupt:
        logger.info("服务器被用户停止")
    except Exception as e:
        logger.error(f"启动服务器时出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理
        if monitor_process and monitor_process.poll() is None:
            monitor_process.terminate()
        process_manager.cleanup()

if __name__ == '__main__':
    main()
