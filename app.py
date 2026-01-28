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
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor

import requests
from aiohttp import web

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 环境变量配置
class Config:
    def __init__(self):
        self.UPLOAD_URL = os.environ.get('UPLOAD_URL', '')
        self.PROJECT_URL = os.environ.get('PROJECT_URL', '')
        self.AUTO_ACCESS = os.environ.get('AUTO_ACCESS', 'false').lower() == 'true'
        self.FILE_PATH = os.environ.get('FILE_PATH', './tmp')
        self.SUB_PATH = os.environ.get('SUB_PATH', 'sub')
        self.PORT = int(os.environ.get('SERVER_PORT', os.environ.get('PORT', '3000')))
        self.ARGO_PORT = int(os.environ.get('ARGO_PORT', '7860'))
        self.UUID = os.environ.get('UUID', 'e2cae6af-5cdd-fa48-4137-ad3e617fbab0')
        self.NEZHA_SERVER = os.environ.get('NEZHA_SERVER', '')
        self.NEZHA_PORT = os.environ.get('NEZHA_PORT', '')
        self.NEZHA_KEY = os.environ.get('NEZHA_KEY', '')
        self.ARGO_DOMAIN = os.environ.get('ARGO_DOMAIN', '')
        self.ARGO_AUTH = os.environ.get('ARGO_AUTH', '')
        self.CFIP = os.environ.get('CFIP', 'cdns.doon.eu.org')
        self.CFPORT = int(os.environ.get('CFPORT', '443'))
        self.NAME = os.environ.get('NAME', '')
        self.MONITOR_KEY = os.environ.get('MONITOR_KEY', '')
        self.MONITOR_SERVER = os.environ.get('MONITOR_SERVER', '')
        self.MONITOR_URL = os.environ.get('MONITOR_URL', '')
        
        # 创建文件目录
        self.file_path = Path(self.FILE_PATH)
        self.file_path.mkdir(exist_ok=True, parents=True)
        
        logger.info(f"配置初始化完成")
        logger.info(f"UUID: {self.UUID}")
        logger.info(f"内部端口: {self.PORT}")
        logger.info(f"外部端口: {self.ARGO_PORT}")
        logger.info(f"文件路径: {self.file_path}")

config = Config()

# 全局变量
subscription = ""
monitor_process = None
xray_process = None
cloudflared_process = None
nezha_process = None
monitor_restart_count = 0
MAX_RESTART_ATTEMPTS = 10
RESTART_DELAY = 30
argo_domain = ""

# 生成随机文件名
def generate_random_name(length=6):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

# 文件路径
npm_name = generate_random_name()
web_name = generate_random_name()
bot_name = generate_random_name()
php_name = generate_random_name()

npm_path = config.file_path / npm_name
web_path = config.file_path / web_name
bot_path = config.file_path / bot_name
php_path = config.file_path / php_name
monitor_path = config.file_path / 'cf-vps-monitor.sh'
sub_path = config.file_path / 'sub.txt'
list_path = config.file_path / 'list.txt'
boot_log_path = config.file_path / 'boot.log'
config_path = config.file_path / 'config.json'
nezha_config_path = config.file_path / 'config.yaml'
tunnel_json_path = config.file_path / 'tunnel.json'
tunnel_yaml_path = config.file_path / 'tunnel.yml'

# ==================== 核心功能函数 ====================

def delete_nodes():
    """删除历史节点"""
    if not config.UPLOAD_URL or not sub_path.exists():
        return
    
    try:
        with open(sub_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
        
        decoded = base64.b64decode(file_content).decode('utf-8')
        nodes = [line for line in decoded.split('\n') 
                if any(proto in line for proto in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
        
        if not nodes:
            return
        
        data = json.dumps({'nodes': nodes})
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(f'{config.UPLOAD_URL}/api/delete-nodes', 
                                   data=data, headers=headers, timeout=10)
            if response.status_code == 200:
                logger.info("历史节点删除成功")
        except Exception as e:
            logger.error(f"删除历史节点失败: {e}")
    except Exception as e:
        logger.error(f"删除历史节点时出错: {e}")

def cleanup_old_files():
    """清理历史文件"""
    try:
        for item in config.file_path.iterdir():
            if item.is_file():
                try:
                    item.unlink()
                    logger.debug(f"删除文件: {item.name}")
                except Exception:
                    pass
        logger.info("清理历史文件完成")
    except Exception as e:
        pass

def generate_config():
    """生成Xray配置文件"""
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
                    "clients": [{"id": config.UUID, "flow": "xtls-rprx-vision"}],
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
                "settings": {
                    "clients": [{"id": config.UUID, "alterId": 0}]
                },
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
                "settings": {
                    "clients": [{"password": config.UUID}]
                },
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
            {
                "protocol": "blackhole",
                "tag": "block"
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

def get_system_architecture():
    """判断系统架构"""
    import platform
    arch = platform.machine().lower()
    if 'arm' in arch or 'aarch64' in arch:
        return 'arm'
    return 'amd'

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

def argo_type():
    """生成固定隧道配置"""
    if not config.ARGO_AUTH or not config.ARGO_DOMAIN:
        logger.info("ARGO_DOMAIN 或 ARGO_AUTH 为空，使用快速隧道")
        return
    
    # 检查是否为TunnelSecret格式
    if 'TunnelSecret' in config.ARGO_AUTH:
        try:
            # 解析JSON获取TunnelID
            tunnel_config = json.loads(config.ARGO_AUTH)
            tunnel_id = tunnel_config.get('TunnelID', '')
            
            with open(tunnel_json_path, 'w', encoding='utf-8') as f:
                f.write(config.ARGO_AUTH)
            
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
            
            logger.info("隧道YAML配置生成成功")
        except Exception as e:
            logger.error(f"生成隧道配置错误: {e}")
    else:
        logger.info("ARGO_AUTH 不是TunnelSecret格式，使用token连接隧道")

def download_monitor_script() -> bool:
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
        
        # 设置执行权限
        os.chmod(monitor_path, 0o755)
        logger.info("监控脚本下载完成")
        return True
    except Exception as e:
        logger.error(f"下载监控脚本失败: {e}")
        return False

def stop_process(process, name: str):
    """停止进程"""
    if process:
        try:
            logger.info(f"停止 {name} 进程 (PID: {process.pid})")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            process = None
        except Exception as e:
            logger.error(f"停止 {name} 进程失败: {e}")

def run_monitor_script():
    """运行监控脚本"""
    global monitor_process, monitor_restart_count
    
    if not config.MONITOR_KEY or not config.MONITOR_SERVER or not config.MONITOR_URL:
        logger.info("监控脚本未配置，跳过")
        return
    
    args = [
        '-i',                    # 安装模式
        '-k', config.MONITOR_KEY,       # 密钥
        '-s', config.MONITOR_SERVER,    # 服务器标识
        '-u', config.MONITOR_URL        # 上报地址
    ]
    
    logger.info(f"运行监控脚本: {monitor_path} {' '.join(args)}")
    
    try:
        # 使用subprocess.Popen启动进程
        monitor_process = subprocess.Popen(
            [str(monitor_path)] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        logger.info(f"监控脚本启动成功，PID: {monitor_process.pid}")
        
        # 启动线程监听进程输出
        def read_output(process):
            for line in process.stdout:
                logger.info(f"监控脚本输出: {line.strip()}")
            for line in process.stderr:
                logger.error(f"监控脚本错误: {line.strip()}")
        
        stdout_thread = threading.Thread(
            target=read_output,
            args=(monitor_process,),
            daemon=True
        )
        stdout_thread.start()
        
        # 启动线程等待进程退出
        def wait_for_process():
            global monitor_process, monitor_restart_count
            process = monitor_process
            if process:
                returncode = process.wait()
                logger.info(f"监控脚本退出，代码: {returncode}")
                
                # 如果进程异常退出，尝试重启
                if returncode != 0 and monitor_restart_count < MAX_RESTART_ATTEMPTS:
                    monitor_restart_count += 1
                    logger.info(f"监控脚本异常退出，将在 {RESTART_DELAY} 秒后重启 (重启次数: {monitor_restart_count}/{MAX_RESTART_ATTEMPTS})")
                    
                    def restart():
                        time.sleep(RESTART_DELAY)
                        run_monitor_script()
                    
                    restart_thread = threading.Thread(target=restart, daemon=True)
                    restart_thread.start()
        
        wait_thread = threading.Thread(target=wait_for_process, daemon=True)
        wait_thread.start()
        
    except Exception as e:
        logger.error(f"运行监控脚本失败: {e}")

def start_monitor_script():
    """启动监控脚本"""
    if not config.MONITOR_KEY or not config.MONITOR_SERVER or not config.MONITOR_URL:
        logger.info("监控脚本未配置，跳过")
        return
    
    # 等待其他服务启动
    time.sleep(10)
    
    downloaded = download_monitor_script()
    if downloaded:
        run_monitor_script()

def get_files_for_architecture(architecture: str):
    """根据系统架构返回对应的文件URL"""
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

def download_files_and_run():
    """下载文件并运行"""
    architecture = get_system_architecture()
    files_to_download = get_files_for_architecture(architecture)
    
    if not files_to_download:
        logger.info("找不到适合当前架构的文件")
        return
    
    # 下载文件
    for file_info in files_to_download:
        if not download_file(file_info['url'], file_info['path']):
            logger.error(f"下载失败: {file_info['path'].name}")
    
    # 运行哪吒监控
    global nezha_process
    if config.NEZHA_SERVER and config.NEZHA_KEY:
        if not config.NEZHA_PORT:
            # v1版本
            port = config.NEZHA_SERVER.split(':')[-1] if ':' in config.NEZHA_SERVER else '443'
            tls_ports = {'443', '8443', '2096', '2087', '2083', '2053'}
            nezhatls = 'true' if port in tls_ports else 'false'
            
            config_yaml = f"""client_secret: {config.NEZHA_KEY}
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
            
            try:
                nezha_process = subprocess.Popen(
                    [str(php_path), "-c", str(nezha_config_path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )
                logger.info(f"{php_path.name} 运行中 (PID: {nezha_process.pid})")
                time.sleep(1)
            except Exception as e:
                logger.error(f"哪吒运行错误: {e}")
        else:
            # v0版本
            args = [
                "-s", f"{config.NEZHA_SERVER}:{config.NEZHA_PORT}",
                "-p", config.NEZHA_KEY,
                "--disable-auto-update",
                "--report-delay", "4",
                "--skip-conn",
                "--skip-procs"
            ]
            
            tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
            if config.NEZHA_PORT in tls_ports:
                args.append("--tls")
            
            try:
                nezha_process = subprocess.Popen(
                    [str(npm_path)] + args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )
                logger.info(f"{npm_path.name} 运行中 (PID: {nezha_process.pid})")
                time.sleep(1)
            except Exception as e:
                logger.error(f"哪吒运行错误: {e}")
    else:
        logger.info("哪吒监控变量为空，跳过运行")
    
    # 运行Xray
    global xray_process
    try:
        xray_process = subprocess.Popen(
            [str(web_path), "-c", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        logger.info(f"{web_path.name} 运行中 (PID: {xray_process.pid})")
        time.sleep(1)
    except Exception as e:
        logger.error(f"Xray运行错误: {e}")
    
    # 运行Cloudflared
    global cloudflared_process
    if bot_path.exists():
        args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2"]
        
        if config.ARGO_AUTH and config.ARGO_AUTH.strip():
            # 检查是否为token格式（120-250字符的base64）
            if 120 <= len(config.ARGO_AUTH) <= 250 and all(c.isalnum() or c in ['=', '/', '+'] for c in config.ARGO_AUTH):
                args.extend(["run", "--token", config.ARGO_AUTH])
            elif 'TunnelSecret' in config.ARGO_AUTH:
                # 确保 YAML 配置已生成
                if not tunnel_yaml_path.exists():
                    logger.info("等待tunnel.yml配置...")
                    time.sleep(1)
                args.extend(["--config", str(tunnel_yaml_path), "run"])
            else:
                args.extend(["--logfile", str(boot_log_path), "--loglevel", "info",
                           "--url", f"http://localhost:{config.ARGO_PORT}"])
        else:
            args.extend(["--logfile", str(boot_log_path), "--loglevel", "info",
                       "--url", f"http://localhost:{config.ARGO_PORT}"])
        
        try:
            cloudflared_process = subprocess.Popen(
                [str(bot_path)] + args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            logger.info(f"{bot_path.name} 运行中 (PID: {cloudflared_process.pid})")
            
            # 等待隧道启动
            logger.info("等待隧道启动...")
            time.sleep(5)
            
        except Exception as e:
            logger.error(f"Cloudflared运行错误: {e}")
    
    time.sleep(2)

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
            response = requests.get('http://ip-api.com/json/', timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success' and data.get('countryCode') and data.get('org'):
                    return f"{data['countryCode']}_{data['org']}"
        except Exception:
            pass
    
    return 'Unknown'

def extract_domains():
    """获取临时隧道domain"""
    global argo_domain
    
    if config.ARGO_AUTH and config.ARGO_DOMAIN:
        argo_domain = config.ARGO_DOMAIN
        logger.info(f'使用固定域名: {argo_domain}')
        generate_links(argo_domain)
        return
    
    try:
        if not boot_log_path.exists():
            logger.error("boot.log文件不存在")
            restart_cloudflared()
            return
        
        with open(boot_log_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        import re
        domains = re.findall(r'https?://([^ ]*trycloudflare\.com)/?', content)
        
        if domains:
            argo_domain = domains[0]
            logger.info(f'找到临时域名: {argo_domain}')
            generate_links(argo_domain)
        else:
            logger.info('未找到域名，重新运行bot以获取Argo域名')
            restart_cloudflared()
    except Exception as e:
        logger.error(f'读取boot.log错误: {e}')

def restart_cloudflared():
    """重启Cloudflared"""
    global cloudflared_process
    
    # 停止现有进程
    if cloudflared_process:
        stop_process(cloudflared_process, "cloudflared")
    
    # 删除日志文件
    if boot_log_path.exists():
        boot_log_path.unlink()
    
    time.sleep(3)
    
    # 重新启动
    args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2",
           "--logfile", str(boot_log_path), "--loglevel", "info",
           "--url", f"http://localhost:{config.ARGO_PORT}"]
    
    try:
        cloudflared_process = subprocess.Popen(
            [str(bot_path)] + args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        logger.info(f"{bot_path.name} 重新运行中 (PID: {cloudflared_process.pid})")
        time.sleep(3)
        extract_domains()
    except Exception as e:
        logger.error(f"执行命令错误: {e}")

def generate_links(domain: str):
    """生成订阅"""
    global subscription
    
    isp = get_meta_info()
    node_name = f"{config.NAME}-{isp}" if config.NAME else isp
    
    # 生成VMESS配置
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
    
    # 打印base64内容
    logger.info("订阅base64内容:")
    encoded = base64.b64encode(sub_txt.encode()).decode()
    logger.info(encoded)
    
    # 更新全局订阅变量
    subscription = sub_txt
    
    # 保存到文件
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(encoded)
    
    logger.info(f"{sub_path} 保存成功")
    
    # 上传节点
    upload_nodes()

def upload_nodes():
    """自动上传节点或订阅"""
    if config.UPLOAD_URL and config.PROJECT_URL:
        subscription_url = f"{config.PROJECT_URL}/{config.SUB_PATH}"
        data = json.dumps({"subscription": [subscription_url]})
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(f'{config.UPLOAD_URL}/api/add-subscriptions', 
                                   data=data, headers=headers, timeout=10)
            if response.status_code == 200:
                logger.info("订阅上传成功")
            elif response.status_code == 400:
                logger.info("订阅已存在")
        except Exception as e:
            logger.error(f"订阅上传失败: {e}")
    elif config.UPLOAD_URL:
        if not list_path.exists():
            return
        
        try:
            with open(list_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except:
            return
        
        nodes = [line for line in content.split('\n') 
                if any(proto in line for proto in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
        
        if not nodes:
            return
        
        data = json.dumps({"nodes": nodes})
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(f'{config.UPLOAD_URL}/api/add-nodes', 
                                   data=data, headers=headers, timeout=10)
            if response.status_code == 200:
                logger.info("节点上传成功")
        except Exception as e:
            logger.error(f"节点上传失败: {e}")

def clean_files():
    """90秒后清理文件"""
    def cleanup():
        time.sleep(90)
        
        files_to_delete = [
            boot_log_path,
            config_path,
            web_path,
            bot_path,
            monitor_path,
            nezha_config_path,
            tunnel_json_path,
            tunnel_yaml_path
        ]
        
        if config.NEZHA_PORT:
            files_to_delete.append(npm_path)
        elif config.NEZHA_SERVER and config.NEZHA_KEY:
            files_to_delete.append(php_path)
        
        for file_path_item in files_to_delete:
            if file_path_item.exists():
                try:
                    file_path_item.unlink()
                    logger.debug(f"清理文件: {file_path_item.name}")
                except Exception:
                    pass
        
        logger.info("应用正在运行")
        logger.info("感谢使用此脚本，享受吧！")
    
    cleanup_thread = threading.Thread(target=cleanup, daemon=True)
    cleanup_thread.start()

def add_visit_task():
    """自动访问项目URL"""
    if not config.AUTO_ACCESS or not config.PROJECT_URL:
        logger.info("跳过自动访问任务")
        return
    
    data = json.dumps({"url": config.PROJECT_URL})
    headers = {'Content-Type': 'application/json'}
    
    try:
        response = requests.post('https://oooo.serv00.net/add-url', 
                               data=data, headers=headers, timeout=10)
        if response.status_code == 200:
            logger.info("自动访问任务添加成功")
    except Exception as e:
        logger.error(f"添加自动访问任务失败: {e}")

# ==================== HTTP服务器实现 ====================

class ProxyServer:
    """HTTP和WebSocket代理服务器"""
    
    def __init__(self):
        self.app = web.Application()
        self.setup_routes()
        self.runner = None
        self.site = None
        
    def setup_routes(self):
        """设置路由"""
        # 订阅路由
        async def handle_sub(request):
            global subscription
            if subscription:
                encoded = base64.b64encode(subscription.encode()).decode()
                return web.Response(text=encoded, content_type='text/plain; charset=utf-8')
            return web.Response(text="订阅尚未生成", status=404)
        
        # 首页路由
        async def handle_index(request):
            index_path = Path('index.html')
            if index_path.exists():
                return web.FileResponse(index_path)
            return web.Response(text="Hello world!")
        
        # Xray代理路由
        async def handle_proxy(request):
            path = request.path
            method = request.method
            headers = dict(request.headers)
            
            # 确定目标端口
            if (path.startswith('/vless-argo') or 
                path.startswith('/vmess-argo') or 
                path.startswith('/trojan-argo') or
                path in ['/vless', '/vmess', '/trojan']):
                target_port = 3001
            else:
                # 其他请求由当前服务器处理
                if path == f'/{config.SUB_PATH}':
                    return await handle_sub(request)
                elif path == '/':
                    return await handle_index(request)
                return web.Response(text="Not Found", status=404)
            
            target_url = f'http://localhost:{target_port}{path}'
            
            try:
                # 读取请求体
                if request.can_read_body:
                    data = await request.read()
                else:
                    data = None
                
                # 转发请求
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method=method,
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
                            response.headers[name] = value
                        
                        await response.prepare(request)
                        
                        # 流式传输响应体
                        async for chunk in resp.content.iter_any():
                            await response.write(chunk)
                        
                        await response.write_eof()
                        return response
                        
            except Exception as e:
                logger.error(f"代理错误: {e}")
                return web.Response(text=f"代理错误: {e}", status=500)
        
        # WebSocket代理
        async def handle_websocket(request):
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
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(target_url) as target_ws:
                        # 双向转发消息
                        async def forward(source, dest):
                            try:
                                async for msg in source:
                                    if msg.type == aiohttp.WSMsgType.TEXT:
                                        await dest.send_str(msg.data)
                                    elif msg.type == aiohttp.WSMsgType.BINARY:
                                        await dest.send_bytes(msg.data)
                                    elif msg.type == aiohttp.WSMsgType.ERROR:
                                        logger.error(f'WebSocket错误: {source.exception()}')
                                        break
                                    elif msg.type == aiohttp.WSMsgType.CLOSE:
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
        
        # 注册路由
        self.app.router.add_get(f'/{config.SUB_PATH}', handle_sub)
        self.app.router.add_get('/', handle_index)
        
        # WebSocket路由
        self.app.router.add_get('/vless-argo', handle_websocket)
        self.app.router.add_get('/vmess-argo', handle_websocket)
        self.app.router.add_get('/trojan-argo', handle_websocket)
        
        # 其他HTTP请求
        self.app.router.add_route('*', '/{path:.*}', handle_proxy)
    
    async def start(self):
        """启动服务器"""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '0.0.0.0', config.ARGO_PORT)
        await self.site.start()
        
        logger.info(f"代理服务器启动在端口: {config.ARGO_PORT}")
        logger.info(f"HTTP流量 -> localhost:{config.PORT}")
        logger.info(f"Xray流量 -> localhost:3001")
        
        # 启动内部HTTP服务器
        internal_server_thread = threading.Thread(target=self._start_internal_server, daemon=True)
        internal_server_thread.start()
    
    def _start_internal_server(self):
        """启动内部HTTP服务器（在单独的线程中）"""
        async def internal_handler(request):
            path = request.path
            
            if path == f'/{config.SUB_PATH}':
                global subscription
                if subscription:
                    encoded = base64.b64encode(subscription.encode()).decode()
                    return web.Response(text=encoded, content_type='text/plain; charset=utf-8')
                return web.Response(text="订阅尚未生成", status=404)
            
            elif path == '/':
                index_path = Path('index.html')
                if index_path.exists():
                    return web.FileResponse(index_path)
                return web.Response(text="Hello world!")
            
            return web.Response(text="Not Found", status=404)
        
        async def start_internal():
            app = web.Application()
            app.router.add_get(f'/{config.SUB_PATH}', internal_handler)
            app.router.add_get('/', internal_handler)
            
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, '0.0.0.0', config.PORT)
            await site.start()
            
            logger.info(f"内部HTTP服务运行在端口: {config.PORT}")
            
            # 保持运行
            while True:
                await asyncio.sleep(3600)
        
        asyncio.run(start_internal())
    
    async def stop(self):
        """停止服务器"""
        if self.runner:
            await self.runner.cleanup()

# ==================== 主程序 ====================

async def start_server():
    """主运行逻辑"""
    try:
        logger.info('开始服务器初始化...')
        
        # 在后台线程中运行初始化
        def run_initialization():
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
        
        # 使用线程池执行初始化
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            await loop.run_in_executor(executor, run_initialization)
        
        # 启动监控脚本
        def start_monitor():
            start_monitor_script()
        
        monitor_thread = threading.Thread(target=start_monitor, daemon=True)
        monitor_thread.start()
        
        # 清理文件
        clean_files()
        
    except Exception as e:
        logger.error(f'启动过程中错误: {e}')

def signal_handler(signum, frame):
    """信号处理"""
    logger.info("收到关闭信号，正在清理...")
    
    global monitor_process, xray_process, cloudflared_process, nezha_process
    
    # 停止所有进程
    stop_process(monitor_process, "监控脚本")
    stop_process(xray_process, "Xray")
    stop_process(cloudflared_process, "Cloudflared")
    stop_process(nezha_process, "哪吒监控")
    
    logger.info("程序退出")
    sys.exit(0)

async def main():
    """主函数"""
    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 启动代理服务器
    proxy_server = ProxyServer()
    server_task = asyncio.create_task(proxy_server.start())
    
    # 启动服务器初始化
    init_task = asyncio.create_task(start_server())
    
    # 等待所有任务
    try:
        await asyncio.gather(init_task, server_task)
    except asyncio.CancelledError:
        await proxy_server.stop()

if __name__ == '__main__':
    # 运行主程序
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        signal_handler(None, None)
    except Exception as e:
        logger.error(f"程序运行错误: {e}")
