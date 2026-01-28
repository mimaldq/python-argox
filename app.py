#!/usr/bin/env python3
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
from typing import Optional, Dict, List
from urllib.parse import urlparse, quote

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
        self.UUID = os.environ.get('UUID', '20e6e496-cf19-45c8-b883-14f5e11cd9f1')
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
        
        logger.info(f"配置初始化完成")
        logger.info(f"UUID: {self.UUID}")
        logger.info(f"外部端口: {self.ARGO_PORT}")
        logger.info(f"内部HTTP端口: {self.PORT}")

config = Config()

# 全局变量
subscription = ""
monitor_process = None
monitor_restart_count = 0
MAX_RESTART_ATTEMPTS = 10
RESTART_DELAY = 30

# 生成随机文件名
def generate_random_name(length=6):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

# 初始化文件路径
file_path = Path(config.FILE_PATH)
file_path.mkdir(exist_ok=True, parents=True)

# 文件路径
npm_path = file_path / generate_random_name()
web_path = file_path / generate_random_name()
bot_path = file_path / generate_random_name()
php_path = file_path / generate_random_name()
monitor_path = file_path / 'cf-vps-monitor.sh'
sub_path = file_path / 'sub.txt'
list_path = file_path / 'list.txt'
boot_log_path = file_path / 'boot.log'
config_path = file_path / 'config.json'
nezha_config_path = file_path / 'config.yaml'
tunnel_json_path = file_path / 'tunnel.json'
tunnel_yaml_path = file_path / 'tunnel.yml'

logger.info(f"工作目录: {file_path}")

# 删除历史节点
def delete_nodes():
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

# 清理历史文件
def cleanup_old_files():
    try:
        for item in file_path.iterdir():
            if item.is_file():
                try:
                    item.unlink()
                except Exception:
                    pass
        logger.info("清理历史文件完成")
    except Exception as e:
        pass

# 生成xray配置文件
def generate_config():
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

# 判断系统架构
def get_system_architecture():
    import platform
    arch = platform.machine().lower()
    if 'arm' in arch or 'aarch64' in arch:
        return 'arm'
    return 'amd'

# 下载文件
def download_file(url: str, file_path: Path) -> bool:
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        
        # 设置执行权限
        os.chmod(file_path, 0o755)
        logger.info(f"下载成功: {file_path.name}")
        return True
    except Exception as e:
        logger.error(f"下载失败 {file_path.name}: {e}")
        return False

# 生成固定隧道配置
def argo_type():
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

# 下载监控脚本
def download_monitor_script() -> bool:
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

# 停止监控进程
def stop_monitor():
    global monitor_process, monitor_restart_count
    
    if monitor_process:
        try:
            logger.info(f"停止监控进程 (PID: {monitor_process.pid})")
            monitor_process.terminate()
            try:
                monitor_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                monitor_process.kill()
            monitor_process = None
        except Exception as e:
            logger.error(f"停止监控进程失败: {e}")

# 运行监控脚本
def run_monitor_script():
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

# 启动监控脚本
def start_monitor_script():
    if not config.MONITOR_KEY or not config.MONITOR_SERVER or not config.MONITOR_URL:
        logger.info("监控脚本未配置，跳过")
        return
    
    # 等待其他服务启动
    time.sleep(10)
    
    downloaded = download_monitor_script()
    if downloaded:
        run_monitor_script()

# 根据系统架构返回对应的文件URL
def get_files_for_architecture(architecture):
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

# 下载文件并运行
def download_files_and_run():
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
            
            command = f"nohup {php_path} -c {nezha_config_path} >/dev/null 2>&1 &"
            try:
                subprocess.run(command, shell=True, check=True)
                logger.info(f"{php_path.name} 运行中")
                time.sleep(1)
            except Exception as e:
                logger.error(f"哪吒运行错误: {e}")
        else:
            # v0版本
            nezha_tls = ''
            tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
            if config.NEZHA_PORT in tls_ports:
                nezha_tls = '--tls'
            
            command = f"nohup {npm_path} -s {config.NEZHA_SERVER}:{config.NEZHA_PORT} -p {config.NEZHA_KEY} {nezha_tls} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &"
            try:
                subprocess.run(command, shell=True, check=True)
                logger.info(f"{npm_path.name} 运行中")
                time.sleep(1)
            except Exception as e:
                logger.error(f"哪吒运行错误: {e}")
    else:
        logger.info("哪吒监控变量为空，跳过运行")
    
    # 运行Xray
    command1 = f"nohup {web_path} -c {config_path} >/dev/null 2>&1 &"
    try:
        subprocess.run(command1, shell=True, check=True)
        logger.info(f"{web_path.name} 运行中")
        time.sleep(1)
    except Exception as e:
        logger.error(f"Xray运行错误: {e}")
    
    # 运行Cloudflared
    if bot_path.exists():
        args = []
        
        if config.ARGO_AUTH and config.ARGO_AUTH.strip() and len(config.ARGO_AUTH) >= 120 and len(config.ARGO_AUTH) <= 250:
            args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2", "run", "--token", config.ARGO_AUTH]
        elif config.ARGO_AUTH and 'TunnelSecret' in config.ARGO_AUTH:
            # 确保 YAML 配置已生成
            if not tunnel_yaml_path.exists():
                logger.info("等待tunnel.yml配置...")
                time.sleep(1)
            args = ["tunnel", "--edge-ip-version", "auto", "--config", str(tunnel_yaml_path), "run"]
        else:
            args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2", 
                   "--logfile", str(boot_log_path), "--loglevel", "info", 
                   "--url", f"http://localhost:{config.ARGO_PORT}"]
        
        try:
            command = f"nohup {bot_path} {' '.join(args)} >/dev/null 2>&1 &"
            subprocess.run(command, shell=True, check=True)
            logger.info(f"{bot_path.name} 运行中")
            
            # 等待隧道启动
            logger.info("等待隧道启动...")
            time.sleep(5)
            
        except Exception as e:
            logger.error(f"Cloudflared运行错误: {e}")
    
    time.sleep(2)

# 获取ISP信息
def get_meta_info():
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

# 获取临时隧道domain
def extract_domains():
    argo_domain = None
    
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
    # 停止现有进程
    try:
        if sys.platform == 'win32':
            subprocess.run(f"taskkill /f /im {bot_path.name} > nul 2>&1", shell=True)
        else:
            subprocess.run(f"pkill -f '[{bot_path.name[0]}]{bot_path.name[1:]}' > /dev/null 2>&1", shell=True)
    except Exception:
        pass
    
    # 删除日志文件
    if boot_log_path.exists():
        boot_log_path.unlink()
    
    time.sleep(3)
    
    # 重新启动
    args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {boot_log_path} --loglevel info --url http://localhost:{config.ARGO_PORT}"
    
    try:
        command = f"nohup {bot_path} {args} >/dev/null 2>&1 &"
        subprocess.run(command, shell=True, check=True)
        logger.info(f"{bot_path.name} 重新运行中")
        time.sleep(3)
        extract_domains()
    except Exception as e:
        logger.error(f"执行命令错误: {e}")

# 生成订阅
def generate_links(domain):
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
    
    sub_txt = f"""
vless://{config.UUID}@{config.CFIP}:{config.CFPORT}?encryption=none&security=tls&sni={domain}&fp=firefox&type=ws&host={domain}&path=%2Fvless-argo%3Fed%3D2560#{node_name}

vmess://{vmess_base64}

trojan://{config.UUID}@{config.CFIP}:{config.CFPORT}?security=tls&sni={domain}&fp=firefox&type=ws&host={domain}&path=%2Ftrojan-argo%3Fed%3D2560#{node_name}
    """
    
    # 打印base64内容
    logger.info("订阅base64内容:")
    logger.info(base64.b64encode(sub_txt.encode()).decode())
    
    # 更新全局订阅变量
    subscription = sub_txt
    
    # 保存到文件
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(sub_txt.encode()).decode())
    
    logger.info(f"{sub_path} 保存成功")
    
    # 上传节点
    upload_nodes()

# 自动上传节点或订阅
def upload_nodes():
    if config.UPLOAD_URL and config.PROJECT_URL:
        subscription_url = f"{config.PROJECT_URL}/{config.SUB_PATH}"
        data = json.dumps({"subscription": [subscription_url]})
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(f'{config.UPLOAD_URL}/api/add-subscriptions', 
                                   data=data, headers=headers, timeout=10)
            if response.status_code == 200:
                logger.info("订阅上传成功")
        except Exception as e:
            logger.error(f"订阅上传失败: {e}")
    elif config.UPLOAD_URL:
        if not list_path.exists():
            return
        
        with open(list_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
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

# 90秒后清理文件
def clean_files():
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
        
        for file_path_item in files_to_delete:
            if file_path_item.exists():
                try:
                    file_path_item.unlink()
                except Exception:
                    pass
        
        logger.info("应用正在运行")
        logger.info("感谢使用此脚本，享受吧！")
    
    cleanup_thread = threading.Thread(target=cleanup, daemon=True)
    cleanup_thread.start()

# 自动访问项目URL
def add_visit_task():
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

# ================================================
# aiohttp 服务器实现（HTTP + WebSocket 合一）
# ================================================

# 处理HTTP请求
async def http_handler(request):
    path = request.path
    
    # 订阅路径
    if path == f"/{config.SUB_PATH}":
        global subscription
        if subscription:
            encoded = base64.b64encode(subscription.encode()).decode()
            return web.Response(text=encoded, content_type='text/plain; charset=utf-8')
        return web.Response(text="订阅尚未生成", status=404)
    
    # 根路径
    if path == "/":
        index_path = Path('index.html')
        if index_path.exists():
            return web.FileResponse(index_path)
        return web.Response(text="Hello world!")
    
    # 其他HTTP请求转发到Xray或本地HTTP服务
    # 判断是否应该转发到Xray
    if (path.startswith('/vless-argo') or 
        path.startswith('/vmess-argo') or 
        path.startswith('/trojan-argo') or
        path in ['/vless', '/vmess', '/trojan']):
        target_host = 'localhost'
        target_port = 3001
    else:
        # 这是常规HTTP请求，理论上这里不需要转发，
        # 因为我们的服务器直接处理了订阅和首页请求
        return web.Response(text="Not Found", status=404)
    
    # 转发HTTP请求（对于非WebSocket的HTTP请求）
    target_url = f'http://{target_host}:{target_port}{path}'
    
    try:
        async with aiohttp.ClientSession() as session:
            # 准备请求数据
            data = await request.read() if request.can_read_body else None
            headers = dict(request.headers)
            headers.pop('Host', None)  # 移除Host头
            
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
                    response.headers[name] = value
                
                await response.prepare(request)
                
                # 流式传输响应体
                async for chunk in resp.content.iter_any():
                    await response.write(chunk)
                
                await response.write_eof()
                return response
                
    except Exception as e:
        logger.error(f"HTTP代理错误: {e}")
        return web.Response(text=f"代理错误: {e}", status=500)

# WebSocket代理处理器
async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    path = request.path
    
    # 确定目标WebSocket服务器
    if (path.startswith('/vless-argo') or 
        path.startswith('/vmess-argo') or 
        path.startswith('/trojan-argo')):
        target_host = 'localhost'
        target_port = 3001
    else:
        # 理论上这里不会到达，因为我们的路由只匹配特定路径
        await ws.close()
        return ws
    
    target_url = f'ws://{target_host}:{target_port}{path}'
    
    logger.info(f"WebSocket代理: {path} -> {target_url}")
    
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

# 创建aiohttp应用
def create_app():
    app = web.Application()
    
    # 注册路由
    app.router.add_get(f'/{config.SUB_PATH}', http_handler)
    app.router.add_get('/', http_handler)
    
    # WebSocket路由
    app.router.add_get('/vless-argo', websocket_handler)
    app.router.add_get('/vmess-argo', websocket_handler)
    app.router.add_get('/trojan-argo', websocket_handler)
    
    # 其他HTTP请求（作为后备）
    app.router.add_route('*', '/{path:.*}', http_handler)
    
    return app

# 启动aiohttp服务器
async def start_aiohttp_server():
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', config.ARGO_PORT)
    
    logger.info(f"服务器启动在端口: {config.ARGO_PORT}")
    logger.info(f"HTTP流量 -> 本地处理")
    logger.info(f"WebSocket流量 -> localhost:3001")
    
    await site.start()
    
    # 保持服务器运行
    try:
        await asyncio.Future()  # 永远运行
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()

# 主运行逻辑
async def start_server():
    try:
        logger.info('开始服务器初始化...')
        
        # 这些是阻塞操作，在后台线程中运行
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
        
        # 在线程中运行初始化
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, run_initialization)
        
        # 启动监控脚本
        def start_monitor():
            start_monitor_script()
        
        threading.Thread(target=start_monitor, daemon=True).start()
        
        # 清理文件
        clean_files()
        
    except Exception as e:
        logger.error(f'启动过程中错误: {e}')

# 主函数
async def main():
    # 启动服务器初始化
    init_task = asyncio.create_task(start_server())
    
    # 启动HTTP/WebSocket服务器
    server_task = asyncio.create_task(start_aiohttp_server())
    
    # 等待所有任务
    await asyncio.gather(init_task, server_task)

# 信号处理
def signal_handler(signum, frame):
    logger.info("收到关闭信号，正在清理...")
    
    stop_monitor()
    
    logger.info("程序退出")
    sys.exit(0)

if __name__ == '__main__':
    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 运行主程序
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        signal_handler(None, None)
