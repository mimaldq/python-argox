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
from aiohttp import web
from urllib.parse import urlparse, quote, urlencode
import yaml
import uuid as uuid_module
import requests

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
logger.info(f"创建文件夹: {FILE_PATH}")

# 全局变量
monitor_process = None
processes = []
sub_txt = ""
argo_domain = ""
sub_encoded = ""
app_started = False

# 用于统计连接
connection_counter = {
    "vless-argo": 0,
    "vmess-argo": 0,
    "trojan-argo": 0,
    "total": 0
}

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
    logger.info("Xray配置文件生成完成")

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
            logger.info(f"{php_name} 运行中")
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
            logger.info(f"{npm_name} 运行中")
            time.sleep(1)
    else:
        logger.info("哪吒监控变量为空，跳过运行")
    
    # 运行Xray
    cmd = f"{web_path} -c {config_path}"
    run_process(cmd, detach=True)
    logger.info(f"{web_name} 运行中")
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
        logger.info(f"{bot_name} 运行中")
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
        logger.error(f"运行监控脚本错误: {e}")

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
        pass  # 忽略错误

def get_meta_info_sync():
    """获取ISP信息（同步版本）- 改进版"""
    # 尝试多个IP信息API
    api_endpoints = [
        ('https://ipinfo.io/json', lambda data: f"{data.get('country', 'XX')}_{data.get('org', 'Unknown').split()[0] if data.get('org') else 'Unknown'}"),
        ('https://ipapi.co/json/', lambda data: f"{data.get('country_code', 'XX')}_{data.get('org', 'Unknown').split()[0] if data.get('org') else 'Unknown'}"),
        ('http://ip-api.com/json/', lambda data: f"{data.get('countryCode', 'XX')}_{data.get('org', 'Unknown').split()[0] if data.get('org') else 'Unknown'}" if data.get('status') == 'success' else None),
        ('https://api.ip.sb/geoip', lambda data: f"{data.get('country_code', 'XX')}_{data.get('organization', 'Unknown').split()[0] if data.get('organization') else 'Unknown'}"),
        ('https://api.myip.com', lambda data: f"{data.get('cc', 'XX')}_Unknown"),
    ]
    
    for url, parser in api_endpoints:
        try:
            # 设置合理的超时和头部
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json'
            }
            
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                result = parser(data)
                if result and 'Unknown' not in result:
                    logger.info(f"成功从 {url} 获取ISP信息: {result}")
                    return result
        except Exception as e:
            logger.debug(f"从 {url} 获取ISP信息失败: {e}")
            continue
    
    # 如果所有API都失败，尝试获取公共IP地址
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=3)
        if response.status_code == 200:
            ip_data = response.json()
            ip = ip_data.get('ip', '')
            if ip:
                # 使用IP地址作为标识
                return f"IP_{ip[:8]}"
    except Exception:
        pass
    
    logger.warning("所有ISP信息API都失败，使用默认值")
    return 'Unknown'

def generate_links(domain):
    """生成订阅链接"""
    global sub_txt, argo_domain, sub_encoded
    
    argo_domain = domain
    
    # 使用同步函数获取ISP信息
    ISP = get_meta_info_sync()
    logger.info(f"获取到ISP信息: {ISP}")
    
    # 清理ISP信息中的特殊字符
    ISP_clean = ISP.replace(' ', '_').replace('/', '_').replace('\\', '_').replace(':', '_')
    
    node_name = f"{NAME}-{ISP_clean}" if NAME else ISP_clean
    
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
    
    # 生成三种协议的配置
    vless_config = f"vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{node_name}"
    
    vmess_config_url = f"vmess://{vmess_base64}"
    
    trojan_config = f"trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{node_name}"
    
    sub_txt = f"{vless_config}\n\n{vmess_config_url}\n\n{trojan_config}"
    
    # 将订阅内容进行base64编码
    sub_encoded = base64.b64encode(sub_txt.encode()).decode()
    
    # 打印base64编码的订阅内容到控制台
    logger.info(f"订阅内容(base64编码):")
    print(sub_encoded)
    print("\n" + "="*60)
    
    # 保存到文件
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(sub_encoded)
    logger.info(f"订阅已保存到 {sub_path}")
    logger.info(f"节点域名: {argo_domain}")
    logger.info(f"节点名称: {node_name}")
    
    # 上传节点
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
            if response.status_code == 200:
                logger.info('订阅上传成功')
                return response
            else:
                logger.error(f'订阅上传失败，状态码: {response.status_code}')
                return None
        except Exception as e:
            logger.error(f'订阅上传失败: {e}')
            return None
    elif UPLOAD_URL:
        if not list_path.exists():
            return None
        
        try:
            with open(list_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            nodes = [line for line in content.split('\n') 
                    if any(proto in line for proto in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
            
            if not nodes:
                return None
            
            json_data = json.dumps({"nodes": nodes})
            
            response = requests.post(
                f"{UPLOAD_URL}/api/add-nodes",
                data=json_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            if response.status_code == 200:
                logger.info('节点上传成功')
                return response
            else:
                logger.error(f'节点上传失败，状态码: {response.status_code}')
                return None
        except Exception as e:
            logger.error(f'节点上传失败: {e}')
            return None
    else:
        return None

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
                pass  # 忽略错误
        
        logger.info('应用正在运行')
        logger.info('感谢使用此脚本，享受吧！')
    
    # 在新线程中运行清理
    threading.Thread(target=cleanup, daemon=True).start()

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

async def handle_index(request):
    """处理根路由"""
    index_path = Path(__file__).parent / 'index.html'
    if index_path.exists():
        return web.FileResponse(index_path)
    return web.Response(text="Hello world!")

async def handle_sub(request):
    """处理订阅路由"""
    global sub_encoded
    try:
        if not sub_encoded:
            # 如果没有订阅内容，尝试从文件读取
            try:
                if sub_path.exists():
                    with open(sub_path, 'r', encoding='utf-8') as f:
                        sub_encoded = f.read()
                        logger.info(f"从文件读取订阅内容，长度: {len(sub_encoded)}")
                else:
                    logger.warning("订阅文件不存在")
                    return web.Response(status=503, text="Subscription not ready yet. Please wait a moment and try again.")
            except Exception as e:
                logger.error(f"读取订阅文件失败: {e}")
                return web.Response(status=503, text="Subscription not ready yet. Please wait a moment and try again.")
        
        # 验证sub_encoded是否为有效的base64
        try:
            test = base64.b64decode(sub_encoded)
            logger.info(f"返回订阅内容，长度: {len(sub_encoded)}")
            return web.Response(
                text=sub_encoded,
                content_type='text/plain'
            )
        except Exception as e:
            logger.error(f"订阅内容base64解码失败: {e}")
            # 如果base64解码失败，返回原始文本作为备份
            if sub_txt:
                return web.Response(
                    text=sub_txt,
                    content_type='text/plain'
                )
            else:
                return web.Response(status=503, text="Subscription not ready yet. Please wait a moment and try again.")
    except Exception as e:
        logger.error(f"处理订阅请求时出错: {e}")
        return web.Response(status=500, text=f"Internal Server Error: {str(e)}")

async def handle_stats(request):
    """处理统计信息"""
    global connection_counter
    
    stats = {
        "connections": connection_counter,
        "timestamp": time.time(),
        "status": "running"
    }
    
    return web.json_response(stats)

async def proxy_xray_websocket(request):
    """代理WebSocket请求到Xray - 修复协议警告"""
    # 提取路径
    path = request.path
    query_string = request.query_string
    
    # 根据路径确定目标端口
    if path.startswith('/vless-argo'):
        target_port = 3003
        connection_type = "vless-argo"
    elif path.startswith('/vmess-argo'):
        target_port = 3004
        connection_type = "vmess-argo"
    elif path.startswith('/trojan-argo'):
        target_port = 3005
        connection_type = "trojan-argo"
    elif path in ['/vless', '/vmess', '/trojan']:
        target_port = 3001
        connection_type = path[1:]  # 移除开头的/
    else:
        # 未知路径，返回404
        return web.Response(status=404, text="Path not found")
    
    # 更新连接计数
    connection_counter[connection_type] += 1
    connection_counter["total"] += 1
    
    # 每100个连接打印一次统计
    if connection_counter["total"] % 100 == 0:
        logger.info(f"连接统计: VLESS={connection_counter['vless-argo']}, VMESS={connection_counter['vmess-argo']}, Trojan={connection_counter['trojan-argo']}, 总计={connection_counter['total']}")
    
    # 构建目标URL
    target_url = f"ws://localhost:{target_port}{path}"
    if query_string:
        target_url += f"?{query_string}"
    
    # 创建WebSocket响应
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    try:
        # 连接到目标WebSocket服务器
        async with aiohttp.ClientSession() as session:
            # 设置headers，但不包括Sec-WebSocket-Protocol，让服务器处理
            headers = {
                'User-Agent': request.headers.get('User-Agent', ''),
                'Origin': request.headers.get('Origin', ''),
            }
            
            # 不传递Sec-WebSocket-Protocol头部，避免协议不匹配警告
            # 如果客户端发送了Sec-WebSocket-Protocol，我们忽略它
            # 这样可以避免"don't overlap server-known ones"警告
            
            async with session.ws_connect(
                target_url,
                headers=headers,
                timeout=30
            ) as target_ws:
                
                # 双向转发数据 - 使用简单的转发，不记录每条消息
                client_to_target_task = asyncio.create_task(
                    forward_websocket_silent(ws, target_ws)
                )
                target_to_client_task = asyncio.create_task(
                    forward_websocket_silent(target_ws, ws)
                )
                
                # 等待任意一个任务完成
                done, pending = await asyncio.wait(
                    [client_to_target_task, target_to_client_task],
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
                        
    except Exception as e:
        # 减少错误日志输出
        logger.debug(f"WebSocket连接错误: {e}")
    
    # 连接关闭
    connection_counter[connection_type] -= 1
    connection_counter["total"] -= 1
    
    return ws

async def forward_websocket_silent(source, target):
    """静默转发WebSocket消息 - 不记录日志"""
    try:
        async for msg in source:
            if msg.type == aiohttp.WSMsgType.TEXT:
                await target.send_str(msg.data)
            elif msg.type == aiohttp.WSMsgType.BINARY:
                await target.send_bytes(msg.data)
            elif msg.type == aiohttp.WSMsgType.PING:
                await target.ping()
            elif msg.type == aiohttp.WSMsgType.PONG:
                await target.pong()
            elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED):
                await target.close()
                break
            elif msg.type == aiohttp.WSMsgType.ERROR:
                break
    except Exception:
        pass  # 忽略所有错误

async def proxy_xray_http(request):
    """代理HTTP请求到Xray - 静默版本"""
    # 提取路径和查询参数
    path = request.path
    query_string = request.query_string
    
    # 根据路径确定目标端口
    if path in ['/vless', '/vmess', '/trojan']:
        target_port = 3001
    elif path.startswith('/vless-argo') or path.startswith('/vmess-argo') or path.startswith('/trojan-argo'):
        target_port = 3001  # Xray会处理fallback到对应端口
    else:
        # 不是Xray路径，返回404
        return web.Response(status=404, text="Path not found")
    
    # 构建目标URL
    target_url = f"http://localhost:{target_port}{path}"
    if query_string:
        target_url += f"?{query_string}"
    
    # 转发请求
    try:
        # 获取原始请求的方法、头部和body
        method = request.method
        headers = dict(request.headers)
        
        # 移除不必要的头部
        headers.pop('Host', None)
        headers.pop('Content-Length', None)
        
        # 读取请求body
        if request.can_read_body:
            body = await request.read()
        else:
            body = None
        
        # 发送请求到目标服务器
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.request(
                method=method,
                url=target_url,
                headers=headers,
                data=body,
                allow_redirects=False
            ) as response:
                
                # 获取响应数据
                resp_body = await response.read()
                
                # 创建响应
                return web.Response(
                    body=resp_body,
                    status=response.status,
                    headers=dict(response.headers)
                )
                
    except Exception as e:
        return web.Response(status=502, text="Bad Gateway")

async def handle_health_check(request):
    """健康检查"""
    return web.Response(text="OK")

def start_server():
    """启动服务器"""
    global app_started
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
    
    app_started = True
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

async def init_app():
    """初始化aiohttp应用"""
    app = web.Application()
    
    # 健康检查
    app.router.add_get('/health', handle_health_check)
    
    # 统计信息
    app.router.add_get('/stats', handle_stats)
    
    # 首页
    app.router.add_get('/', handle_index)
    
    # 订阅 - 使用环境变量中的SUB_PATH
    app.router.add_get(f'/{SUB_PATH}', handle_sub)
    
    # WebSocket路由 - Xray流量
    xray_ws_paths = [
        '/vless-argo',
        '/vmess-argo', 
        '/trojan-argo',
        '/vless',
        '/vmess',
        '/trojan'
    ]
    
    for path in xray_ws_paths:
        app.router.add_get(path, proxy_xray_websocket)
    
    # 其他HTTP请求
    app.router.add_route('*', '/{path:.*}', proxy_xray_http)
    
    return app

async def start_aiohttp_server():
    """启动aiohttp服务器"""
    app = await init_app()
    
    # 创建运行器
    runner = web.AppRunner(app)
    await runner.setup()
    
    # 启动站点 - 监听所有地址的ARGO_PORT端口
    site = web.TCPSite(runner, '0.0.0.0', ARGO_PORT)
    await site.start()
    
    logger.info(f"服务器运行在端口 {ARGO_PORT}")
    logger.info(f"订阅地址: http://localhost:{ARGO_PORT}/{SUB_PATH}")
    
    return runner

def main():
    """主函数"""
    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 启动主服务（在新的线程中）
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # 启动监控脚本（在新的线程中，延迟10秒）
    def start_monitor():
        time.sleep(10)
        if download_monitor_script():
            run_monitor_script()
    
    monitor_thread = threading.Thread(target=start_monitor, daemon=True)
    monitor_thread.start()
    
    # 清理文件（在新的线程中）
    clean_thread = threading.Thread(target=clean_files, daemon=True)
    clean_thread.start()
    
    # 启动aiohttp服务器
    try:
        # 创建事件循环
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # 启动服务器
        runner = loop.run_until_complete(start_aiohttp_server())
        
        # 运行服务器
        logger.info("服务器启动成功")
        print(f"\n{'='*60}")
        print(f"服务器运行在端口 {ARGO_PORT}")
        print(f"订阅地址: http://localhost:{ARGO_PORT}/{SUB_PATH}")
        print(f"WebSocket路径: /vless-argo, /vmess-argo, /trojan-argo")
        print(f"状态统计: http://localhost:{ARGO_PORT}/stats")
        print(f"健康检查: http://localhost:{ARGO_PORT}/health")
        print(f"{'='*60}\n")
        
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            logger.info("用户停止服务器")
        finally:
            loop.run_until_complete(runner.cleanup())
            loop.close()
            
    except Exception as e:
        logger.error(f"启动服务器时出错: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    # 确保requests库可用
    try:
        import requests
    except ImportError:
        logger.error("请安装requests库: pip install requests")
        sys.exit(1)
    
    main()
