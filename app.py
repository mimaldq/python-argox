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
from urllib.parse import urlparse, quote
import yaml
import uuid as uuid_module

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
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
logger.info(f"{FILE_PATH} created or already exists")

# 全局变量
monitor_process = None
processes = []
sub_txt = ""
argo_domain = ""

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
                logger.error(f"Error killing process: {e}")

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
                logger.info("Nodes deleted successfully")
        except Exception as e:
            logger.error(f"Error deleting nodes: {e}")
    except Exception as e:
        logger.error(f"Error in delete_nodes: {e}")

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
        logger.error(f"Error cleaning old files: {e}")

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
        logger.info(f"Downloaded {filepath.name} successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to download {url}: {e}")
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
        logger.error(f"Error running command {cmd}: {e}")
        return None

def download_files_and_run():
    """下载并运行依赖文件"""
    architecture = get_system_architecture()
    files_to_download = get_files_for_architecture(architecture)
    
    if not files_to_download:
        logger.error("No files found for current architecture")
        return
    
    # 下载文件
    for filepath, url in files_to_download:
        if not download_file(url, filepath):
            logger.error(f"Failed to download {filepath.name}")
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
            logger.info(f"{php_name} is running")
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
            logger.info(f"{npm_name} is running")
            time.sleep(1)
    else:
        logger.info("Nezha variables are empty, skipping")
    
    # 运行Xray
    cmd = f"{web_path} -c {config_path}"
    run_process(cmd, detach=True)
    logger.info(f"{web_name} is running")
    time.sleep(1)
    
    # 运行cloudflared
    if bot_path.exists():
        args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2"]
        
        if ARGO_AUTH and ARGO_AUTH.strip() and len(ARGO_AUTH.strip()) >= 120 and len(ARGO_AUTH.strip()) <= 250:
            args.extend(["run", "--token", ARGO_AUTH.strip()])
        elif ARGO_AUTH and 'TunnelSecret' in ARGO_AUTH:
            # 确保隧道配置文件存在
            if not tunnel_yaml_path.exists():
                logger.info("Waiting for tunnel config file generation...")
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
        logger.info(f"{bot_name} is running")
        time.sleep(5)
    
    time.sleep(2)

def argo_type():
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

def download_monitor_script():
    """下载监控脚本"""
    if not MONITOR_KEY or not MONITOR_SERVER or not MONITOR_URL:
        logger.info("Monitor environment variables incomplete, skipping monitor script")
        return False
    
    monitor_url = "https://raw.githubusercontent.com/mimaldq/cf-vps-monitor/main/cf-vps-monitor.sh"
    logger.info(f"Downloading monitor script from {monitor_url}")
    
    try:
        response = requests.get(monitor_url, timeout=30)
        response.raise_for_status()
        
        with open(monitor_path, 'wb') as f:
            f.write(response.content)
        
        monitor_path.chmod(0o755)
        logger.info("Monitor script downloaded successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to download monitor script: {e}")
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

def extract_domains():
    """提取隧道域名"""
    global argo_domain
    
    if ARGO_AUTH and ARGO_DOMAIN:
        argo_domain = ARGO_DOMAIN
        logger.info(f'Using fixed domain: {argo_domain}')
        generate_links(argo_domain)
    else:
        try:
            if not boot_log_path.exists():
                logger.error("boot.log not found")
                return
            
            with open(boot_log_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import re
            domains = re.findall(r'https?://([^ ]*trycloudflare\.com)', content)
            
            if domains:
                argo_domain = domains[0]
                logger.info(f'Found temporary domain: {argo_domain}')
                generate_links(argo_domain)
            else:
                logger.info('Domain not found, restarting bot to get Argo domain')
                boot_log_path.unlink(missing_ok=True)
                
                # 停止现有的cloudflared进程
                kill_bot_process()
                time.sleep(3)
                
                # 重新启动cloudflared
                cmd = f"nohup {bot_path} tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {boot_log_path} --loglevel info --url http://localhost:{ARGO_PORT} >/dev/null 2>&1 &"
                run_process(cmd, detach=True)
                logger.info(f"{bot_name} restarted")
                time.sleep(3)
                extract_domains()
        except Exception as e:
            logger.error(f'Error reading boot.log: {e}')

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

async def get_meta_info():
    """获取ISP信息"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://ipapi.co/json/', timeout=3) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('country_code') and data.get('org'):
                        return f"{data['country_code']}_{data['org']}"
    except Exception:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('http://ip-api.com/json/', timeout=3) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('status') == 'success' and data.get('countryCode') and data.get('org'):
                            return f"{data['countryCode']}_{data['org']}"
        except Exception:
            pass
    
    return 'Unknown'

def generate_links(domain):
    """生成订阅链接"""
    global sub_txt, argo_domain
    argo_domain = domain
    
    # 同步方式调用异步函数
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        ISP = loop.run_until_complete(get_meta_info())
    finally:
        loop.close()
    
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
        "host": argo_domain,
        "path": "/vmess-argo?ed=2560",
        "tls": "tls",
        "sni": argo_domain,
        "alpn": "",
        "fp": "firefox"
    }
    
    vmess_base64 = base64.b64encode(json.dumps(vmess_config).encode()).decode()
    
    # 转义路径中的特殊字符
    encoded_path = quote("/vless-argo?ed=2560", safe='')
    
    sub_txt = f"""vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path={encoded_path}#{node_name}

vmess://{vmess_base64}

trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path={encoded_path.replace('vless', 'trojan')}#{node_name}
"""
    
    # 打印base64编码的订阅内容
    encoded_content = base64.b64encode(sub_txt.encode()).decode()
    logger.info(f"Subscription content (base64): {encoded_content}")
    
    # 保存到文件
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(encoded_content)
    logger.info(f"{sub_path} saved successfully")
    
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
                logger.info('Subscription uploaded successfully')
                return response
            else:
                logger.error(f'Upload failed with status code: {response.status_code}')
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
                logger.info('Nodes uploaded successfully')
                return response
            else:
                logger.error(f'Upload failed with status code: {response.status_code}')
                return None
        except Exception as e:
            logger.error(f'Failed to upload nodes: {e}')
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
        
        logger.info('Application is running')
        logger.info('Thank you for using this script, enjoy!')
    
    # 在新线程中运行清理
    threading.Thread(target=cleanup, daemon=True).start()

def add_visit_task():
    """添加自动访问任务"""
    if not AUTO_ACCESS or not PROJECT_URL:
        logger.info("Skipping auto-access task")
        return None
    
    try:
        response = requests.post(
            'https://oooo.serv00.net/add-url',
            json={'url': PROJECT_URL},
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        logger.info("Auto-access task added successfully")
        return response
    except Exception as e:
        logger.error(f"Failed to add auto-access task: {e}")
        return None

async def handle_index(request):
    """处理根路由"""
    index_path = Path(__file__).parent / 'index.html'
    if index_path.exists():
        return web.FileResponse(index_path)
    return web.Response(text="Hello world!")

async def handle_sub(request):
    """处理订阅路由"""
    global sub_txt
    if not sub_txt:
        return web.Response(status=404, text="Subscription not ready")
    
    encoded_content = base64.b64encode(sub_txt.encode()).decode()
    return web.Response(
        text=encoded_content,
        content_type='text/plain; charset=utf-8'
    )

async def websocket_handler(request):
    """处理WebSocket连接，转发到Xray"""
    # 获取路径
    path = request.path
    
    # 确定转发目标端口
    if path.startswith('/vless-argo'):
        target_port = 3003
    elif path.startswith('/vmess-argo'):
        target_port = 3004
    elif path.startswith('/trojan-argo'):
        target_port = 3005
    elif path == '/vless' or path == '/vmess' or path == '/trojan':
        target_port = 3001
    else:
        # 如果不是已知的WebSocket路径，返回404
        return web.Response(status=404)
    
    # 构建目标URL
    target_url = f"ws://localhost:{target_port}{path}"
    
    # 如果有查询参数，添加到目标URL
    if request.query_string:
        target_url += f"?{request.query_string}"
    
    logger.info(f"Proxying WebSocket from {path} to {target_url}")
    
    # 创建WebSocket响应
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    try:
        # 连接到目标WebSocket服务器
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(target_url) as target_ws:
                # 创建两个任务来双向转发数据
                client_to_target = asyncio.create_task(forward_websocket(ws, target_ws, "client->target"))
                target_to_client = asyncio.create_task(forward_websocket(target_ws, ws, "target->client"))
                
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
    except Exception as e:
        logger.error(f"Error proxying WebSocket: {e}")
        if not ws.closed:
            await ws.close()
    
    return ws

async def forward_websocket(source_ws, target_ws, label):
    """转发WebSocket消息"""
    try:
        async for msg in source_ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                await target_ws.send_str(msg.data)
            elif msg.type == aiohttp.WSMsgType.BINARY:
                await target_ws.send_bytes(msg.data)
            elif msg.type == aiohttp.WSMsgType.CLOSE:
                await target_ws.close()
                break
            elif msg.type == aiohttp.WSMsgType.ERROR:
                logger.error(f"WebSocket error in {label}: {source_ws.exception()}")
                break
    except Exception as e:
        logger.error(f"Error in {label}: {e}")
        if not target_ws.closed:
            await target_ws.close()

async def http_proxy_handler(request):
    """处理HTTP代理请求"""
    # 获取路径
    path = request.path
    
    # 确定转发目标端口
    if path.startswith('/vless-argo') or path.startswith('/vmess-argo') or path.startswith('/trojan-argo'):
        target_port = 3001
    else:
        target_port = PORT
    
    # 构建目标URL
    target_url = f"http://localhost:{target_port}{path}"
    if request.query_string:
        target_url += f"?{request.query_string}"
    
    logger.info(f"Proxying HTTP from {path} to {target_url}")
    
    # 转发HTTP请求
    try:
        async with aiohttp.ClientSession() as session:
            # 获取原始请求的方法、头部和body
            method = request.method
            headers = dict(request.headers)
            
            # 移除不必要的头部
            headers.pop('Host', None)
            
            # 读取请求body
            if request.can_read_body:
                body = await request.read()
            else:
                body = None
            
            # 发送请求到目标服务器
            async with session.request(
                method=method,
                url=target_url,
                headers=headers,
                data=body,
                timeout=aiohttp.ClientTimeout(total=30)
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
        logger.error(f"Error proxying HTTP request: {e}")
        return web.Response(status=502, text="Bad Gateway")

def start_server():
    """启动服务器"""
    logger.info('Starting server initialization...')
    
    delete_nodes()
    cleanup_old_files()
    
    argo_type()
    generate_config()
    download_files_and_run()
    
    # 等待隧道启动
    logger.info('Waiting for tunnel startup...')
    time.sleep(5)
    
    extract_domains()
    add_visit_task()
    
    logger.info('Server initialization complete')

def signal_handler(signum, frame):
    """信号处理"""
    logger.info("Received shutdown signal, cleaning up...")
    
    if monitor_process and monitor_process.poll() is None:
        logger.info("Stopping monitor script...")
        monitor_process.terminate()
    
    process_manager.cleanup()
    
    logger.info("Program exited")
    sys.exit(0)

async def init_app():
    """初始化aiohttp应用"""
    app = web.Application()
    
    # 添加路由
    app.router.add_get('/', handle_index)
    app.router.add_get(f'/{SUB_PATH}', handle_sub)
    
    # WebSocket路由
    ws_routes = [
        '/vless-argo', '/vmess-argo', '/trojan-argo',
        '/vless', '/vmess', '/trojan'
    ]
    
    # 为每个WebSocket路由添加处理器
    for route in ws_routes:
        app.router.add_get(route, websocket_handler)
    
    # 其他HTTP请求使用代理
    app.router.add_route('*', '/{path:.*}', http_proxy_handler)
    
    return app

async def start_aiohttp_server():
    """启动aiohttp服务器"""
    app = await init_app()
    
    # 创建运行器
    runner = web.AppRunner(app)
    await runner.setup()
    
    # 启动站点
    site = web.TCPSite(runner, '0.0.0.0', ARGO_PORT)
    await site.start()
    
    logger.info(f"aiohttp server running on port {ARGO_PORT}")
    
    # 保持服务器运行
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
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        logger.info(f"Starting aiohttp server on port {ARGO_PORT}")
        logger.info(f"HTTP traffic -> localhost:{PORT}")
        logger.info(f"Xray WebSocket traffic -> localhost:3001,3003,3004,3005")
        
        runner = loop.run_until_complete(start_aiohttp_server())
        
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
        finally:
            loop.run_until_complete(runner.cleanup())
    except Exception as e:
        logger.error(f"Error starting aiohttp server: {e}")

if __name__ == '__main__':
    # 确保requests库可用
    try:
        import requests
    except ImportError:
        logger.error("Please install requests library: pip install requests")
        sys.exit(1)
    
    main()
