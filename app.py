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
import re
from pathlib import Path
from aiohttp import web

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

# 全局变量（使用锁保护）
global_lock = threading.Lock()
argo_domain = ""
sub_encoded = ""
connection_counter = {
    "vless-argo": 0,
    "vmess-argo": 0,
    "trojan-argo": 0,
    "total": 0
}
# 异步计数器保护锁
async_counter_lock = asyncio.Lock()

# 初始化状态标志
init_success = False
init_failed_event = threading.Event()

# 进程监控器
class ProcessMonitor:
    def __init__(self):
        self.processes = []  # 普通进程（不自动重启）
        self.watchdogs = {}   # {name: (process, restart_flag)}
        self.lock = threading.Lock()

    def add_process(self, process):
        """添加不需要自动重启的进程"""
        with self.lock:
            self.processes.append(process)

    def add_watchdog(self, name, cmd, restart=True):
        """添加需要监控的进程（自动重启）"""
        def watchdog_thread():
            while True:
                try:
                    logger.info(f"启动监控进程: {name}")
                    process = subprocess.Popen(
                        cmd,
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True
                    )
                    with self.lock:
                        self.watchdogs[name] = (process, restart)
                    process.wait()  # 等待进程退出
                    exit_code = process.returncode
                    logger.warning(f"进程 {name} 退出，退出码: {exit_code}")
                    if not restart:
                        break
                    logger.info(f"进程 {name} 将在5秒后重启")
                    time.sleep(5)
                except Exception as e:
                    logger.error(f"监控进程 {name} 出错: {e}")
                    if restart:
                        time.sleep(5)
        thread = threading.Thread(target=watchdog_thread, daemon=True)
        thread.start()

    def stop_all(self):
        """停止所有进程"""
        with self.lock:
            # 复制键列表，避免遍历时修改字典
            watchdogs_items = list(self.watchdogs.items())
            processes_copy = list(self.processes)
            self.watchdogs.clear()
            self.processes.clear()
        
        # 停止监控进程
        for name, (proc, _) in watchdogs_items:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
            except Exception as e:
                logger.error(f"停止进程 {name} 出错: {e}")
        # 停止普通进程
        for proc in processes_copy:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
            except Exception as e:
                logger.error(f"停止进程出错: {e}")

process_monitor = ProcessMonitor()

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
    try:
        arch = os.uname().machine.lower()
    except AttributeError:
        arch = os.environ.get('HOSTTYPE', '').lower()
    if 'arm' in arch or 'aarch64' in arch:
        return 'arm'
    return 'amd'

def download_file(url, filepath):
    """下载文件（使用with确保连接释放）"""
    try:
        with requests.get(url, stream=True, timeout=30) as response:
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
    """运行进程（不监控重启）"""
    try:
        if detach:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            process_monitor.add_process(process)
            return process
        else:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result
    except Exception as e:
        logger.error(f"运行命令 {cmd} 出错: {e}")
        return None

def argo_type():
    """配置Argo隧道类型 - 与Node.js保持一致"""
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

def download_files_and_run():
    """下载并运行依赖文件 - 健壮性增强"""
    global init_success
    architecture = get_system_architecture()
    files_to_download = get_files_for_architecture(architecture)
    
    if not files_to_download:
        logger.error("找不到适合当前架构的文件")
        init_failed_event.set()
        return
    
    # 下载文件，关键文件失败则设置失败标志并清理已启动进程
    for filepath, url in files_to_download:
        if not download_file(url, filepath):
            logger.error(f"下载 {filepath.name} 失败，初始化失败")
            process_monitor.stop_all()  # 停止所有已启动的进程
            init_failed_event.set()
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
    
    # 运行cloudflared - 使用监控进程实现自动重启
    if bot_path.exists():
        args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2"]
        
        # 检查ARGO_AUTH格式
        if ARGO_AUTH and re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
            logger.info("使用Token连接隧道")
            args.extend(["run", "--token", ARGO_AUTH])
        elif ARGO_AUTH and 'TunnelSecret' in ARGO_AUTH:
            if not tunnel_yaml_path.exists():
                logger.info("等待隧道配置文件生成...")
                time.sleep(1)
            if tunnel_yaml_path.exists():
                logger.info(f"使用配置文件连接隧道: {tunnel_yaml_path}")
                args.extend(["--config", str(tunnel_yaml_path), "run"])
            else:
                logger.warning("隧道配置文件不存在，使用快速隧道")
                args.extend(["--logfile", str(boot_log_path), "--loglevel", "info", "--url", f"http://localhost:{ARGO_PORT}"])
        else:
            logger.info(f"使用快速隧道，端口: {ARGO_PORT}")
            args.extend(["--logfile", str(boot_log_path), "--loglevel", "info", "--url", f"http://localhost:{ARGO_PORT}"])
        
        cmd = f"{bot_path} {' '.join(args)}"
        logger.info(f"启动cloudflared监控进程: {bot_name}")
        process_monitor.add_watchdog("cloudflared", cmd, restart=True)
    
    time.sleep(2)
    init_success = True

def download_monitor_script():
    """下载监控脚本"""
    if not MONITOR_KEY or not MONITOR_SERVER or not MONITOR_URL:
        logger.info("监控环境变量不完整，跳过监控脚本启动")
        return False
    
    monitor_url = "https://raw.githubusercontent.com/mimaldq/cf-vps-monitor/main/cf-vps-monitor.sh"
    logger.info(f"从 {monitor_url} 下载监控脚本")
    
    try:
        with requests.get(monitor_url, timeout=30) as response:
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
        
        process_monitor.add_process(process)
        logger.info("监控脚本已启动")
        
    except Exception as e:
        logger.error(f"运行监控脚本错误: {e}")

def extract_domains():
    """提取隧道域名"""
    global argo_domain
    
    # 如果是固定隧道，直接使用配置的域名
    if ARGO_AUTH and ARGO_DOMAIN:
        with global_lock:
            argo_domain = ARGO_DOMAIN
        logger.info(f'使用固定域名: {ARGO_DOMAIN}')
        generate_links(argo_domain)
        return
    
    # 否则从日志中提取临时域名
    try:
        if not boot_log_path.exists():
            logger.error("boot.log 文件不存在")
            # 等待5秒后重试
            time.sleep(5)
            if boot_log_path.exists():
                return extract_domains()
            else:
                logger.error("等待后boot.log仍不存在，可能隧道启动失败")
                return
        
        # 读取日志文件
        max_attempts = 10
        for attempt in range(max_attempts):
            try:
                with open(boot_log_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 查找域名 - 使用简单的正则表达式
                pattern = r'https?://([^ \n]*trycloudflare\.com)'
                matches = re.findall(pattern, content)
                
                if matches:
                    with global_lock:
                        argo_domain = matches[0]
                    logger.info(f'找到临时域名: {argo_domain}')
                    generate_links(argo_domain)
                    return
                
                # 如果没找到，等待一下再重试
                if attempt < max_attempts - 1:
                    logger.info(f'未找到域名，等待3秒后重试 ({attempt + 1}/{max_attempts})')
                    time.sleep(3)
                    
            except Exception as e:
                logger.error(f'读取boot.log错误: {e}')
                break
        
        logger.error(f'经过{max_attempts}次尝试仍未找到域名')
        
    except Exception as e:
        logger.error(f'提取域名过程中出错: {e}')

def get_meta_info_sync():
    """获取ISP信息（同步版本）"""
    try:
        with requests.get('https://ipapi.co/json/', timeout=5) as response1:
            if response1.status_code == 200:
                data1 = response1.json()
                country_code = data1.get('country_code')
                org = data1.get('org')
                if country_code and org:
                    org_clean = org.replace(' ', '_').replace('.', '_').replace(',', '_')
                    return f"{country_code}_{org_clean}"
    except Exception as e:
        logger.debug(f"ipapi.co请求失败: {e}")
    
    try:
        with requests.get('http://ip-api.com/json/', timeout=5) as response2:
            if response2.status_code == 200:
                data2 = response2.json()
                if data2.get('status') == 'success':
                    country_code = data2.get('countryCode')
                    org = data2.get('org')
                    if country_code and org:
                        org_clean = org.replace(' ', '_').replace('.', '_').replace(',', '_')
                        return f"{country_code}_{org_clean}"
    except Exception as e:
        logger.debug(f"ip-api.com请求失败: {e}")
    
    try:
        import socket
        hostname = socket.gethostname()
        return f"Host_{hostname}"
    except Exception:
        pass
    
    return 'Unknown'

def generate_links(domain):
    """生成订阅链接"""
    global sub_encoded
    
    with global_lock:
        argo_domain = domain
    
    ISP = get_meta_info_sync()
    logger.info(f"获取到ISP信息: {ISP}")
    
    if NAME:
        node_name = f"{NAME}-{ISP}"
    else:
        node_name = ISP
    
    logger.info(f"节点名称: {node_name}")
    
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
    
    vmess_json = json.dumps(vmess_config, separators=(',', ':'))
    vmess_base64 = base64.b64encode(vmess_json.encode()).decode()
    
    vless_config = f"vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{node_name}"
    vmess_config_url = f"vmess://{vmess_base64}"
    trojan_config = f"trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{node_name}"
    
    sub_txt = f"{vless_config}\n\n{vmess_config_url}\n\n{trojan_config}"
    
    with global_lock:
        sub_encoded = base64.b64encode(sub_txt.encode()).decode()
    
    logger.info("订阅内容(base64编码):")
    print(sub_encoded)
    print("\n" + "="*60)
    
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(sub_encoded)
    logger.info(f"订阅已保存到 {sub_path}")
    logger.info(f"节点域名: {argo_domain}")
    logger.info(f"节点名称: {node_name}")
    
    upload_nodes()

def upload_nodes():
    """上传节点或订阅"""
    if UPLOAD_URL and PROJECT_URL:
        subscription_url = f"{PROJECT_URL}/{SUB_PATH}"
        json_data = {
            "subscription": [subscription_url]
        }
        try:
            with requests.post(
                f"{UPLOAD_URL}/api/add-subscriptions",
                json=json_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            ) as response:
                if response.status_code == 200:
                    logger.info('订阅上传成功')
                else:
                    logger.error(f'订阅上传失败，状态码: {response.status_code}')
        except Exception as e:
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
            
            with requests.post(
                f"{UPLOAD_URL}/api/add-nodes",
                data=json_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            ) as response:
                if response.status_code == 200:
                    logger.info('节点上传成功')
                else:
                    logger.error(f'节点上传失败，状态码: {response.status_code}')
        except Exception as e:
            logger.error(f'节点上传失败: {e}')

def cleanup_files_on_exit():
    """退出时清理临时文件"""
    files_to_delete = [boot_log_path, config_path, web_path, bot_path, monitor_path, sub_path]
    if NEZHA_PORT:
        files_to_delete.append(npm_path)
    elif NEZHA_SERVER and NEZHA_KEY:
        files_to_delete.append(php_path)
    
    for file in files_to_delete:
        try:
            if file.exists():
                file.unlink()
                logger.debug(f"已删除临时文件: {file}")
        except Exception as e:
            logger.warning(f"删除文件失败 {file}: {e}")
    logger.info("临时文件清理完成")

def add_visit_task():
    """添加自动访问任务"""
    if not AUTO_ACCESS or not PROJECT_URL:
        logger.info("跳过自动访问任务")
        return
    
    try:
        with requests.post(
            'https://oooo.serv00.net/add-url',
            json={'url': PROJECT_URL},
            headers={'Content-Type': 'application/json'},
            timeout=10
        ) as response:
            if response.status_code == 200:
                logger.info("自动访问任务添加成功")
            else:
                logger.error(f"添加自动访问任务失败，状态码: {response.status_code}")
    except Exception as e:
        logger.error(f"添加自动访问任务失败: {e}")

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
        # 读取全局变量（使用锁保护）
        with global_lock:
            encoded = sub_encoded
        
        if not encoded:
            # 如果没有订阅内容，尝试从文件读取
            try:
                if sub_path.exists():
                    with open(sub_path, 'r', encoding='utf-8') as f:
                        encoded = f.read()
                        with global_lock:
                            sub_encoded = encoded
                        logger.info(f"从文件读取订阅内容，长度: {len(encoded)}")
                else:
                    logger.warning("订阅文件不存在")
                    return web.Response(status=503, text="Subscription not ready yet. Please wait a moment and try again.")
            except Exception as e:
                logger.error(f"读取订阅文件失败: {e}")
                return web.Response(status=503, text="Subscription not ready yet. Please wait a moment and try again.")
        
        # 验证是否为有效的base64
        try:
            test = base64.b64decode(encoded)
            logger.info(f"返回订阅内容，长度: {len(encoded)}")
            return web.Response(
                text=encoded,
                content_type='text/plain'
            )
        except Exception as e:
            logger.error(f"订阅内容base64解码失败: {e}")
            return web.Response(status=500, text="Invalid subscription format")
    except Exception as e:
        logger.error(f"处理订阅请求时出错: {e}")
        return web.Response(status=500, text=f"Internal Server Error: {str(e)}")

async def handle_stats(request):
    """处理统计信息"""
    with global_lock:
        stats = {
            "connections": connection_counter.copy(),
            "timestamp": time.time(),
            "status": "running"
        }
    return web.json_response(stats)

async def proxy_xray_websocket(request):
    """代理WebSocket请求到Xray - 优化版本"""
    path = request.path
    query_string = request.query_string
    
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
        connection_type = path[1:]
    else:
        return web.Response(status=404, text="Path not found")
    
    # 增加连接计数（异步安全）
    async with async_counter_lock:
        with global_lock:
            connection_counter[connection_type] += 1
            connection_counter["total"] += 1
            current_total = connection_counter["total"]
            if current_total % 100 == 0:
                logger.info(f"连接统计: VLESS={connection_counter['vless-argo']}, VMESS={connection_counter['vmess-argo']}, Trojan={connection_counter['trojan-argo']}, 总计={connection_counter['total']}")
    
    target_url = f"ws://localhost:{target_port}{path}"
    if query_string:
        target_url += f"?{query_string}"
    
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    try:
        async with aiohttp.ClientSession() as session:
            headers = {
                'User-Agent': request.headers.get('User-Agent', ''),
                'Origin': request.headers.get('Origin', ''),
                'Sec-WebSocket-Protocol': request.headers.get('Sec-WebSocket-Protocol', ''),
            }
            
            async with session.ws_connect(
                target_url,
                headers=headers,
                timeout=30
            ) as target_ws:
                
                client_to_target_task = asyncio.create_task(
                    forward_websocket_silent(ws, target_ws)
                )
                target_to_client_task = asyncio.create_task(
                    forward_websocket_silent(target_ws, ws)
                )
                
                done, pending = await asyncio.wait(
                    [client_to_target_task, target_to_client_task],
                    return_when=asyncio.FIRST_COMPLETED
                )
                
                for task in pending:
                    task.cancel()
                
                for task in pending:
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
    except Exception as e:
        logger.debug(f"WebSocket代理错误: {e}")
    finally:
        # 减少连接计数（异步安全）
        async with async_counter_lock:
            with global_lock:
                connection_counter[connection_type] -= 1
                connection_counter["total"] -= 1
    
    return ws

async def forward_websocket_silent(source, target):
    """静默转发WebSocket消息"""
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
        pass

async def proxy_xray_http(request):
    """代理HTTP请求到Xray"""
    path = request.path
    query_string = request.query_string
    
    if path in ['/vless', '/vmess', '/trojan']:
        target_port = 3001
    elif path.startswith('/vless-argo') or path.startswith('/vmess-argo') or path.startswith('/trojan-argo'):
        target_port = 3001
    else:
        return web.Response(status=404, text="Path not found")
    
    target_url = f"http://localhost:{target_port}{path}"
    if query_string:
        target_url += f"?{query_string}"
    
    try:
        method = request.method
        headers = dict(request.headers)
        headers.pop('Host', None)
        headers.pop('Content-Length', None)
        
        if request.can_read_body:
            body = await request.read()
        else:
            body = None
        
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.request(
                method=method,
                url=target_url,
                headers=headers,
                data=body,
                allow_redirects=False
            ) as response:
                
                resp_body = await response.read()
                
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
    logger.info('开始服务器初始化...')
    
    delete_nodes()
    cleanup_old_files()
    
    argo_type()
    generate_config()
    download_files_and_run()
    
    if init_failed_event.is_set():
        logger.error("初始化失败，退出")
        return
    
    logger.info('等待隧道启动...')
    time.sleep(5)
    
    extract_domains()
    add_visit_task()
    
    logger.info('服务器初始化完成')

def signal_handler(signum, frame):
    """信号处理"""
    logger.info("收到关闭信号，正在清理...")
    
    # 停止所有子进程
    process_monitor.stop_all()
    
    # 清理临时文件
    cleanup_files_on_exit()
    
    # 停止事件循环
    loop = asyncio.get_event_loop()
    if loop.is_running():
        loop.stop()
    
    logger.info("程序退出")
    os._exit(0)  # 强制退出，避免残留

async def init_app():
    """初始化aiohttp应用"""
    app = web.Application()
    
    app.router.add_get('/health', handle_health_check)
    app.router.add_get('/stats', handle_stats)
    app.router.add_get('/', handle_index)
    app.router.add_get(f'/{SUB_PATH}', handle_sub)
    
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
    
    app.router.add_route('*', '/{path:.*}', proxy_xray_http)
    
    return app

async def start_aiohttp_server():
    """启动aiohttp服务器"""
    app = await init_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', ARGO_PORT)
    await site.start()
    
    logger.info(f"服务器运行在端口 {ARGO_PORT}")
    logger.info(f"订阅地址: http://localhost:{ARGO_PORT}/{SUB_PATH}")
    
    return runner

def main():
    """主函数"""
    # 检查依赖
    try:
        import requests
        import aiohttp
    except ImportError as e:
        logger.error(f"缺少依赖库: {e}. 请运行: pip install requests aiohttp")
        sys.exit(1)
    
    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 启动主服务
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # 等待初始化结果（最多60秒）
    if not init_failed_event.wait(timeout=60):
        logger.error("初始化超时")
        sys.exit(1)
    if not init_success:
        logger.error("初始化失败，退出")
        sys.exit(1)
    
    # 启动监控脚本
    def start_monitor():
        time.sleep(10)
        if download_monitor_script():
            run_monitor_script()
    
    monitor_thread = threading.Thread(target=start_monitor, daemon=True)
    monitor_thread.start()
    
    # 启动aiohttp服务器
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        runner = loop.run_until_complete(start_aiohttp_server())
        
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
    main()
