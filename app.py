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
from typing import Optional, Dict, List, Tuple

import requests
from aiohttp import web

# ==================== 日志配置 ====================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== 配置类 ====================

class Config:
    def __init__(self):
        # 基本配置
        self.UPLOAD_URL = os.environ.get('UPLOAD_URL', '')
        self.PROJECT_URL = os.environ.get('PROJECT_URL', '')
        self.AUTO_ACCESS = os.environ.get('AUTO_ACCESS', 'false').lower() == 'true'
        self.FILE_PATH = os.environ.get('FILE_PATH', '/app/data/tmp')
        self.SUB_PATH = os.environ.get('SUB_PATH', 'sub')
        self.PORT = int(os.environ.get('PORT', '3000'))
        self.ARGO_PORT = int(os.environ.get('ARGO_PORT', '7860'))
        self.UUID = os.environ.get('UUID', 'e2cae6af-5cdd-fa48-4137-ad3e617fbab0')
        
        # 哪吒监控配置
        self.NEZHA_SERVER = os.environ.get('NEZHA_SERVER', '')
        self.NEZHA_PORT = os.environ.get('NEZHA_PORT', '')
        self.NEZHA_KEY = os.environ.get('NEZHA_KEY', '')
        
        # Cloudflare隧道配置
        self.ARGO_DOMAIN = os.environ.get('ARGO_DOMAIN', '')
        self.ARGO_AUTH = os.environ.get('ARGO_AUTH', '')
        
        # 节点配置
        self.CFIP = os.environ.get('CFIP', 'cdns.doon.eu.org')
        self.CFPORT = int(os.environ.get('CFPORT', '443'))
        self.NAME = os.environ.get('NAME', '')
        
        # 监控配置
        self.MONITOR_KEY = os.environ.get('MONITOR_KEY', '')
        self.MONITOR_SERVER = os.environ.get('MONITOR_SERVER', '')
        self.MONITOR_URL = os.environ.get('MONITOR_URL', '')
        
        # 创建文件目录
        self.file_path = Path(self.FILE_PATH)
        self.file_path.mkdir(exist_ok=True, parents=True)
        
        logger.info("=" * 50)
        logger.info("配置初始化完成")
        logger.info(f"UUID: {self.UUID}")
        logger.info(f"内部HTTP端口: {self.PORT}")
        logger.info(f"外部代理端口: {self.ARGO_PORT}")
        logger.info(f"文件路径: {self.file_path}")
        logger.info("=" * 50)

# ==================== 全局变量 ====================

config = Config()
subscription = ""
argo_domain = ""
monitor_process = None
xray_process = None
cloudflared_process = None
nezha_process = None
monitor_restart_count = 0

# ==================== 工具函数 ====================

def generate_random_name(length=6):
    """生成随机文件名"""
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

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
        logger.info(f"下载文件: {url} -> {file_path}")
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

def stop_process(process: subprocess.Popen, name: str):
    """停止进程"""
    if process:
        try:
            logger.info(f"停止 {name} 进程 (PID: {process.pid})")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        except Exception as e:
            logger.error(f"停止 {name} 进程失败: {e}")

# ==================== 核心功能函数 ====================

def delete_nodes():
    """删除历史节点"""
    logger.info("清理历史节点...")
    # 在实际应用中实现此功能
    pass

def cleanup_old_files():
    """清理历史文件"""
    logger.info("清理旧文件...")
    try:
        for item in config.file_path.iterdir():
            if item.is_file():
                try:
                    item.unlink()
                except Exception:
                    pass
        logger.info("清理完成")
    except Exception as e:
        logger.error(f"清理文件时出错: {e}")

def generate_config():
    """生成Xray配置文件"""
    logger.info("生成Xray配置文件...")
    
    # 修复的配置 - 修正字符串引号问题
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

def argo_type():
    """生成固定隧道配置"""
    logger.info("配置Cloudflare隧道...")
    if not config.ARGO_AUTH or not config.ARGO_DOMAIN:
        logger.info("使用快速隧道模式")
        return
    
    if 'TunnelSecret' in config.ARGO_AUTH:
        try:
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
            
            logger.info("固定隧道配置生成成功")
        except Exception as e:
            logger.error(f"生成隧道配置错误: {e}")
    else:
        logger.info("使用Token连接隧道")

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
    logger.info("下载并启动必要组件...")
    
    architecture = get_system_architecture()
    files_to_download = get_files_for_architecture(architecture)
    
    if not files_to_download:
        logger.error("找不到适合当前架构的文件")
        return
    
    # 下载文件
    for file_info in files_to_download:
        if not download_file(file_info['url'], file_info['path']):
            logger.error(f"下载失败: {file_info['path'].name}")
    
    # 运行哪吒监控
    global nezha_process
    if config.NEZHA_SERVER and config.NEZHA_KEY:
        logger.info("启动哪吒监控...")
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
                logger.info(f"哪吒v1启动成功 (PID: {nezha_process.pid})")
                time.sleep(1)
            except Exception as e:
                logger.error(f"哪吒启动错误: {e}")
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
                logger.info(f"哪吒v0启动成功 (PID: {nezha_process.pid})")
                time.sleep(1)
            except Exception as e:
                logger.error(f"哪吒启动错误: {e}")
    else:
        logger.info("哪吒监控未配置，跳过")
    
    # 运行Xray
    global xray_process
    try:
        logger.info("启动Xray...")
        xray_process = subprocess.Popen(
            [str(web_path), "-c", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        logger.info(f"Xray启动成功 (PID: {xray_process.pid})")
        time.sleep(1)
    except Exception as e:
        logger.error(f"Xray启动错误: {e}")
    
    # 运行Cloudflared
    global cloudflared_process
    if bot_path.exists():
        logger.info("启动Cloudflared隧道...")
        args = ["tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2"]
        
        def is_valid_token(token):
            if not token:
                return False
            if not (120 <= len(token) <= 250):
                return False
            pattern = r'^[A-Za-z0-9+/=]+$'
            return bool(re.match(pattern, token))
        
        if config.ARGO_AUTH and config.ARGO_AUTH.strip():
            if is_valid_token(config.ARGO_AUTH):
                args.extend(["run", "--token", config.ARGO_AUTH])
            elif 'TunnelSecret' in config.ARGO_AUTH:
                if not tunnel_yaml_path.exists():
                    logger.info("等待隧道配置文件...")
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
            logger.info(f"Cloudflared启动成功 (PID: {cloudflared_process.pid})")
            logger.info("等待隧道启动...")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Cloudflared启动错误: {e}")
    
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
    """获取临时隧道域名"""
    global argo_domain
    
    if config.ARGO_AUTH and config.ARGO_DOMAIN:
        argo_domain = config.ARGO_DOMAIN
        logger.info(f'使用固定域名: {argo_domain}')
        generate_links(argo_domain)
        return
    
    try:
        if not boot_log_path.exists():
            logger.error("隧道日志文件不存在")
            restart_cloudflared()
            return
        
        with open(boot_log_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        domains = re.findall(r'https?://([^ ]*trycloudflare\.com)/?', content)
        
        if domains:
            argo_domain = domains[0]
            logger.info(f'找到临时域名: {argo_domain}')
            generate_links(argo_domain)
        else:
            logger.info('未找到域名，重新启动隧道...')
            restart_cloudflared()
    except Exception as e:
        logger.error(f'读取隧道日志错误: {e}')

def restart_cloudflared():
    """重启Cloudflared"""
    global cloudflared_process
    
    if cloudflared_process:
        stop_process(cloudflared_process, "cloudflared")
        cloudflared_process = None
    
    if boot_log_path.exists():
        boot_log_path.unlink()
    
    time.sleep(3)
    
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
        logger.info(f"Cloudflared重新启动 (PID: {cloudflared_process.pid})")
        time.sleep(3)
        extract_domains()
    except Exception as e:
        logger.error(f"重启隧道错误: {e}")

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
    
    logger.info("订阅内容生成完成")
    
    subscription = sub_txt
    
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(sub_txt.encode()).decode())
    
    logger.info(f"订阅文件保存到: {sub_path}")
    
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
        # 节点上传逻辑
        pass

def clean_files():
    """90秒后清理文件"""
    def cleanup():
        time.sleep(90)
        
        files_to_delete = [
            boot_log_path,
            config_path,
            web_path,
            bot_path,
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

# ==================== HTTP服务器 ====================

class HTTPServer:
    def __init__(self):
        self.app = web.Application()
        self.setup_routes()
    
    def setup_routes(self):
        async def handle_index(request):
            index_path = Path('index.html')
            if index_path.exists():
                return web.FileResponse(index_path)
            return web.Response(
                text="<h1>Proxy Server</h1><p>Server is running</p>",
                content_type='text/html'
            )
        
        async def handle_sub(request):
            global subscription
            if subscription:
                encoded = base64.b64encode(subscription.encode()).decode()
                return web.Response(text=encoded, content_type='text/plain; charset=utf-8')
            else:
                return web.Response(
                    text="Subscription is being generated, please refresh later...",
                    status=503,
                    content_type='text/plain'
                )
        
        async def handle_health(request):
            return web.Response(text="OK", content_type='text/plain')
        
        self.app.router.add_get('/', handle_index)
        self.app.router.add_get(f'/{config.SUB_PATH}', handle_sub)
        self.app.router.add_get('/health', handle_health)
    
    async def start(self, port):
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', port)
        await site.start()
        logger.info(f"HTTP服务器启动在端口: {port}")
        return runner

# ==================== 主函数 ====================

async def main():
    """主函数"""
    logger.info("=" * 50)
    logger.info("开始启动代理服务器")
    logger.info("=" * 50)
    
    # 初始化
    delete_nodes()
    cleanup_old_files()
    argo_type()
    generate_config()
    
    # 启动服务组件
    def start_services():
        download_files_and_run()
        time.sleep(5)
        extract_domains()
        add_visit_task()
        clean_files()
    
    # 在线程中启动服务
    services_thread = threading.Thread(target=start_services, daemon=True)
    services_thread.start()
    
    # 启动HTTP服务器
    http_server = HTTPServer()
    http_runner = await http_server.start(config.PORT)
    
    logger.info("=" * 50)
    logger.info("服务器启动完成")
    logger.info(f"访问地址: http://localhost:{config.PORT}/")
    logger.info(f"订阅地址: http://localhost:{config.PORT}/{config.SUB_PATH}")
    logger.info("=" * 50)
    
    try:
        # 保持运行
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        await http_runner.cleanup()
        logger.info("HTTP服务器已停止")
    finally:
        # 清理进程
        stop_process(monitor_process, "监控脚本")
        stop_process(xray_process, "Xray")
        stop_process(cloudflared_process, "Cloudflared")
        stop_process(nezha_process, "哪吒监控")

if __name__ == '__main__':
    # 信号处理
    def signal_handler(signum, frame):
        logger.info("收到关闭信号，正在退出...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 运行主程序
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("程序被用户中断")
    except Exception as e:
        logger.error(f"程序运行错误: {e}")
        import traceback
        traceback.print_exc()
