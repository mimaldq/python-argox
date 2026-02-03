import asyncio
import os
import sys
import json
import random
import string
import subprocess
import time
import logging
import signal
import base64
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime

import aiohttp
from aiohttp import web, ClientSession, WSMsgType, ClientTimeout
import aiofiles
import aiofiles.os
import yaml
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

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

# 创建运行目录
FILE_PATH = Path(FILE_PATH)
FILE_PATH.mkdir(exist_ok=True, parents=True)

# 生成随机文件名
def generate_random_name(length: int = 6) -> str:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

# 全局变量
npm_name = generate_random_name()
web_name = generate_random_name()
bot_name = generate_random_name()
php_name = generate_random_name()
monitor_name = 'cf-vps-monitor.sh'

npm_path = FILE_PATH / npm_name
web_path = FILE_PATH / web_name
bot_path = FILE_PATH / bot_name
php_path = FILE_PATH / php_name
monitor_path = FILE_PATH / monitor_name
sub_path = FILE_PATH / 'sub.txt'
list_path = FILE_PATH / 'list.txt'
boot_log_path = FILE_PATH / 'boot.log'
config_path = FILE_PATH / 'config.json'
tunnel_json_path = FILE_PATH / 'tunnel.json'
tunnel_yaml_path = FILE_PATH / 'tunnel.yml'

# 进程存储
processes = {}
monitor_process = None
xray_domains = None

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ProxyServer:
    """代理服务器，处理WebSocket升级和HTTP转发"""
    
    def __init__(self, http_port: int = PORT, xray_port: int = 3001):
        self.http_port = http_port
        self.xray_port = xray_port
        self.app = web.Application()
        self.setup_routes()
        
        # WebSocket路由映射
        self.ws_routes = {
            '/vless-argo': 3003,  # vless over WebSocket
            '/vmess-argo': 3004,  # vmess over WebSocket
            '/trojan-argo': 3005,  # trojan over WebSocket
        }
        
        # HTTP代理路由映射
        self.http_proxy_routes = {
            '/vless': self.xray_port,  # vless over TCP
            '/vmess': self.xray_port,  # vmess over TCP
            '/trojan': self.xray_port,  # trojan over TCP
        }
        
        # WebSocket连接池
        self.ws_connections: Set[web.WebSocketResponse] = set()
    
    def setup_routes(self):
        """设置路由"""
        self.app.router.add_get('/', self.handle_root)
        self.app.router.add_get(f'/{SUB_PATH}', self.handle_subscription)
        self.app.router.add_route('*', '/{path:.*}', self.handle_proxy)
    
    async def handle_root(self, request: web.Request) -> web.Response:
        """处理根路径"""
        index_path = Path('index.html')
        if index_path.exists():
            try:
                async with aiofiles.open(index_path, 'r') as f:
                    content = await f.read()
                return web.Response(text=content, content_type='text/html')
            except:
                return web.Response(text='Hello world!')
        else:
            return web.Response(text='Hello world!')
    
    async def handle_subscription(self, request: web.Request) -> web.Response:
        """处理订阅请求"""
        try:
            if sub_path.exists():
                async with aiofiles.open(sub_path, 'r') as f:
                    content = await f.read()
                return web.Response(text=content, content_type='text/plain; charset=utf-8')
            else:
                return web.Response(status=404, text='Subscription not found')
        except:
            return web.Response(status=500, text='Internal server error')
    
    async def handle_proxy(self, request: web.Request) -> web.StreamResponse:
        """处理代理请求"""
        # 检查是否是WebSocket升级请求
        if request.headers.get('Upgrade', '').lower() == 'websocket':
            return await self.handle_websocket_upgrade(request)
        else:
            return await self.handle_http_request(request)
    
    async def handle_websocket_upgrade(self, request: web.Request) -> web.WebSocketResponse:
        """处理WebSocket升级请求"""
        path = request.path
        
        # 检查是否是Xray WebSocket路由
        for ws_route, target_port in self.ws_routes.items():
            if path.startswith(ws_route):
                return await self.proxy_websocket(request, 'localhost', target_port, path)
        
        # 如果不是Xray WebSocket路由，返回404
        logger.warning(f"未知的WebSocket路径: {path}")
        return web.Response(status=404, text='Not Found')
    
    async def proxy_websocket(self, request: web.Request, target_host: str, target_port: int, path: str) -> web.WebSocketResponse:
        """代理WebSocket连接到目标服务器"""
        logger.info(f"代理WebSocket: {path} -> {target_host}:{target_port}")
        
        # 创建WebSocket响应
        ws_response = web.WebSocketResponse()
        await ws_response.prepare(request)
        self.ws_connections.add(ws_response)
        
        try:
            # 构建目标URL
            target_url = f"ws://{target_host}:{target_port}{path}"
            if request.query_string:
                target_url = f"{target_url}?{request.query_string}"
            
            # 准备请求头
            headers = dict(request.headers)
            headers.pop('Host', None)
            
            # 连接到目标WebSocket服务器
            timeout = ClientTimeout(total=30)
            async with ClientSession(timeout=timeout) as session:
                async with session.ws_connect(
                    target_url,
                    headers=headers,
                    autoclose=False,
                    autoping=False
                ) as ws_target:
                    
                    logger.info(f"WebSocket连接建立: {path}")
                    
                    # 创建双向转发任务
                    client_to_target = asyncio.create_task(
                        self.forward_ws_messages(ws_response, ws_target, "client->target")
                    )
                    target_to_client = asyncio.create_task(
                        self.forward_ws_messages(ws_target, ws_response, "target->client")
                    )
                    
                    # 等待任一任务完成
                    done, pending = await asyncio.wait(
                        [client_to_target, target_to_client],
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    
                    # 取消未完成的任务
                    for task in pending:
                        task.cancel()
                    
                    # 清理
                    try:
                        await ws_target.close()
                    except:
                        pass
                    
        except Exception as e:
            logger.error(f"WebSocket代理错误: {e}")
        finally:
            self.ws_connections.discard(ws_response)
            try:
                await ws_response.close()
            except:
                pass
        
        return ws_response
    
    async def forward_ws_messages(self, source, target, direction: str):
        """转发WebSocket消息"""
        try:
            async for msg in source:
                if msg.type == WSMsgType.TEXT:
                    await target.send_str(msg.data)
                elif msg.type == WSMsgType.BINARY:
                    await target.send_bytes(msg.data)
                elif msg.type == WSMsgType.PING:
                    await target.ping(msg.data)
                elif msg.type == WSMsgType.PONG:
                    await target.pong(msg.data)
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR, WSMsgType.CLOSED):
                    break
        except Exception as e:
            logger.debug(f"WebSocket转发错误 ({direction}): {e}")
    
    async def handle_http_request(self, request: web.Request) -> web.StreamResponse:
        """处理HTTP请求"""
        path = request.path
        
        # 检查是否是Xray HTTP代理路由
        for http_route, target_port in self.http_proxy_routes.items():
            if path.startswith(http_route):
                return await self.proxy_http_request(request, 'localhost', target_port)
        
        # 如果不是代理路由，转发到HTTP服务器
        return await self.proxy_http_request(request, 'localhost', self.http_port)
    
    async def proxy_http_request(self, request: web.Request, target_host: str, target_port: int) -> web.StreamResponse:
        """代理HTTP请求到目标服务器"""
        # 构建目标URL
        target_url = f"http://{target_host}:{target_port}{request.path}"
        if request.query_string:
            target_url = f"{target_url}?{request.query_string}"
        
        # 准备请求头
        headers = dict(request.headers)
        headers.pop('Host', None)
        
        try:
            async with ClientSession() as session:
                # 根据请求方法转发请求
                if request.method == 'GET':
                    async with session.get(target_url, headers=headers) as resp:
                        return await self.create_response(resp, request)
                
                elif request.method == 'POST':
                    data = await request.read()
                    async with session.post(target_url, headers=headers, data=data) as resp:
                        return await self.create_response(resp, request)
                
                elif request.method == 'PUT':
                    data = await request.read()
                    async with session.put(target_url, headers=headers, data=data) as resp:
                        return await self.create_response(resp, request)
                
                elif request.method == 'DELETE':
                    async with session.delete(target_url, headers=headers) as resp:
                        return await self.create_response(resp, request)
                
                elif request.method == 'HEAD':
                    async with session.head(target_url, headers=headers) as resp:
                        return await self.create_response(resp, request)
                
                elif request.method == 'OPTIONS':
                    async with session.options(target_url, headers=headers) as resp:
                        return await self.create_response(resp, request)
                
                elif request.method == 'PATCH':
                    data = await request.read()
                    async with session.patch(target_url, headers=headers, data=data) as resp:
                        return await self.create_response(resp, request)
                
                else:
                    return web.Response(status=405, text='Method not allowed')
                    
        except Exception as e:
            logger.error(f"HTTP代理错误: {e}")
            return web.Response(status=502, text='Bad Gateway')
    
    async def create_response(self, resp: aiohttp.ClientResponse, request: web.Request) -> web.StreamResponse:
        """创建响应"""
        response = web.StreamResponse(
            status=resp.status,
            reason=resp.reason,
        )
        
        # 复制响应头
        for name, value in resp.headers.items():
            response.headers[name] = value
        
        await response.prepare(request)
        
        # 流式传输响应体
        async for chunk in resp.content.iter_any():
            await response.write(chunk)
        
        await response.write_eof()
        return response
    
    async def start(self):
        """启动代理服务器"""
        runner = web.AppRunner(self.app)
        await runner.setup()
        
        # 启动代理服务器
        site = web.TCPSite(runner, '0.0.0.0', ARGO_PORT)
        await site.start()
        logger.info(f"代理服务器启动在端口: {ARGO_PORT}")
        logger.info(f"HTTP流量 -> localhost:{self.http_port}")
        logger.info(f"Xray TCP流量 -> localhost:{self.xray_port}")
        logger.info(f"Xray WebSocket流量 -> localhost:3003-3005")
        logger.info(f"订阅地址: http://[服务器IP]:{ARGO_PORT}/{SUB_PATH}")
    
    async def close_all_connections(self):
        """关闭所有WebSocket连接"""
        logger.info(f"正在关闭 {len(self.ws_connections)} 个WebSocket连接...")
        for ws in self.ws_connections.copy():
            try:
                await ws.close()
            except:
                pass
        self.ws_connections.clear()

class XrayConfig:
    """Xray配置生成器"""
    
    @staticmethod
    def generate(uuid: str) -> Dict:
        return {
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
                            "id": uuid,
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
                        "clients": [{"id": uuid}],
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
                        "clients": [{"id": uuid, "level": 0}],
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
                        "clients": [{"id": uuid, "alterId": 0}]
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
                        "clients": [{"password": uuid}]
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

class FileManager:
    """文件管理器"""
    
    @staticmethod
    async def download_file(url: str, dest: Path) -> bool:
        """下载文件"""
        try:
            async with ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        async with aiofiles.open(dest, 'wb') as f:
                            async for chunk in response.content.iter_chunked(8192):
                                await f.write(chunk)
                        dest.chmod(0o775)
                        logger.info(f"下载成功: {dest.name}")
                        return True
                    else:
                        logger.error(f"下载失败: {url} - {response.status}")
                        return False
        except Exception as e:
            logger.error(f"下载错误: {e}")
            return False
    
    @staticmethod
    async def cleanup_old_files():
        """清理旧文件"""
        try:
            for file in FILE_PATH.glob('*'):
                try:
                    if file.is_file():
                        file.unlink()
                except:
                    pass
        except:
            pass
    
    @staticmethod
    async def write_json_config(config: Dict, path: Path):
        """写入JSON配置文件"""
        async with aiofiles.open(path, 'w') as f:
            await f.write(json.dumps(config, indent=2))
    
    @staticmethod
    async def write_file(content: str, path: Path):
        """写入文本文件"""
        async with aiofiles.open(path, 'w') as f:
            await f.write(content)

class ProcessManager:
    """进程管理器"""
    
    @staticmethod
    def get_system_architecture() -> str:
        """获取系统架构"""
        import platform
        arch = platform.machine().lower()
        if 'arm' in arch or 'aarch' in arch:
            return 'arm'
        else:
            return 'amd'
    
    @staticmethod
    def get_download_urls(arch: str) -> Dict[str, str]:
        """获取下载URL"""
        if arch == 'arm':
            return {
                'web': 'https://arm64.ssss.nyc.mn/web',
                'bot': 'https://arm64.ssss.nyc.mn/bot',
                'agent': 'https://arm64.ssss.nyc.mn/agent',
                'v1': 'https://arm64.ssss.nyc.mn/v1'
            }
        else:
            return {
                'web': 'https://amd64.ssss.nyc.mn/web',
                'bot': 'https://amd64.ssss.nyc.mn/bot',
                'agent': 'https://amd64.ssss.nyc.mn/agent',
                'v1': 'https://amd64.ssss.nyc.mn/v1'
            }
    
    @staticmethod
    async def run_detached_process(cmd: List[str], name: str, cwd: Path = None):
        """运行后台进程"""
        try:
            # 在Linux/Unix上使用nohup运行后台进程
            if sys.platform != 'win32':
                full_cmd = ['nohup'] + cmd + ['>', '/dev/null', '2>&1', '&']
                process = await asyncio.create_subprocess_shell(
                    ' '.join(full_cmd),
                    cwd=cwd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
            else:
                # Windows上使用start
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    cwd=cwd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            
            processes[name] = process
            logger.info(f"进程启动: {name}")
            await asyncio.sleep(1)
            return process
        except Exception as e:
            logger.error(f"启动进程失败 {name}: {e}")
            return None
    
    @staticmethod
    async def run_process(cmd: List[str], name: str, capture_output: bool = False):
        """运行进程"""
        try:
            if capture_output:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            else:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
            
            processes[name] = process
            logger.info(f"进程启动: {name}")
            return process
        except Exception as e:
            logger.error(f"启动进程失败 {name}: {e}")
            return None
    
    @staticmethod
    async def kill_process(name: str):
        """终止进程"""
        if name in processes:
            try:
                process = processes[name]
                if process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except asyncio.TimeoutError:
                        process.kill()
                        await process.wait()
                del processes[name]
                logger.info(f"进程终止: {name}")
            except Exception as e:
                logger.error(f"终止进程失败 {name}: {e}")

class TunnelManager:
    """隧道管理器"""
    
    @staticmethod
    async def generate_tunnel_config():
        """生成隧道配置"""
        if not ARGO_AUTH or not ARGO_DOMAIN:
            logger.info("ARGO_DOMAIN 或 ARGO_AUTH 为空，使用快速隧道")
            return False
        
        if 'TunnelSecret' in ARGO_AUTH:
            try:
                # 写入隧道JSON配置
                await FileManager.write_file(ARGO_AUTH, tunnel_json_path)
                
                # 解析隧道ID
                config = json.loads(ARGO_AUTH)
                tunnel_id = config.get('TunnelID', '')
                
                # 生成YAML配置
                yaml_config = f"""tunnel: {tunnel_id}
credentials-file: {tunnel_json_path}
protocol: http2

ingress:
  - hostname: {ARGO_DOMAIN}
    service: http://localhost:{ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
                await FileManager.write_file(yaml_config, tunnel_yaml_path)
                
                logger.info('隧道YAML配置生成成功')
                return True
            except Exception as e:
                logger.error(f'生成隧道配置错误: {e}')
                return False
        else:
            logger.info("ARGO_AUTH 不是TunnelSecret格式，使用token连接隧道")
            return False

class NodeManager:
    """节点管理器"""
    
    @staticmethod
    async def delete_nodes():
        """删除节点"""
        try:
            if not UPLOAD_URL or not sub_path.exists():
                return
            
            async with aiofiles.open(sub_path, 'r') as f:
                file_content = await f.read()
            
            try:
                decoded = base64.b64decode(file_content).decode('utf-8')
            except:
                return
            
            nodes = [line for line in decoded.split('\n') 
                    if any(proto in line for proto in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
            
            if not nodes:
                return
            
            data = json.dumps({"nodes": nodes})
            headers = {'Content-Type': 'application/json'}
            
            async with ClientSession() as session:
                async with session.post(f"{UPLOAD_URL}/api/delete-nodes", 
                                      data=data, headers=headers):
                    pass
        except:
            pass
    
    @staticmethod
    async def get_isp_info() -> str:
        """获取ISP信息"""
        try:
            async with ClientSession() as session:
                try:
                    async with session.get('https://ipapi.co/json/', timeout=3) as resp:
                        data = await resp.json()
                        if data.get('country_code') and data.get('org'):
                            return f"{data['country_code']}_{data['org']}"
                except:
                    try:
                        async with session.get('http://ip-api.com/json/', timeout=3) as resp:
                            data = await resp.json()
                            if data.get('status') == 'success' and data.get('countryCode') and data.get('org'):
                                return f"{data['countryCode']}_{data['org']}"
                    except:
                        pass
        except:
            pass
        return 'Unknown'
    
    @staticmethod
    async def generate_links(argo_domain: str):
        """生成订阅链接"""
        isp = await NodeManager.get_isp_info()
        node_name = f"{NAME}-{isp}" if NAME else isp
        
        # 创建VMESS配置
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
        
        vmess_base64 = base64.b64encode(
            json.dumps(vmess_config).encode()
        ).decode()
        
        sub_content = f"""
vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{node_name}

vmess://{vmess_base64}

trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{node_name}
        """
        
        # 保存订阅文件
        encoded_content = base64.b64encode(sub_content.encode()).decode()
        await FileManager.write_file(encoded_content, sub_path)
        
        logger.info(f"{sub_path} 保存成功")
        
        # 打印订阅内容
        logger.info("订阅内容(base64):")
        logger.info(encoded_content)
        
        # 上传节点
        await NodeManager.upload_nodes()
        
        return sub_content
    
    @staticmethod
    async def upload_nodes():
        """上传节点"""
        try:
            if UPLOAD_URL and PROJECT_URL:
                subscription_url = f"{PROJECT_URL}/{SUB_PATH}"
                data = json.dumps({"subscription": [subscription_url]})
                headers = {'Content-Type': 'application/json'}
                
                async with ClientSession() as session:
                    async with session.post(f"{UPLOAD_URL}/api/add-subscriptions", 
                                          data=data, headers=headers) as resp:
                        if resp.status == 200:
                            logger.info('订阅上传成功')
                        else:
                            logger.error(f'订阅上传失败: {resp.status}')
            
            elif UPLOAD_URL and list_path.exists():
                async with aiofiles.open(list_path, 'r') as f:
                    content = await f.read()
                
                nodes = [line for line in content.split('\n') 
                        if any(proto in line for proto in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
                
                if nodes:
                    data = json.dumps({"nodes": nodes})
                    headers = {'Content-Type': 'application/json'}
                    
                    async with ClientSession() as session:
                        async with session.post(f"{UPLOAD_URL}/api/add-nodes", 
                                              data=data, headers=headers) as resp:
                            if resp.status == 200:
                                logger.info('节点上传成功')
                            else:
                                logger.error(f'节点上传失败: {resp.status}')
        except Exception as e:
            logger.error(f'上传失败: {e}')

class MonitorManager:
    """监控管理器"""
    
    @staticmethod
    async def download_monitor_script() -> bool:
        """下载监控脚本"""
        if not MONITOR_KEY or not MONITOR_SERVER or not MONITOR_URL:
            logger.info("监控环境变量不完整，跳过监控脚本启动")
            return False
        
        monitor_url = "https://raw.githubusercontent.com/mimaldq/cf-vps-monitor/main/cf-vps-monitor.sh"
        
        try:
            async with ClientSession() as session:
                async with session.get(monitor_url) as response:
                    if response.status == 200:
                        content = await response.read()
                        async with aiofiles.open(monitor_path, 'wb') as f:
                            await f.write(content)
                        
                        monitor_path.chmod(0o755)
                        logger.info("监控脚本下载完成")
                        return True
                    else:
                        logger.error(f"下载监控脚本失败: {response.status}")
                        return False
        except Exception as e:
            logger.error(f"下载监控脚本错误: {e}")
            return False
    
    @staticmethod
    async def run_monitor_script():
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
        
        try:
            process = await ProcessManager.run_process(cmd, 'monitor', capture_output=True)
            
            global monitor_process
            monitor_process = process
            
            # 读取输出
            async def read_output(stream, is_error=False):
                try:
                    async for line in stream:
                        line_str = line.decode().strip()
                        if is_error:
                            logger.error(f"监控脚本错误: {line_str}")
                        else:
                            logger.info(f"监控脚本输出: {line_str}")
                except Exception as e:
                    logger.error(f"读取监控脚本输出失败: {e}")
            
            if process.stdout:
                asyncio.create_task(read_output(process.stdout))
            if process.stderr:
                asyncio.create_task(read_output(process.stderr, True))
            
            # 监控退出
            async def monitor_exit():
                await process.wait()
                logger.info(f"监控脚本退出，代码: {process.returncode}")
                if process.returncode != 0:
                    logger.info("将在30秒后重启监控脚本...")
                    await asyncio.sleep(30)
                    await MonitorManager.run_monitor_script()
            
            asyncio.create_task(monitor_exit())
            
        except Exception as e:
            logger.error(f"运行监控脚本失败: {e}")

class HTTPServer:
    """简单的HTTP服务器，用于处理非代理请求"""
    
    def __init__(self, port: int = PORT):
        self.port = port
        self.app = web.Application()
        self.setup_routes()
    
    def setup_routes(self):
        """设置路由"""
        self.app.router.add_get('/', self.handle_root)
    
    async def handle_root(self, request: web.Request) -> web.Response:
        """处理根路径"""
        return web.Response(text='HTTP Server is running', content_type='text/plain')
    
    async def start(self):
        """启动HTTP服务器"""
        runner = web.AppRunner(self.app)
        await runner.setup()
        
        # 启动HTTP服务器
        site = web.TCPSite(runner, 'localhost', self.port)
        await site.start()
        logger.info(f"HTTP服务器启动在内部端口: {self.port}")

class MainApp:
    """主应用"""
    
    def __init__(self):
        self.proxy_server = ProxyServer()
        self.http_server = HTTPServer()
        self.xray_domains = None
    
    async def setup_nezha(self):
        """设置哪吒监控"""
        if not NEZHA_SERVER or not NEZHA_KEY:
            logger.info('哪吒监控变量为空，跳过运行')
            return
        
        if NEZHA_PORT:
            # 哪吒v0
            await self.setup_nezha_v0()
        else:
            # 哪吒v1
            await self.setup_nezha_v1()
    
    async def setup_nezha_v0(self):
        """设置哪吒v0"""
        args = [
            str(npm_path),
            "-s", f"{NEZHA_SERVER}:{NEZHA_PORT}",
            "-p", NEZHA_KEY
        ]
        
        tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
        if NEZHA_PORT in tls_ports:
            args.append("--tls")
        
        args.extend(["--disable-auto-update", "--report-delay", "4", "--skip-conn", "--skip-procs"])
        
        await ProcessManager.run_detached_process(args, 'nezha', FILE_PATH)
    
    async def setup_nezha_v1(self):
        """设置哪吒v1"""
        # 检测TLS
        port = NEZHA_SERVER.split(':')[-1] if ':' in NEZHA_SERVER else ''
        tls_ports = {'443', '8443', '2096', '2087', '2083', '2053'}
        nezha_tls = 'true' if port in tls_ports else 'false'
        
        # 生成config.yaml
        config_yaml = f"""
client_secret: {NEZHA_KEY}
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
tls: {nezha_tls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {UUID}
"""
        
        config_yaml_path = FILE_PATH / 'config.yaml'
        await FileManager.write_file(config_yaml, config_yaml_path)
        
        # 运行哪吒v1
        args = [str(php_path), "-c", str(config_yaml_path)]
        await ProcessManager.run_detached_process(args, 'nezha', FILE_PATH)
    
    async def setup_xray(self):
        """设置Xray"""
        # 生成配置文件
        config = XrayConfig.generate(UUID)
        await FileManager.write_json_config(config, config_path)
        logger.info("Xray配置文件生成完成")
        
        # 运行Xray
        args = [str(web_path), "-c", str(config_path)]
        await ProcessManager.run_detached_process(args, 'xray', FILE_PATH)
    
    async def setup_cloudflared(self):
        """设置Cloudflared"""
        if not bot_path.exists():
            logger.error(f"cloudflared文件不存在: {bot_path}")
            return
        
        if ARGO_AUTH and re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
            args = [
                str(bot_path),
                "tunnel", "--edge-ip-version", "auto", "--no-autoupdate", 
                "--protocol", "http2", "run", "--token", ARGO_AUTH
            ]
            await ProcessManager.run_detached_process(args, 'cloudflared', FILE_PATH)
            
        elif ARGO_AUTH and 'TunnelSecret' in ARGO_AUTH:
            if tunnel_yaml_path.exists():
                args = [
                    str(bot_path),
                    "--config", str(tunnel_yaml_path), "run"
                ]
                await ProcessManager.run_detached_process(args, 'cloudflared', FILE_PATH)
            else:
                logger.warning('隧道配置文件不存在，使用临时隧道')
                args = [
                    str(bot_path),
                    "tunnel", "--edge-ip-version", "auto", "--no-autoupdate", 
                    "--protocol", "http2", "--logfile", str(boot_log_path),
                    "--loglevel", "info", "--url", f"http://localhost:{ARGO_PORT}"
                ]
                await ProcessManager.run_detached_process(args, 'cloudflared', FILE_PATH)
        else:
            args = [
                str(bot_path),
                "tunnel", "--edge-ip-version", "auto", "--no-autoupdate", 
                "--protocol", "http2", "--logfile", str(boot_log_path),
                "--loglevel", "info", "--url", f"http://localhost:{ARGO_PORT}"
            ]
            await ProcessManager.run_detached_process(args, 'cloudflared', FILE_PATH)
        
        logger.info(f"{bot_name} 运行中")
    
    async def extract_domains(self):
        """提取域名"""
        if ARGO_AUTH and ARGO_DOMAIN:
            argo_domain = ARGO_DOMAIN
            logger.info(f'使用固定域名: {argo_domain}')
            self.xray_domains = [argo_domain]
            return argo_domain
        else:
            try:
                await asyncio.sleep(5)  # 等待cloudflared启动
                
                if boot_log_path.exists():
                    await asyncio.sleep(2)  # 确保文件写入完成
                    
                    async with aiofiles.open(boot_log_path, 'r') as f:
                        content = await f.read()
                    
                    domains = re.findall(r'https?://([^ ]*trycloudflare\.com)/?', content)
                    
                    if domains:
                        argo_domain = domains[0]
                        logger.info(f'找到临时域名: {argo_domain}')
                        self.xray_domains = [argo_domain]
                        return argo_domain
                    else:
                        logger.info('未找到域名，重新运行bot以获取Argo域名')
                        
                        # 清理并重启
                        if boot_log_path.exists():
                            boot_log_path.unlink()
                        
                        await ProcessManager.kill_process('cloudflared')
                        await asyncio.sleep(3)
                        
                        # 重新启动cloudflared
                        args = [
                            str(bot_path),
                            "tunnel", "--edge-ip-version", "auto", "--no-autoupdate",
                            "--protocol", "http2", "--logfile", str(boot_log_path),
                            "--loglevel", "info", "--url", f"http://localhost:{ARGO_PORT}"
                        ]
                        
                        await ProcessManager.run_detached_process(args, 'cloudflared_restart', FILE_PATH)
                        await asyncio.sleep(5)
                        
                        # 再次尝试提取
                        return await self.extract_domains()
                else:
                    logger.error('boot.log文件不存在')
                    return None
            except Exception as e:
                logger.error(f'提取域名错误: {e}")
                return None
    
    async def add_visit_task(self):
        """添加访问任务"""
        if not AUTO_ACCESS or not PROJECT_URL:
            logger.info("跳过添加自动访问任务")
            return
        
        try:
            data = json.dumps({"url": PROJECT_URL})
            headers = {'Content-Type': 'application/json'}
            
            async with ClientSession() as session:
                async with session.post('https://oooo.serv00.net/add-url', 
                                      data=data, headers=headers) as resp:
                    if resp.status == 200:
                        logger.info('自动访问任务添加成功')
                    else:
                        logger.error(f'添加自动访问任务失败: {resp.status}')
        except Exception as e:
            logger.error(f'添加自动访问任务失败: {e}')
    
    async def download_dependencies(self):
        """下载依赖文件"""
        arch = ProcessManager.get_system_architecture()
        urls = ProcessManager.get_download_urls(arch)
        
        download_tasks = []
        
        # 下载web和bot（必需）
        if 'web' in urls:
            download_tasks.append(
                FileManager.download_file(urls['web'], web_path)
            )
        
        if 'bot' in urls:
            download_tasks.append(
                FileManager.download_file(urls['bot'], bot_path)
            )
        
        # 下载哪吒监控
        if NEZHA_SERVER and NEZHA_KEY:
            if NEZHA_PORT and 'agent' in urls:
                download_tasks.append(
                    FileManager.download_file(urls['agent'], npm_path)
                )
            elif not NEZHA_PORT and 'v1' in urls:
                download_tasks.append(
                    FileManager.download_file(urls['v1'], php_path)
                )
        
        # 并行下载
        results = await asyncio.gather(*download_tasks, return_exceptions=True)
        
        # 检查下载结果
        success_count = sum(1 for r in results if r is True)
        logger.info(f"文件下载完成，成功 {success_count}/{len(download_tasks)} 个文件")
        
        if success_count < len(download_tasks):
            logger.warning("部分文件下载失败，可能会影响功能")
    
    async def cleanup_files(self):
        """清理文件"""
        await asyncio.sleep(90)  # 90秒后清理
        
        files_to_delete = [
            boot_log_path, config_path, web_path, bot_path, monitor_path
        ]
        
        if NEZHA_PORT and npm_path.exists():
            files_to_delete.append(npm_path)
        elif NEZHA_SERVER and NEZHA_KEY and php_path.exists():
            files_to_delete.append(php_path)
        
        for file in files_to_delete:
            try:
                if file.exists():
                    file.unlink()
                    logger.debug(f"已清理文件: {file.name}")
            except:
                pass
        
        logger.info('应用正在运行')
        logger.info('感谢使用此脚本，享受吧！')
    
    async def start_monitor(self):
        """启动监控脚本"""
        if not MONITOR_KEY or not MONITOR_SERVER or not MONITOR_URL:
            logger.info("监控脚本未配置，跳过")
            return
        
        await asyncio.sleep(10)  # 等待其他服务启动
        
        downloaded = await MonitorManager.download_monitor_script()
        if downloaded:
            await MonitorManager.run_monitor_script()
    
    async def run(self):
        """主运行逻辑"""
        try:
            logger.info('开始服务器初始化...')
            
            # 清理和设置
            await NodeManager.delete_nodes()
            await FileManager.cleanup_old_files()
            
            # 隧道配置
            tunnel_configured = await TunnelManager.generate_tunnel_config()
            
            # 下载依赖
            await self.download_dependencies()
            
            # 启动HTTP服务器
            await self.http_server.start()
            
            # 启动Xray
            await self.setup_xray()
            
            # 启动哪吒监控
            await self.setup_nezha()
            
            # 启动cloudflared
            await self.setup_cloudflared()
            
            # 等待隧道启动
            logger.info('等待隧道启动...')
            await asyncio.sleep(8)
            
            # 提取域名并生成订阅
            argo_domain = await self.extract_domains()
            if argo_domain:
                await NodeManager.generate_links(argo_domain)
            
            # 添加访问任务
            await self.add_visit_task()
            
            logger.info('服务器初始化完成')
            
            # 启动监控脚本
            await self.start_monitor()
            
            # 清理文件
            asyncio.create_task(self.cleanup_files())
            
            # 启动代理服务器
            await self.proxy_server.start()
            
        except Exception as e:
            logger.error(f'启动过程中错误: {e}')
            raise
    
    async def shutdown(self):
        """关闭应用"""
        logger.info("收到关闭信号，正在清理...")
        
        # 关闭所有WebSocket连接
        await self.proxy_server.close_all_connections()
        
        # 停止监控脚本
        global monitor_process
        if monitor_process:
            logger.info("停止监控脚本...")
            await ProcessManager.kill_process('monitor')
        
        # 停止其他进程
        for name in list(processes.keys()):
            await ProcessManager.kill_process(name)
        
        logger.info("程序退出")

# 主函数
async def main():
    # 创建应用实例
    app = MainApp()
    
    # 设置信号处理
    def signal_handler():
        asyncio.create_task(app.shutdown())
    
    if sys.platform != 'win32':
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)
    
    try:
        await app.run()
        
        # 保持运行
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        logger.info("收到键盘中断信号")
        await app.shutdown()
    except Exception as e:
        logger.error(f"应用程序错误: {e}")
        await app.shutdown()

if __name__ == '__main__':
    # 检查必要环境变量
    logger.info("=" * 50)
    logger.info("Xray代理服务器启动")
    logger.info(f"UUID: {UUID}")
    logger.info(f"订阅路径: /{SUB_PATH}")
    logger.info(f"ARGO端口: {ARGO_PORT}")
    logger.info("=" * 50)
    
    asyncio.run(main())
