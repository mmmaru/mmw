import os
import yaml
import base64
import secrets
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 定义配置文件路径
CONFIG_PATH = "config.yaml"
KEYS_DIR = "./keys"

app = FastAPI()
security = HTTPBasic()

# 存储token到key的映射
token_key_map: Dict[str, str] = {}

@dataclass
class KeyPair:
    """证书密钥对"""
    cert_path: Path  # .crt文件路径
    key_path: Path   # .key或.pem文件路径

class Config:
    """配置类"""
    def __init__(self):
        with open(CONFIG_PATH, 'r') as f:
            config = yaml.safe_load(f)
        self.admin_username = config['admin']['username']
        self.admin_password = config['admin']['password']

config = Config()

def get_current_admin(credentials: HTTPBasicCredentials = Depends(security)):
    """验证管理员身份"""
    is_correct_username = credentials.username == config.admin_username
    is_correct_password = credentials.password == config.admin_password

    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def load_keys() -> List[KeyPair]:
    """从keys目录加载所有密钥对"""
    keys_dir = Path(KEYS_DIR)
    if not keys_dir.exists():
        keys_dir.mkdir()

    key_pairs = []
    crt_files = list(keys_dir.glob("*.crt"))

    for crt_file in crt_files:
        stem = crt_file.stem
        key_file = keys_dir / f"{stem}.key"
        pem_file = keys_dir / f"{stem}.pem"

        if key_file.exists():
            key_pairs.append(KeyPair(crt_file, key_file))
        elif pem_file.exists():
            key_pairs.append(KeyPair(crt_file, pem_file))

    return key_pairs

class TokenResponse(BaseModel):
    token: str
    key_name: str

@app.post("/admin/generate_token")
async def generate_token(key_name: str, _: str = Depends(get_current_admin)) -> TokenResponse:
    """生成一次性token"""
    # 重新加载密钥列表
    key_pairs = load_keys()

    # 验证密钥是否存在
    if not any(key_name == key.cert_path.stem for key in key_pairs):
        raise HTTPException(status_code=404, detail="Key not found")

    # 生成随机token
    token = secrets.token_urlsafe(32)
    token_key_map[token] = key_name

    return TokenResponse(token=token, key_name=key_name)

class CSRRequest(BaseModel):
    token: str
    csr_pem: str

class CertResponse(BaseModel):
    cert_pem: str

@app.post("/visit/sign_csr")
async def sign_csr(request: CSRRequest) -> CertResponse:
    """签名CSR"""
    if request.token not in token_key_map:
        raise HTTPException(status_code=400, detail="Invalid token")

    key_name = token_key_map.pop(request.token)  # 使用后立即删除token

    # 加载CA密钥对
    key_pairs = load_keys()
    ca_key_pair = next((kp for kp in key_pairs if kp.cert_path.stem == key_name), None)
    if not ca_key_pair:
        raise HTTPException(status_code=400, detail="CA key not found")

    try:
        # 加载CA证书和私钥
        with open(ca_key_pair.cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(ca_key_pair.key_path, 'rb') as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

        # 加载CSR
        csr = x509.load_pem_x509_csr(request.csr_pem.encode())

        # 生成证书
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now() + timedelta(days=-2)
        ).not_valid_after(
            datetime.now() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).sign(ca_private_key, hashes.SHA256())

        # 序列化证书
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        return CertResponse(cert_pem=cert_pem)

    except Exception as e:
        logger.error(f"Error signing CSR: {str(e)}")
        raise HTTPException(status_code=500, detail="Error signing CSR")

@app.get("/admin/index.html")
async def admin_page(_: str = Depends(get_current_admin)):
    """管理员页面"""
    with open("static/admin.html", "r") as f:
        content = f.read()
    return HTMLResponse(content=content)

@app.get("/visit/index.html")
async def visit_page():
    """访客页面"""
    with open("static/visit.html", "r") as f:
        content = f.read()
    return HTMLResponse(content=content)

@app.get("/admin/keys")
async def list_keys(_: str = Depends(get_current_admin)):
    """列出所有可用的密钥"""
    key_pairs = load_keys()
    return {"keys": [kp.cert_path.stem for kp in key_pairs]}

# 挂载静态文件
app.mount("/static", StaticFiles(directory="static"), name="static")

# 创建requirements.txt
requirements = """
fastapi==0.68.1
uvicorn==0.15.0
pyyaml==5.4.1
cryptography==3.4.7
"""

with open("requirements.txt", "w") as f:
    f.write(requirements.strip())

# 创建静态文件目录
os.makedirs("static", exist_ok=True)

# 创建管理员页面
admin_html = """
<!DOCTYPE html>
<html>
<head>
    <title>管理员页面</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .key-item { margin: 10px 0; }
        .token-display { margin: 10px 0; padding: 10px; background: #f0f0f0; }
    </style>
</head>
<body>
    <h1>密钥管理</h1>
    <div id="keys-list"></div>

    <script>
        async function loadKeys() {
            const response = await fetch('/admin/keys');
            const data = await response.json();
            const keysList = document.getElementById('keys-list');
            keysList.innerHTML = '';
            
            data.keys.forEach(key => {
                const div = document.createElement('div');
                div.className = 'key-item';
                div.innerHTML = `
                    ${key}
                    <button onclick="generateToken('${key}')">生成Token</button>
                    <div id="token-${key}" class="token-display" style="display:none;"></div>
                `;
                keysList.appendChild(div);
            });
        }

        async function generateToken(keyName) {
            const response = await fetch('/admin/generate_token?key_name=' + keyName, {
                method: 'POST'
            });
            const data = await response.json();
            
            const tokenDisplay = document.getElementById('token-' + keyName);
            tokenDisplay.textContent = '生成的Token: ' + data.token;
            tokenDisplay.style.display = 'block';
        }

        loadKeys();
    </script>
</body>
</html>
"""

with open("static/admin.html", "w") as f:
    f.write(admin_html)

# 创建访客页面
visit_html = """
<!DOCTYPE html>
<html>
<head>
    <title>访客页面</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .input-group { margin: 10px 0; }
        input { margin: 5px 0; padding: 5px; }
    </style>
</head>
<body>
    <h1>证书生成</h1>
    <div class="input-group">
        <label>Token:</label><br>
        <input type="text" id="token" required>
    </div>
    <div class="input-group">
        <label>P12密码 (6位):</label><br>
        <input type="password" id="password" pattern=".{6,6}" required>
    </div>
    <button onclick="generateCert()">生成证书</button>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/forge/0.10.0/forge.min.js"></script>
    <script>
        async function generateCert() {
            const token = document.getElementById('token').value;
            const password = document.getElementById('password').value;
            
            if (!token || !password || password.length !== 6) {
                alert('请输入有效的token和6位密码');
                return;
            }

            try {
                // 生成密钥对
                const keys = forge.pki.rsa.generateKeyPair(2048);
                console.log({"privateKey": forge.pki.privateKeyToPem(keys.privateKey)})
                // 创建CSR
                const csr = forge.pki.createCertificationRequest();
                csr.publicKey = keys.publicKey;
                csr.setSubject([{
                    name: 'commonName',
                    value: 'Client Certificate'
                }]);
                csr.sign(keys.privateKey);
                
                // 转换CSR为PEM格式
                const csrPem = forge.pki.certificationRequestToPem(csr);
                // 发送CSR到服务器
                const response = await fetch('/visit/sign_csr', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        token: token,
                        csr_pem: csrPem
                    })
                });
                
                if (!response.ok) {
                    throw new Error('签名请求失败');
                }
                
                const data = await response.json();
                
                // 转换证书
                const cert = forge.pki.certificateFromPem(data.cert_pem);
                
                // 创建P12
                const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
                    keys.privateKey,
                    [cert],
                    password,
                    {
                        friendlyName: 'Client Certificate',
                        algorithm: '3des'
                    }
                );
                
                const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
                
                // 下载P12
                const blob = new Blob(
                    [new Uint8Array(p12Der.split('').map(c => c.charCodeAt(0)))],
                    {type: 'application/x-pkcs12'}
                );
                
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'certificate.p12';
                a.click();
                
            } catch (error) {
                alert('生成证书失败: ' + error.message);
            }
        }
    </script>
</body>
</html>
"""

with open("static/visit.html", "w") as f:
    f.write(visit_html)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
