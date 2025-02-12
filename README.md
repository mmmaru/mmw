# MMW
mtls manager web  

🎉本项目`main.py`99%由cursor生成🎉  

## 安全性声明
访客端网页在前端生成RSA私钥和csr后, 由后端签名, 后端返回签名后的crt, 前端将crt和私钥打包成p12进行下载. 安装这个p12仅安装客户端认证证书, 不涉及信任CA, 就算真的成为你的中间人也无法解密你的https  
本项目开源在 https://github.com/mmmaru/mmw  

## 部署
```sh
git clone git@github.com:mmmaru/mmw.git
cd ./mmw
pip install -r requirements.txt
mkdir ./keys
mkdir ./static
cp ./config-sample.yaml ./config.yaml

# 更改管理员账号密码
vim ./config.yaml

# 更改监听的ip 端口
vim main.py

python main.py
```

## 给cursor的提问
```
## 后端
根据需求写python fastapi后端代码, 要求进行类型标注, 以及写较多的注释, 注释使用中文
配置文件使用yaml格式
管理员账号密码通过配置文件的形式读取, 管理员身份验证使用http basic. 配置文件存储的密码为明文, 不需要额外加密解密. admin.username: "qri”, admin.password: "adminpassword"
后续提到的秘钥全部使用rsa加密, 秘钥在接口通信时 使用pem格式的字符串
后端维护一个签发者秘钥列表, 秘钥保存在./keys下. 秘钥是中间秘钥, 每份秘钥有一个.crt和一个.pem, 或者一个.crt和一个.key
管理员可以生成针对某个秘钥生成一次性访问token. 无需数据库, 生成的token仅在内存中就好, 使用一个map维护token和key的关联性. 生成的token无需用jwt, 用无意义的随机字符串就行. 每次生成token时都从文件夹中更新秘钥信息, 以防有新添加的秘钥
其他访客可以通过访客端, 输入一次性token, 来让对应的秘钥根据访客提供的csr生成信任的crt(成为客户端crt)返回给访客, 生成的客户端crt满足: 根秘钥仅信任客户端crt, 不信任客户端crt再派生的证书; crt有效时间3650天
访客无需登录
无需数据库
生成需要的requirements.txt

## 前端
生成管理员使用的管理页的前端代码, 并将fastapi的/admin/index.html指向这个页面. 这个页面的路径同样需要basic auth. 这个页面需要列出所有可以生成token的key, 管理员可以点击key后面的"生成token"按钮来生成token, 展示在前端
生成访客可以使用的访客页面, 并将fastapi的/visit/index.html指向这个页面. 在这个页面, 用户输入一个token和一个仅用于最终p12的6位密码, 点击生成, 这时 在**前端** 进行生成私钥, 并且生成csr, 传给后端进行签名, 后端签名后 前端再将签名后的crt和私钥打包成一个p12, 前端自动为用户下载
```