# async-x25519-chat

异步 TCP 聊天示例程序，使用 X25519（x25519/Curve25519）进行握手派生共享密钥，并使用 AES-256-GCM 对消息进行加密。以 asyncio 实现客户端/服务端，代码风格可读、变量具名且带行尾注释，便于学习与开源维护。

## 主要特性
- 基于 TCP 的双向加密聊天（客户端/服务端模式）。  
- 握手采用 X25519（双方交换公钥并计算共享密钥）。  
- 使用 HKDF-SHA256 从共享密钥派生 32 字节 AES-256 密钥。  
- 消息加密采用 AES-GCM（nonce 12 字节，tag 16 字节）。  
- 消息帧采用 4 字节大端长度前缀。  
- 使用 asyncio 实现非阻塞 I/O（stdin 经 executor 读取），便于扩展为高并发服务器。  
- 代码可读性优先：描述性变量名、扁平化逻辑、行尾注释，适合开源发布与二次开发。

## 适用场景与安全提醒
- 适合学习、演示和受信任网络中的点对点加密通信。  

## 依赖
- Python 3.10 或更高版本。  
- cryptography 库（用于 X25519、HKDF、AES-GCM）：

安装依赖：
```
pip install cryptography
```
## 快速开始（运行示例）
1. 克隆仓库并进入目录：
```
git clone https://github.com/wangyifan349/async-x25519-chat.git
cd async-x25519-chat
```

2. 安装依赖：
```
pip install cryptography
```

3. 作为服务端运行（监听所有接口 12345 端口）：
```
python3 async_tcp_x25519_readable.py --role server --bind 0.0.0.0 --port 12345
```

4. 作为客户端运行（连接服务端）：
```
python3 async_tcp_x25519_readable.py --role client --host 服务器IP --port 12345
```

5. 使用说明：
- 在任一端在终端输入文本后回车，即可发送加密消息到对端。  
- 输入 /quit 可结束发送并关闭连接。  
- 使用 Ctrl+C 中断程序。

## 协议与消息格式（准确说明）
- 握手阶段：双方交换 X25519 公钥（公钥作为裸字节流 framed 发送，帧格式与消息相同：4 字节长度前缀 + 公钥字节）。  
- 共享密钥：各方使用对方公钥与自身私钥调用 X25519 exchange() 生成 32 字节原始共享密钥。  
- 密钥派生：使用 HKDF-SHA256（info = b"x25519-aesgcm-v1"，salt = None）派生 32 字节 AES 密钥（用于 AES-256-GCM）。  
- 消息帧格式：每条消息 = 4 字节大端长度前缀 + 加密负载。  
- 加密负载格式：nonce(12 bytes) || ciphertext || tag(16 bytes)（AES-GCM 的标准输出）。接收方从负载前 12 字节取 nonce，剩余为 ciphertext+tag，用 AES-GCM 解密得到明文。  
- 关联数据（AAD）：示例中未使用（为 None）。如需防篡改连接元数据，可把 AAD 加入并在双方一致下派生与验证。

# 许可
本仓库采用 MIT 许可证
