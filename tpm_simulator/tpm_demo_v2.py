from flask import Flask, request, jsonify
from secrets import token_bytes
import base64
import time

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)

# ================== 启动时生成一对“TPM 内部”的 RSA 密钥 ==================

RSA_KEY_SIZE = 2048

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=RSA_KEY_SIZE,
)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")


# ================== API：随机数 / 加密 / 解密 / 签名 / 验证 ==================


@app.route("/api/random", methods=["GET"])
def api_random():
    """
    生成随机种子（TPM RNG 模拟）
    GET /api/random?bytes=32
    """
    try:
        n = int(request.args.get("bytes", 32))
    except ValueError:
        n = 32

    if n <= 0 or n > 4096:
        return jsonify({"error": "bytes must be in (0, 4096]"}), 400

    rb = token_bytes(n)
    return jsonify(
        {
            "random_hex": rb.hex(),
            "bytes": n,
            "timestamp": time.time(),
        }
    )


@app.route("/api/public_key", methods=["GET"])
def api_public_key():
    """
    返回当前“TPM 内部”公钥（PEM）
    """
    return jsonify({"public_key_pem": public_pem})


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    """
    用 TPM 公钥加密一段短文本（演示用）
    POST JSON: {"plaintext": "hello"}
    返回: {"ciphertext_b64": "..."}
    """
    data = request.get_json(force=True, silent=True) or {}
    plaintext = data.get("plaintext", "")
    if not plaintext:
        return jsonify({"error": "plaintext is empty"}), 400

    plaintext_bytes = plaintext.encode("utf-8")

    # 注意：RSA 适合短数据，这里只做演示
    try:
        ciphertext = public_key.encrypt(
            plaintext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as e:
        # 明文太长时会报错
        return jsonify({"error": f"plaintext too long for RSA: {str(e)}"}), 400

    ciphertext_b64 = base64.b64encode(ciphertext).decode("utf-8")
    return jsonify({"ciphertext_b64": ciphertext_b64})


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    """
    用 TPM 私钥解密
    POST JSON: {"ciphertext_b64": "..."}
    """
    data = request.get_json(force=True, silent=True) or {}
    ciphertext_b64 = data.get("ciphertext_b64", "")
    if not ciphertext_b64:
        return jsonify({"error": "ciphertext_b64 is empty"}), 400

    try:
        ciphertext = base64.b64decode(ciphertext_b64)
    except Exception:
        return jsonify({"error": "invalid base64"}), 400

    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        return jsonify({"error": f"decrypt failed: {str(e)}"}), 400

    return jsonify({"plaintext": plaintext_bytes.decode("utf-8", errors="replace")})


@app.route("/api/sign", methods=["POST"])
def api_sign():
    """
    用 TPM 私钥对消息签名
    POST JSON: {"message": "hello"}
    返回: {"signature_b64": "...", "message_sha256": "..."}
    """
    data = request.get_json(force=True, silent=True) or {}
    message = data.get("message", "")
    if not message:
        return jsonify({"error": "message is empty"}), 400

    message_bytes = message.encode("utf-8")

    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    signature_b64 = base64.b64encode(signature).decode("utf-8")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message_bytes)
    message_sha256 = digest.finalize().hex()

    return jsonify(
        {
            "signature_b64": signature_b64,
            "message_sha256": message_sha256,
        }
    )


@app.route("/api/verify", methods=["POST"])
def api_verify():
    """
    使用 TPM 公钥验证签名
    POST JSON: {"message": "hello", "signature_b64": "..."}
    返回: {"valid": true/false}
    """
    data = request.get_json(force=True, silent=True) or {}
    message = data.get("message", "")
    signature_b64 = data.get("signature_b64", "")

    if not message or not signature_b64:
        return jsonify({"error": "message or signature_b64 missing"}), 400

    message_bytes = message.encode("utf-8")
    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        return jsonify({"error": "invalid base64"}), 400

    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        valid = True
    except Exception:
        valid = False

    return jsonify({"valid": valid})


# ================== 简单前端页面：直接演示 ==================


@app.route("/")
def index():
    """
    更高级的前端页面：自适应布局 + 全局/局部进度条 + 适配 2K/27 寸字号
    """
    html = r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>TPM Demo · Trusted Crypto Core</title>
  <style>
    :root {
      --bg0: #020617;
      --bg1: #000000;
      --card: rgba(15, 23, 42, 0.88);
      --border: rgba(148, 163, 184, 0.35);
      --text: #e5e7eb;
      --muted: #9ca3af;
      --accent: #38bdf8;
      --accent2: #0ea5e9;
      --good: #4ade80;
      --shadow: 0 18px 55px rgba(2, 6, 23, 0.75);
      --r: 16px;

      /* ========= 关键：大屏字号倍率（27 寸 2K 推荐 1.15~1.25） ========= */
      --font-scale: 1.25;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif;
      background: radial-gradient(circle at 15% 5%, #1e293b 0, #020617 45%, #000 100%);
      color: var(--text);
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* 全局顶部进度条（API 调用时出现） */
    .topbar {
      position: fixed;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: rgba(56, 189, 248, 0.08);
      z-index: 9999;
    }
    .topbar > div {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, var(--accent), var(--accent2));
      box-shadow: 0 0 18px rgba(56,189,248,0.9);
      transition: width 0.12s linear, opacity 0.25s ease;
      opacity: 0;
    }

    /* 让主内容“自适应”屏幕：大屏更宽，小屏有边距 */
    .wrap {
      width: min(1480px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 18px 0 34px;
      padding-top: 22px; /* 避开 topbar */
    }

    header {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 12px;
      align-items: start;
      margin: 12px 0 18px;
    }

    @media (max-width: 860px) {
      header { grid-template-columns: 1fr; }
    }

    .title {
      font-size: clamp(
        calc(24px * var(--font-scale)),
        calc(2.4vw * var(--font-scale)),
        calc(36px * var(--font-scale))
      );
      font-weight: 780;
      letter-spacing: 0.02em;
      display: flex;
      align-items: center;
      gap: 10px;
      line-height: 1.15;
    }

    .badge {
      padding: 4px 10px;
      border-radius: 999px;
      border: 1px solid rgba(56, 189, 248, 0.35);
      background: radial-gradient(circle at top left, rgba(56, 189, 248, 0.18), transparent 60%);
      font-size: calc(12px * var(--font-scale));
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--accent);
      white-space: nowrap;
    }

    .subtitle {
      margin-top: 8px;
      color: var(--muted);
      font-size: calc(15px * var(--font-scale));
      line-height: 1.55;
      max-width: 86ch;
    }

    .chips {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: flex-end;
      align-items: flex-start;
      padding-top: 2px;
    }

    .chip {
      padding: 7px 12px;
      border-radius: 999px;
      border: 1px solid rgba(148, 163, 184, 0.35);
      color: var(--muted);
      font-size: calc(12px * var(--font-scale));
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(2, 6, 23, 0.35);
      backdrop-filter: blur(8px);
    }
    .dot {
      width: 7px; height: 7px; border-radius: 999px;
      background: var(--accent);
      box-shadow: 0 0 14px rgba(56,189,248,0.9);
    }

    /* Grid：使用 auto-fit，真正“自适应”列数 */
    main {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
      gap: 16px;
      align-items: stretch;
    }

    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--r);
      box-shadow: var(--shadow);
      overflow: hidden;
      position: relative;
      min-height: 380px;
    }

    .card::before {
      content: "";
      position: absolute; inset: 0;
      background: radial-gradient(circle at 15% 0%, rgba(56,189,248,0.22), transparent 55%);
      opacity: 0;
      transition: opacity 0.25s ease;
      pointer-events: none;
    }
    .card:hover::before { opacity: 1; }

    .card-head {
      padding: 16px 16px 12px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 10px;
      position: relative;
      z-index: 1;
    }

    .card-title {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 700;
      font-size: calc(18px * var(--font-scale));
      line-height: 1.2;
    }

    .icon {
      width: 26px; height: 26px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border-radius: 999px;
      border: 1px solid rgba(148, 163, 184, 0.55);
      color: var(--accent);
      font-size: calc(13px * var(--font-scale));
      background: rgba(2, 6, 23, 0.35);
      flex: 0 0 auto;
    }

    .card-desc {
      color: var(--muted);
      font-size: calc(13px * var(--font-scale));
      margin-top: 6px;
      line-height: 1.45;
    }

    .card-body {
      padding: 0 16px 16px;
      position: relative;
      z-index: 1;
    }

    label {
      display: block;
      font-size: calc(14px * var(--font-scale));
      color: var(--muted);
      margin: 10px 0 6px;
    }

    input, textarea {
      width: 100%;
      border-radius: 12px;
      border: 1px solid rgba(51, 65, 85, 0.95);
      background: rgba(2, 6, 23, 0.55);
      color: var(--text);
      padding: 10px 12px;
      font-size: calc(14px * var(--font-scale));
      outline: none;
      transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
      resize: vertical;
    }
    input:focus, textarea:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 1px rgba(56,189,248,0.65);
      background: rgba(2, 6, 23, 0.75);
    }

    textarea {
      min-height: 86px;
      max-height: 260px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      line-height: 1.5;
    }

    .row {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      margin-top: 10px;
    }

    button {
      border-radius: 999px;
      border: 1px solid rgba(56, 189, 248, 0.6);
      padding: 9px 14px;
      font-size: calc(14px * var(--font-scale));
      background: linear-gradient(135deg, rgba(15,23,42,0.95), rgba(2,6,23,0.95));
      color: var(--text);
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: transform 0.15s ease, box-shadow 0.15s ease, background 0.15s ease, border-color 0.15s ease;
      box-shadow: 0 10px 26px rgba(2, 6, 23, 0.9);
    }
    button:hover {
      transform: translateY(-1px);
      background: linear-gradient(135deg, rgba(3,105,161,0.95), rgba(15,23,42,0.95));
      border-color: var(--accent2);
      box-shadow: 0 14px 32px rgba(2, 6, 23, 0.95);
    }
    button:active { transform: translateY(0px) scale(0.99); }

    .btn2 {
      border-color: rgba(148, 163, 184, 0.55);
      background: rgba(2,6,23,0.55);
    }
    .btn2:hover {
      border-color: rgba(148, 163, 184, 0.95);
      background: rgba(2,6,23,0.7);
    }

    .result {
      margin-top: 12px;
      padding: 12px 12px;
      border-radius: 12px;
      border: 1px solid rgba(51, 65, 85, 0.95);
      background: radial-gradient(circle at 10% 0%, rgba(15,23,42,0.8), rgba(2,6,23,0.9));
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: calc(13px * var(--font-scale));
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 200px;
      overflow: auto;
      color: #e5e7eb;
      line-height: 1.45;
    }

    /* 卡片内进度条：让过程更“像系统在工作” */
    .progress {
      height: 10px;
      border-radius: 999px;
      background: rgba(56, 189, 248, 0.08);
      border: 1px solid rgba(56, 189, 248, 0.16);
      overflow: hidden;
      margin-top: 12px;
    }
    .bar {
      height: 100%;
      width: 0%;
      border-radius: 999px;
      background: linear-gradient(90deg, var(--accent), var(--accent2));
      box-shadow: 0 0 18px rgba(56,189,248,0.8);
      transition: width 0.12s linear, opacity 0.25s ease;
      opacity: 0.0;
    }

    footer {
      margin-top: 18px;
      display: flex;
      justify-content: space-between;
      gap: 10px;
      align-items: center;
      color: var(--muted);
      font-size: calc(13px * var(--font-scale));
      flex-wrap: wrap;
    }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 10px;
    }
    .s-dot {
      width: 10px; height: 10px; border-radius: 999px;
      background: var(--good);
      box-shadow: 0 0 14px rgba(74, 222, 128, 0.85);
    }
    .status strong { color: #e5e7eb; font-weight: 650; }

    .hint { opacity: 0.9; }
  </style>
</head>

<body>
  <div class="topbar"><div id="topbarFill"></div></div>

  <div class="wrap">
    <header>
      <div>
        <div class="title">
          TPM 模拟核心 <span class="badge">Trusted Crypto Core</span>
        </div>
        <div class="subtitle">
          轻量级 Demo：随机数（RNG）、RSA 加解密、签名与验证。所有操作均通过后端接口触发，并以进度条体现执行过程。
        </div>
      </div>
      <div class="chips">
        <div class="chip"><span class="dot"></span> Python · Flask</div>
        <div class="chip"><span class="dot"></span> cryptography · RSA-2048</div>
        <div class="chip"><span class="dot"></span> RNG / Encrypt / Sign</div>
      </div>
    </header>

    <main>
      <!-- 1. RNG -->
      <section class="card">
        <div class="card-head">
          <div>
            <div class="card-title"><span class="icon">R</span> 随机数生成 · RNG</div>
            <div class="card-desc">模拟 TPM 硬件随机数发生器（种子输出）</div>
          </div>
        </div>
        <div class="card-body">
          <label>随机字节数（1 ~ 64）：</label>
          <input id="randBytes" type="number" value="32" min="1" max="64" />
          <div class="row">
            <button onclick="genRandom()">生成随机种子</button>
          </div>

          <div class="progress"><div class="bar" id="pRng"></div></div>
          <div id="randResult" class="result">等待生成随机数...</div>
        </div>
      </section>

      <!-- 2. RSA Encrypt/Decrypt -->
      <section class="card">
        <div class="card-head">
          <div>
            <div class="card-title"><span class="icon">K</span> RSA 加解密</div>
            <div class="card-desc">使用 TPM 内部 RSA-2048 密钥对进行演示</div>
          </div>
        </div>
        <div class="card-body">
          <label>明文（不要太长）：</label>
          <textarea id="plainText" rows="3">hello, this is a TPM demo.</textarea>

          <div class="row">
            <button onclick="encrypt()">使用 TPM 公钥加密</button>
            <button class="btn2" onclick="decrypt()">使用 TPM 私钥解密</button>
          </div>

          <div class="progress"><div class="bar" id="pRsa"></div></div>

          <label style="margin-top:12px;">密文（Base64）：</label>
          <textarea id="cipherText" rows="3" placeholder="点击“加密”生成密文"></textarea>

          <div id="decryptResult" class="result">解密结果将在此显示。</div>
        </div>
      </section>

      <!-- 3. Sign/Verify -->
      <section class="card">
        <div class="card-head">
          <div>
            <div class="card-title"><span class="icon">S</span> 数字签名 · 验证</div>
            <div class="card-desc">模拟 TPM 对关键消息进行签名并验证</div>
          </div>
        </div>
        <div class="card-body">
          <label>待签名消息：</label>
          <textarea id="signMsg" rows="3">this message will be signed by TPM.</textarea>

          <div class="row">
            <button onclick="signMsgFn()">生成签名</button>
            <button class="btn2" onclick="verifyMsgFn()">验证签名</button>
          </div>

          <div class="progress"><div class="bar" id="pSig"></div></div>

          <label style="margin-top:12px;">签名（Base64）：</label>
          <textarea id="signResult" rows="3" placeholder="点击“生成签名”后自动填充"></textarea>

          <div id="verifyResult" class="result">等待签名结果...</div>
        </div>
      </section>
    </main>

    <footer>
      <div class="status">
        <span class="s-dot"></span>
        <span>TPM 模拟状态：<strong>在线</strong> · 内部 RSA 密钥已初始化</span>
      
    </footer>
  </div>

  <script>
    // ---------------- 全局/局部进度条动画（纯前端演示用） ----------------

    const topbarFill = document.getElementById('topbarFill');

    function startBar(el) {
      if (!el) return;
      el.style.opacity = '1';
      el.style.width = '0%';
      // 快速拉到 65%（模拟“处理中”）
      requestAnimationFrame(() => {
        el.style.width = '12%';
        setTimeout(() => el.style.width = '38%', 80);
        setTimeout(() => el.style.width = '65%', 180);
      });
    }

    function endBar(el, ok=true) {
      if (!el) return;
      el.style.opacity = '1';
      el.style.width = '92%';
      setTimeout(() => {
        el.style.width = '100%';
      }, 90);
      setTimeout(() => {
        el.style.opacity = '0';
        el.style.width = '0%';
      }, 360);
    }

    // 演示按钮：不调用接口也能看进度条效果
    function pulseDemo(id) {
      const el = document.getElementById(id);
      startBar(el);
      startBar(topbarFill);
      setTimeout(() => { endBar(el, true); endBar(topbarFill, true); }, 520);
    }

    async function fetchJSON(url, options, localBarId) {
      const localBar = localBarId ? document.getElementById(localBarId) : null;

      startBar(topbarFill);
      if (localBar) startBar(localBar);

      try {
        const res = await fetch(url, options);
        const data = await res.json().catch(() => ({}));
        endBar(topbarFill, !data.error);
        if (localBar) endBar(localBar, !data.error);
        return { ok: res.ok && !data.error, data, status: res.status };
      } catch (e) {
        endBar(topbarFill, false);
        if (localBar) endBar(localBar, false);
        return { ok: false, data: { error: String(e) }, status: 0 };
      }
    }

    // ---------------- 业务按钮 ----------------

    async function genRandom() {
      const n = document.getElementById('randBytes').value || 32;
      const ret = await fetchJSON('/api/random?bytes=' + n, null, 'pRng');
      const el = document.getElementById('randResult');

      if (!ret.ok) {
        el.innerText = '错误：' + (ret.data.error || '请求失败');
        return;
      }
      el.innerText =
        '长度: ' + ret.data.bytes + ' 字节\\n' +
        'HEX: ' + ret.data.random_hex;
    }

    async function encrypt() {
      const text = document.getElementById('plainText').value;
      const ret = await fetchJSON('/api/encrypt', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ plaintext: text })
      }, 'pRsa');

      if (!ret.ok) {
        alert('加密失败: ' + (ret.data.error || '请求失败'));
        return;
      }
      document.getElementById('cipherText').value = ret.data.ciphertext_b64;
    }

    async function decrypt() {
      const ct = document.getElementById('cipherText').value;
      const box = document.getElementById('decryptResult');

      const ret = await fetchJSON('/api/decrypt', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ ciphertext_b64: ct })
      }, 'pRsa');

      if (!ret.ok) {
        box.innerText = '解密失败: ' + (ret.data.error || '请求失败');
        return;
      }
      box.innerText = '解密结果: ' + ret.data.plaintext;
    }

    async function signMsgFn() {
      const msg = document.getElementById('signMsg').value;
      const ret = await fetchJSON('/api/sign', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ message: msg })
      }, 'pSig');

      const box = document.getElementById('verifyResult');

      if (!ret.ok) {
        box.innerText = '签名失败: ' + (ret.data.error || '请求失败');
        return;
      }
      document.getElementById('signResult').value = ret.data.signature_b64;
      box.innerText = '消息 SHA-256: ' + ret.data.message_sha256 + '\\n签名已生成，可点击“验证签名”。';
    }

    async function verifyMsgFn() {
      const msg = document.getElementById('signMsg').value;
      const sig = document.getElementById('signResult').value;
      const box = document.getElementById('verifyResult');

      const ret = await fetchJSON('/api/verify', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ message: msg, signature_b64: sig })
      }, 'pSig');

      if (!ret.ok) {
        box.innerText = '验证失败: ' + (ret.data.error || '请求失败');
        return;
      }
      box.innerText = '验证结果: ' + (ret.data.valid ? '✅ 有效签名' : '❌ 无效签名');
    }

    // 页面加载：自动跑一次 RNG，让界面有“已初始化/已工作”效果
    window.addEventListener('load', () => { genRandom(); });
  </script>
</body>
</html>
    """
    return html




if __name__ == "__main__":
    # 开发模式启动
    app.run(host="0.0.0.0", port=8000, debug=True)
