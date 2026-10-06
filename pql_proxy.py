#!/usr/bin/env python3
"""PromptQL Playground 反代（OpenAI 兼容）
把 PromptQL 的 GraphQL 内部接口翻译成 /v1/chat/completions。

用法:
    python3 pql_proxy.py            # 监听 127.0.0.1:8000（token 自动续）
    python3 pql_proxy.py --login    # 首次：浏览器打开链接登录一次，之后永久自动续
    JWT=eyJ... python3 pql_proxy.py  # 备用：手动给 token（环境变量或 key.txt）
"""
import base64
import hashlib
import json
import os
import re
import secrets
import time
import urllib.parse
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------- 配置 ----------------
GQL_URL = 'https://data.prompt.ql.app/promptql/playground-v2-hge/v1/graphql'
ORIGIN = 'https://mobile-app-origin.ql.app'
PROJECT_ID = '4c2a0298-30c6-4b30-84d8-8440f5b356ee'
TIMEZONE = 'Asia/Shanghai'
LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 8000
POLL_INTERVAL = 2
POLL_TIMEOUT = 180

JWT = os.environ.get('JWT', '').strip()
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'key.txt')
AUTH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'auth.json')
_KEY_MTIME = 0

# ---------------- OAuth 自动登录 ----------------
# 原理：refresh_token -> oauth token 接口换 access_token
#       -> EnrichToken mutation 换 playground JWT（24h）
OAUTH_BASE = 'https://oauth.pro.ql.app/oauth2'
OAUTH_CLIENT_ID = '2e126f16-0d98-4890-9431-f4065f133e73'
OAUTH_REDIRECT = 'https://prompt.ql.app/mobile-app/oauth2/callback'
OAUTH_SCOPE = 'openid offline'  # offline 才能拿到 refresh_token

# 原生文件上传：POST {ARTIFACTS_BASE}/artifacts（multipart）
# 官方网页版 createArtifact 接口，需 userDirectoryJWT（即 playground JWT）
# baseUrl 待确认，暂留配置项
ARTIFACTS_BASE = None  # 例如 'https://data.prompt.ql.app/promptql/promptql-v2'

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def _jwt_exp(jwt: str) -> int:
    return json.loads(base64.urlsafe_b64decode(jwt.split('.')[1] + '=='))['exp']

def _post_form(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, headers={
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 15) Mobile Safari/537.36',
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())

def oauth_login_url():
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    state = _b64url(secrets.token_bytes(16))
    q = urllib.parse.urlencode({
        'client_id': OAUTH_CLIENT_ID,
        'redirect_uri': OAUTH_REDIRECT,
        'response_type': 'code',
        'scope': OAUTH_SCOPE,
        'state': state,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
    })
    return f'{OAUTH_BASE}/auth?{q}', verifier

def oauth_exchange(code, verifier):
    return _post_form(f'{OAUTH_BASE}/token', {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': OAUTH_REDIRECT,
        'client_id': OAUTH_CLIENT_ID,
        'code_verifier': verifier,
    })

def oauth_refresh(refresh_token):
    return _post_form(f'{OAUTH_BASE}/token', {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': OAUTH_CLIENT_ID,
    })

def mint_lux_jwt(access_token):
    """access_token -> luxJWT（调 control plane 的 mint 接口）。"""
    req = urllib.request.Request(
        'https://auth.pro.ql.app/ddn/promptql/token', data=b'',
        headers={
            'authorization': f'Bearer {access_token}',
            'x-hasura-project-id': PROJECT_ID,
            'Accept': '*/*',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 15) Mobile Safari/537.36',
        }, method='POST')
    with urllib.request.urlopen(req, timeout=30) as r:
        res = json.loads(r.read().decode())
    if not res.get('token'):
        raise RuntimeError('mint luxJWT 失败: ' + json.dumps(res)[:300])
    return res['token']

def enrich_token(lux_jwt):
    """luxJWT -> playground JWT，调 playground 自己的 GraphQL，无需 auth 头。"""
    q = ('mutation EnrichToken($luxJWT: String!, $projectId: uuid!) {'
         ' enrich_token(luxJWT: $luxJWT, projectId: $projectId) { userDirectoryJWT } }')
    payload = {'query': q, 'operationName': 'EnrichToken',
               'variables': {'luxJWT': lux_jwt, 'projectId': PROJECT_ID}}
    req = urllib.request.Request(GQL_URL, data=json.dumps(payload).encode(), headers={
        'Content-Type': 'application/json', 'Accept': '*/*', 'Accept-Encoding': 'identity',
        'Origin': ORIGIN,
        'User-Agent': 'Mozilla/5.0 (Linux; Android 15) Mobile Safari/537.36',
    }, method='POST')
    with urllib.request.urlopen(req, timeout=30) as r:
        res = json.loads(r.read().decode())
    jwt = (res.get('data') or {}).get('enrich_token', {}).get('userDirectoryJWT')
    if not jwt:
        raise RuntimeError('enrich_token 没返回 JWT: ' + json.dumps(res)[:300])
    return jwt

def native_upload(jwt, file_data, filename, mime, thread_id='00000000-0000-0000-0000-000000000000'):
    """原生上传文件到 PromptQL artifacts，返回 (artifact_id, version)。
    对应网页版 createArtifact：POST {ARTIFACTS_BASE}/artifacts，multipart。
    ARTIFACTS_BASE 未配置时抛 RuntimeError。"""
    if not ARTIFACTS_BASE:
        raise RuntimeError('ARTIFACTS_BASE 未配置，原生上传不可用')
    import uuid
    boundary = '----pql' + uuid.uuid4().hex[:12]
    artifact_request = json.dumps({
        'filename': filename, 'title': filename, 'artifact_type': 'file',
        'data': None, 'threadId': thread_id, 'file_mime_type': mime,
    })
    body = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="artifact_request"; filename="blob"\r\n'
        f'Content-Type: application/json\r\n\r\n'
        f'{artifact_request}\r\n'
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="artifact_data"; filename="{filename}"\r\n'
        f'Content-Type: {mime}\r\n\r\n'
    ).encode() + file_data + f'\r\n--{boundary}--\r\n'.encode()
    req = urllib.request.Request(ARTIFACTS_BASE + '/artifacts', data=body, headers={
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'Authorization': f'Bearer {jwt}',
        'Origin': ORIGIN,
        'User-Agent': 'Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36',
    }, method='POST')
    with urllib.request.urlopen(req, timeout=60) as r:
        res = json.loads(r.read().decode())
    data = res.get('data') or res
    aid = data.get('artifact_id') or data.get('artifactId')
    ver = data.get('version', 1)
    if not aid:
        raise RuntimeError('上传未返回 artifact_id: ' + json.dumps(res)[:300])
    return aid, ver

def load_auth():
    try:
        with open(AUTH_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}

def save_auth(d):
    with open(AUTH_FILE, 'w') as f:
        json.dump(d, f)

def auto_jwt():
    """返回有效的 playground JWT；过期自动用 refresh_token 续。"""
    a = load_auth()
    now = time.time()
    if a.get('playground_jwt') and a.get('playground_exp', 0) - 3600 > now:
        return a['playground_jwt']
    rt = a.get('refresh_token')
    if not rt:
        return None
    try:
        tok = oauth_refresh(rt)
    except Exception as e:
        raise RuntimeError(f'refresh_token 失效，请重新 --login（{e}）')
    if tok.get('refresh_token'):
        a['refresh_token'] = tok['refresh_token']  # rotation
    jwt = enrich_token(mint_lux_jwt(tok['access_token']))
    a['playground_jwt'] = jwt
    a['playground_exp'] = _jwt_exp(jwt)
    save_auth(a)
    return jwt

def do_login():
    url, verifier = oauth_login_url()
    print('1. 在浏览器打开下面这个链接，完成登录：')
    print()
    print(url)
    print()
    print('2. 登录后浏览器会跳到一个空白/报错页，从地址栏复制 ?code= 后面的那串字符，粘贴到这里：')
    code = input('code: ').strip().split('&')[0].split('?code=')[-1].strip()
    if not code:
        print('没拿到 code，退出')
        return
    print('正在换 token...')
    tok = oauth_exchange(code, verifier)
    a = {'refresh_token': tok['refresh_token']}
    save_auth(a)
    jwt = enrich_token(mint_lux_jwt(tok['access_token']))
    a['playground_jwt'] = jwt
    a['playground_exp'] = _jwt_exp(jwt)
    save_auth(a)
    print('登录成功！refresh_token 已保存，以后 playground token 会自动续，不用再管。')

def load_jwt():
    """优先级：自动续签(auth.json) > 环境变量 > key.txt（热加载）。"""
    global JWT, _KEY_MTIME
    try:
        jwt = auto_jwt()
        if jwt:
            return jwt
    except RuntimeError as e:
        # refresh 失败时不要吞掉，让调用方看到明确错误
        raise
    except Exception:
        pass
    if os.environ.get('JWT', '').strip():
        JWT = os.environ['JWT'].strip()
        return JWT
    try:
        mt = os.path.getmtime(KEY_FILE)
        if mt != _KEY_MTIME:
            with open(KEY_FILE) as f:
                JWT = f.read().strip()
            _KEY_MTIME = mt
    except FileNotFoundError:
        pass
    return JWT

# 模型名 -> llmConfigId（来自 FetchLlmConfigs）
MODELS = {
    'gpt-6.1-sol':      '8b028746-86fd-487d-a02b-7322c5d72073',
    'gpt-6-sol':        '8b028746-86fd-487d-a02b-7322c5d72073',
    'gpt-6-astra':      'ddf1b6be-a9e2-4c37-b44f-9805c5b69576',
    'claude-fable-5.1': '5444b356-874d-4742-829b-ad0924b8df18',
    'claude-opus-5.5':  '703dbedc-136a-40da-8158-9116adc463ee',
}
DISPLAY = {
    'gpt-6.1-sol': 'GPT-6.1 Sol', 'gpt-6-sol': 'GPT-6.1 Sol',
    'gpt-6-astra': 'GPT-6 Astra',
    'claude-fable-5.1': 'Claude Fable 5.1',
    'claude-opus-5.5': 'Claude Opus 5.5',
}
DEFAULT_MODEL = 'gpt-6.1-sol'

# ---------------- GraphQL ----------------
def gql(query, variables=None, operation=None, retries=3):
    payload = {'query': query}
    if variables:
        payload['variables'] = variables
    if operation:
        payload['operationName'] = operation
    token = load_jwt()
    req = urllib.request.Request(
        GQL_URL,
        data=json.dumps(payload).encode(),
        headers={
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Accept-Encoding': 'identity',
            'Origin': ORIGIN,
            'Referer': ORIGIN + '/',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 15) Mobile Safari/537.36',
        },
        method='POST',
    )
    last = None
    for i in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors='replace')[:500]
            raise RuntimeError(f'GraphQL HTTP {e.code}: {body}')
        except Exception as e:  # 网络抽风，重试
            last = e
            time.sleep(2 * (i + 1))
    raise RuntimeError(f'网络失败(已重试{retries}次): {last}')

START_THREAD_Q = '''mutation StartThreadRoomlessWithModel(
  $message: String!, $projectId: String!, $timezone: String!, $llmConfigId: String!,
  $agentResponseConfig: String, $uploads: [UserUploadInput!]) {
  start_thread(message: $message, projectId: $projectId, timezone: $timezone,
    llmConfigId: $llmConfigId, roomless: true, agentResponseConfig: $agentResponseConfig,
    uploads: $uploads) {
    thread_id
    thread_events { thread_event_id }
  }
}'''

EVENTS_Q = '''query getThreadEvents($thread_id: uuid, $after_event_id: bigint!) {
  thread_events(
    where: {thread_id: {_eq: $thread_id}, thread_event_id: {_gt: $after_event_id}}
    order_by: {thread_event_id: asc}) {
    thread_event_id
    event_data
  }
}'''

POST_IN_CHAT = re.compile(r'<post_in_chat[^>]*>(.*?)</post_in_chat>', re.S)

def start_thread(message, llm_config_id, uploads=None):
    vars = {
        'message': '<agent_mention /> ' + message,
        'projectId': PROJECT_ID,
        'timezone': TIMEZONE,
        'llmConfigId': llm_config_id,
        'agentResponseConfig': 'force_respond',
    }
    if uploads:
        vars['uploads'] = uploads
    res = gql(START_THREAD_Q, vars, 'StartThreadRoomlessWithModel')
    if res.get('errors'):
        raise RuntimeError('start_thread 失败: ' + json.dumps(res['errors'])[:300])
    st = res['data']['start_thread']
    evs = st.get('thread_events') or []
    after = evs[-1]['thread_event_id'] if evs else '0'
    return st['thread_id'], after

def poll_reply(thread_id, after_id):
    """轮询直到 interaction_finished，返回 (text, usage)。"""
    texts, usage = [], {}
    deadline = time.time() + POLL_TIMEOUT
    finished = False
    while time.time() < deadline and not finished:
        res = gql(EVENTS_Q, {'thread_id': thread_id, 'after_event_id': after_id},
                  'getThreadEvents')
        if res.get('errors'):
            raise RuntimeError('getThreadEvents 失败: ' + json.dumps(res['errors'])[:300])
        for ev in res['data']['thread_events']:
            after_id = ev['thread_event_id']
            content = (ev.get('event_data', {}).get('AgentMessage', {})
                         .get('update', {}).get('content', {}))
            if 'interaction_finished' in content:
                finished = True
                continue
            iu = content.get('interaction_update', {})
            ma = iu.get('main_agent', {})
            lr = ma.get('llm_response') or {}
            rt = lr.get('response_text') or ''
            if rt:
                for m in POST_IN_CHAT.finditer(rt):
                    texts.append(m.group(1))
                if lr.get('usage'):
                    usage = lr['usage']
        if not finished:
            time.sleep(POLL_INTERVAL)
    if not finished:
        raise RuntimeError('等待回复超时')
    return ''.join(texts).strip(), usage

def chat(message, model, uploads=None):
    llm_config_id = MODELS.get(model, MODELS[DEFAULT_MODEL])
    thread_id, after = start_thread(message, llm_config_id, uploads)
    return poll_reply(thread_id, after)

# ---------------- HTTP ----------------
def parse_tool_calls(text):
    """从 agent 回复里解析 ```tool_calls JSON```，返回 (tool_calls, 剩余正文)。"""
    m = re.search(r'```tool_calls\s*(\{.*?\})\s*```', text, re.S)
    if not m:
        return None, text
    try:
        data = json.loads(m.group(1))
        tcs = data.get('tool_calls')
        if not tcs:
            return None, text
        out = []
        for i, tc in enumerate(tcs):
            args = tc.get('arguments', {})
            out.append({
                'id': f'call_pql_{int(time.time())}_{i}',
                'type': 'function',
                'function': {
                    'name': tc.get('name', ''),
                    'arguments': args if isinstance(args, str) else json.dumps(args, ensure_ascii=False),
                },
            })
        rest = (text[:m.start()] + text[m.end():]).strip()
        return out, rest
    except (ValueError, AttributeError):
        return None, text

def openai_response(model, text, usage, stream):
    mid = 'chatcmpl-pql-' + str(int(time.time()))
    created = int(time.time())
    u = {
        'prompt_tokens': usage.get('input_tokens', 0),
        'completion_tokens': usage.get('output_tokens', 0),
        'total_tokens': usage.get('input_tokens', 0) + usage.get('output_tokens', 0),
    }
    tool_calls, clean_text = parse_tool_calls(text)
    if not stream:
        msg = {'role': 'assistant', 'content': clean_text or None}
        finish = 'stop'
        if tool_calls:
            msg['tool_calls'] = tool_calls
            msg['content'] = clean_text or None
            finish = 'tool_calls'
        return json.dumps({
            'id': mid, 'object': 'chat.completion', 'created': created,
            'model': model,
            'choices': [{'index': 0, 'message': msg, 'finish_reason': finish}],
            'usage': u,
        }, ensure_ascii=False)
    # SSE 流式：分块吐
    chunks = []
    def chunk(delta, finish=None):
        d = {'id': mid, 'object': 'chat.completion.chunk', 'created': created,
             'model': model,
             'choices': [{'index': 0, 'delta': delta, 'finish_reason': finish}]}
        return 'data: ' + json.dumps(d, ensure_ascii=False) + '\n\n'
    chunks.append(chunk({'role': 'assistant'}))
    if tool_calls:
        for tc in tool_calls:
            chunks.append(chunk({'tool_calls': [tc]}))
        chunks.append(chunk({}, 'tool_calls'))
    else:
        step = 60
        for i in range(0, len(clean_text), step):
            chunks.append(chunk({'content': clean_text[i:i + step]}))
        chunks.append(chunk({}, 'stop'))
    chunks.append('data: [DONE]\n\n')
    return ''.join(chunks)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='application/json'):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(data)

    def _handle_file_upload(self):
        """POST /v1/files：multipart 上传文件，返回 OpenAI 格式的 file 对象。"""
        import uuid
        ctype = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in ctype:
            self._send(400, '{"error":"need multipart/form-data"}')
            return
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length)
            # 解析 multipart
            boundary = ctype.split('boundary=')[1].encode()
            parts = body.split(b'--' + boundary)
            file_data = None
            filename = 'upload.bin'
            for part in parts:
                if b'filename="' in part:
                    # 提取文件名
                    fn = re.search(rb'filename="([^"]+)"', part)
                    if fn:
                        filename = fn.group(1).decode('utf-8', 'ignore')
                    # 文件内容在 \r\n\r\n 之后
                    idx = part.find(b'\r\n\r\n')
                    if idx >= 0:
                        file_data = part[idx+4:]
                        # 去掉末尾的 \r\n
                        if file_data.endswith(b'\r\n'):
                            file_data = file_data[:-2]
                    break
            if not file_data:
                self._send(400, '{"error":"no file in upload"}')
                return
            # 存到本地
            files_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')
            os.makedirs(files_dir, exist_ok=True)
            fid = 'file-' + uuid.uuid4().hex[:16]
            # 根据扩展名定 mime
            ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            mime_map = {'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
                        'webp': 'image/webp', 'gif': 'image/gif', 'pdf': 'application/pdf',
                        'txt': 'text/plain', 'md': 'text/markdown'}
            mime = mime_map.get(ext, 'application/octet-stream')
            safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
            fpath = os.path.join(files_dir, fid + '_' + safe_name)
            with open(fpath, 'wb') as f:
                f.write(file_data)
            # 存元信息
            meta = {'id': fid, 'filename': filename, 'mime': mime,
                    'bytes': len(file_data), 'path': fpath}
            with open(os.path.join(files_dir, fid + '.json'), 'w') as f:
                json.dump(meta, f)
            self._send(200, json.dumps({
                'id': fid, 'object': 'file', 'bytes': len(file_data),
                'filename': filename, 'purpose': 'vision',
            }))
        except Exception as e:
            self._send(500, json.dumps({'error': str(e)[:200]}))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_GET(self):
        if self.path == '/v1/models':
            self._send(200, json.dumps({
                'object': 'list',
                'data': [{'id': m, 'object': 'model', 'owned_by': DISPLAY.get(m, m)}
                         for m in MODELS],
            }))
        elif self.path in ('/', '/health'):
            self._send(200, 'pql_proxy ok', 'text/plain')
        else:
            self._send(404, '{"error":"not found"}')

    def do_POST(self):
        if self.path == '/v1/files':
            self._handle_file_upload()
            return
        if self.path != '/v1/chat/completions':
            self._send(404, '{"error":"not found"}')
            return
        try:
            length = int(self.headers.get('Content-Length', 0))
            req = json.loads(self.rfile.read(length).decode() or '{}')
        except Exception:
            self._send(400, '{"error":"invalid json"}')
            return
        try:
            token = load_jwt()
        except RuntimeError as e:
            self._send(401, json.dumps({'error': str(e)}, ensure_ascii=False))
            return
        if not token:
            self._send(401, json.dumps({'error': '没登录：先运行 python3 pql_proxy.py --login'}))
            return
        model = req.get('model', DEFAULT_MODEL)
        messages = req.get('messages', [])
        tools = req.get('tools', [])
        tool_choice = req.get('tool_choice', 'auto')

        def _content_text(c):
            if isinstance(c, str):
                return c
            if isinstance(c, list):
                return ' '.join(p.get('text', '') for p in c if isinstance(p, dict))
            return str(c)

        def _collect_images(c):
            """从多模态 content 里提取图片。
            支持：公网 http(s) URL、base64 data URI、file_id（/v1/files 上传的）。
            base64 data URI 直接传给 agent（vision 原生支持）。"""
            urls = []
            if isinstance(c, list):
                for p in c:
                    if not isinstance(p, dict):
                        continue
                    if p.get('type') == 'image_url':
                        u = (p.get('image_url') or {}).get('url', '')
                        if u.startswith('http'):
                            urls.append(u)
                        elif u.startswith('data:image/'):
                            # 解码压缩后再转 base64，省 token
                            try:
                                import base64 as _b64
                                header, b64data = u.split(',', 1)
                                raw = _b64.b64decode(b64data)
                                mime = header.split(':')[1].split(';')[0]
                                raw, mime = _compress_image(raw, mime)
                                urls.append(f"data:{mime};base64,{_b64.b64encode(raw).decode()}")
                            except Exception:
                                urls.append(u)
                    elif p.get('type') == 'file' and p.get('file_id'):
                        du = _file_to_data_uri(p['file_id'])
                        urls.append(du if du else '[文件不存在或格式不支持]')
            elif isinstance(c, str):
                for fid in re.findall(r'file-[0-9a-f]{16}', c):
                    du = _file_to_data_uri(fid)
                    if du:
                        urls.append(du)
            return urls

        def _compress_image(raw, mime):
            """图片压缩到 1024px 以内、JPEG 质量 80，大幅降 token。"""
            try:
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(raw))
                # 转 RGB（去 alpha，JPEG 不支持）
                if img.mode in ('RGBA', 'LA', 'P'):
                    bg = Image.new('RGB', img.size, (255, 255, 255))
                    bg.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                    img = bg
                elif img.mode != 'RGB':
                    img = img.convert('RGB')
                # 缩到最长边 1024
                w, h = img.size
                if max(w, h) > 1024:
                    r = 1024 / max(w, h)
                    img = img.resize((int(w*r), int(h*r)), Image.LANCZOS)
                out = io.BytesIO()
                img.save(out, 'JPEG', quality=80, optimize=True)
                return out.getvalue(), 'image/jpeg'
            except Exception:
                return raw, mime

        def _file_to_data_uri(fid):
            """file_id -> data URI（图片压缩后）或文本内容。"""
            try:
                import base64 as _b64
                files_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')
                with open(os.path.join(files_dir, fid + '.json')) as f:
                    meta = json.load(f)
                with open(meta['path'], 'rb') as f:
                    raw = f.read()
                mime = meta.get('mime', '')
                if mime.startswith('image/'):
                    raw, mime = _compress_image(raw, mime)
                    return f"data:{mime};base64,{_b64.b64encode(raw).decode()}"
                else:
                    try:
                        txt = raw.decode('utf-8', 'ignore')[:20000]
                        return f"[文件 {meta['filename']} 内容]\n{txt}"
                    except:
                        return None
            except:
                return None

        # 组装发给 PromptQL 的提示词：带上工具定义 + 最近的 tool 往返
        prompt_parts = []
        if tools:
            defs = []
            for t in tools:
                f = t.get('function', t)
                defs.append(f"- {f.get('name','')}: {f.get('description','')}\n  参数: {json.dumps(f.get('parameters',{}), ensure_ascii=False)}")
            prompt_parts.append(
                "你可以使用以下工具。当你需要调用工具时，只输出下面这种 JSON（放在 ```tool_calls 代码块里），不要输出其他内容：\n"
                "```tool_calls\n{\"tool_calls\": [{\"name\": \"工具名\", \"arguments\": {...}}]}\n```\n"
                "可用工具：\n" + "\n".join(defs) +
                ("\n\n用户要求必须调用工具。" if tool_choice == 'required' else ""))
        hist = []
        for m in messages:
            r = m.get('role')
            if r == 'tool':
                hist.append(f"[工具 {m.get('name','')} 返回]\n{_content_text(m.get('content',''))}")
            elif r == 'assistant' and m.get('tool_calls'):
                names = [t.get('function',{}).get('name','') for t in m['tool_calls']]
                hist.append(f"[你刚才调用了工具: {', '.join(names)}]")
        user_msgs = [_content_text(m.get('content','')) for m in messages if m.get('role') == 'user']
        # 原生上传：尝试把文件传到 PromptQL artifacts，走 uploads 参数（不走 base64）
        native_uploads = []
        if ARTIFACTS_BASE:
            try:
                token = load_jwt()
                for m in messages:
                    if m.get('role') != 'user':
                        continue
                    c = m.get('content')
                    # 从 file_id 引用提取
                    fids = []
                    if isinstance(c, list):
                        for p in c:
                            if isinstance(p, dict) and p.get('type') == 'file' and p.get('file_id'):
                                fids.append(p['file_id'])
                    elif isinstance(c, str):
                        fids.extend(re.findall(r'file-[0-9a-f]{16}', c))
                    for fid in fids:
                        try:
                            files_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')
                            with open(os.path.join(files_dir, fid + '.json')) as f:
                                meta = json.load(f)
                            with open(meta['path'], 'rb') as f:
                                raw = f.read()
                            aid, ver = native_upload(token, raw, meta['filename'], meta.get('mime', 'application/octet-stream'))
                            native_uploads.append({
                                'artifact_name': meta['filename'],
                                'artifact_reference': {'artifact_id': aid, 'version': ver},
                            })
                        except Exception:
                            pass
            except Exception:
                pass
        # 图片：收集所有 image_url，喂给 agent（原生上传成功的就不走 base64 了）
        img_urls = []
        if not native_uploads:
            for m in messages:
                if m.get('role') == 'user':
                    img_urls.extend(_collect_images(m.get('content')))
        if img_urls:
            prompt_parts.append("用户发送了以下图片，请查看并结合图片内容回答：\n" + "\n".join(f"- {u}" for u in img_urls))
        if native_uploads:
            prompt_parts.append(f"用户上传了 {len(native_uploads)} 个文件（见附件），请查看并结合文件内容回答。")
        if hist:
            prompt_parts.append("\n".join(hist[-6:]))
        prompt = "\n\n".join(prompt_parts + ([user_msgs[-1]] if user_msgs else []))
        stream = bool(req.get('stream'))
        try:
            text, usage = chat(str(prompt), model, native_uploads or None)
        except RuntimeError as e:
            msg = str(e)
            code = 401 if '401' in msg or 'JWT' in msg else 502
            self._send(code, json.dumps({'error': msg}, ensure_ascii=False))
            return
        body = openai_response(model, text, usage, stream)
        ctype = 'text/event-stream' if stream else 'application/json'
        self._send(200, body, ctype)

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--login':
        do_login()
        sys.exit(0)
    srv = HTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f'pql_proxy listening on {LISTEN_HOST}:{LISTEN_PORT}')
    print('models:', ', '.join(sorted(set(MODELS))))
    try:
        has = bool(load_jwt())
    except RuntimeError as e:
        print('JWT 错误:', e)
        has = False
    print('JWT:', '已配置（自动续签）' if has else '未配置（先运行 --login，或用 JWT=/key.txt 手动）')
    srv.serve_forever()
