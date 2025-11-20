from datetime import datetime, timedelta, time, date
from io import StringIO, BytesIO
import csv
import os
import random
import time as pytime
import uuid
import base64
import requests
from requests.exceptions import (
    Timeout, ConnectionError, RequestException,
    ConnectTimeout, ReadTimeout, SSLError
)
import hmac
import hashlib
import json
from urllib.parse import quote, urlencode, urlparse

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    Response,
    flash,
    get_flashed_messages,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, case
from PIL import Image

print(">>> app.py 已被执行")

app = Flask(__name__)

# --- 基本设定 ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, "lottery.db")

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "change_this_to_random_string"

# 7 天免登录
app.permanent_session_lifetime = timedelta(days=7)

db = SQLAlchemy(app)

# 圖片儲存路徑
UPLOAD_BASE = os.path.join(BASE_DIR, "static", "uploads")
ORIGINAL_DIR = os.path.join(UPLOAD_BASE, "originals")
GENERATED_DIR = os.path.join(UPLOAD_BASE, "generated")
THUMB_DIR = os.path.join(UPLOAD_BASE, "thumbnails")
for folder in (ORIGINAL_DIR, GENERATED_DIR, THUMB_DIR):
    os.makedirs(folder, exist_ok=True)

# 管理员账号
ADMIN_USERNAME = "robot"
ADMIN_PASSWORD = "cs168"

# 固定战队列表
TEAM_CHOICES = ["青龙战队", "白虎战队", "朱雀战队", "玄武战队", "黄龙战队"]

# 即梦AI配置（从环境变量读取，如果没有则使用默认值）
# Aihubmix统一接口（推荐，最简单）
AIHUBMIX_API_TOKEN = os.getenv("AIHUBMIX_API_TOKEN", "")  # Aihubmix Bearer Token
USE_AIHUBMIX = os.getenv("USE_AIHUBMIX", "false").lower() == "true"  # 是否使用Aihubmix

# 即梦4.0使用Bearer Token认证，更简单
JIMENG_V4_API_URL = os.getenv("JIMENG_V4_API_URL", "")  # 即梦4.0 API地址
JIMENG_V4_API_TOKEN = os.getenv("JIMENG_V4_API_TOKEN", "")  # 即梦4.0 Bearer Token
JIMENG_V4_MODEL = os.getenv("JIMENG_V4_MODEL", "doubao-seedream-4-0-250828")  # 模型名称
USE_JIMENG_V4 = os.getenv("USE_JIMENG_V4", "false").lower() == "true"  # 是否使用即梦4.0

# 如果4.0的Token未配置，尝试使用3.0的AK/SK（某些情况下可能兼容）
# 注意：这需要根据实际API文档调整

# 即梦3.0配置（旧版本，使用复杂签名）
JIMENG_API_URL = os.getenv("JIMENG_API_URL", "https://visual.volcengineapi.com")
JIMENG_API_PATH = os.getenv("JIMENG_API_PATH", "/")
JIMENG_ACCESS_KEY = os.getenv("JIMENG_ACCESS_KEY", "")  # AK - 从环境变量读取
JIMENG_SECRET_KEY = os.getenv("JIMENG_SECRET_KEY", "")  # SK - 从环境变量读取
JIMENG_SERVICE = os.getenv("JIMENG_SERVICE", "cv")  # 服务名
JIMENG_REGION = os.getenv("JIMENG_REGION", "cn-north-1")  # 区域
JIMENG_SUBMIT_ACTION = os.getenv("JIMENG_SUBMIT_ACTION", "CVSync2AsyncSubmitTask")
JIMENG_RESULT_ACTION = os.getenv("JIMENG_RESULT_ACTION", "CVSync2AsyncGetResult")
JIMENG_VERSION = os.getenv("JIMENG_VERSION", "2022-08-31")
JIMENG_REQ_KEY = os.getenv("JIMENG_REQ_KEY", "i2i_v30_jimeng")
JIMENG_ALLOW_FALLBACK = os.getenv("JIMENG_ALLOW_FALLBACK", "false").lower() == "true"


def _env_float(var_name, default_value):
    try:
        return float(os.getenv(var_name, default_value))
    except (TypeError, ValueError):
        return float(default_value)


JIMENG_RESULT_POLL_INTERVAL = _env_float("JIMENG_POLL_INTERVAL", 3)
JIMENG_RESULT_TIMEOUT = _env_float("JIMENG_POLL_TIMEOUT", 90)
JIMENG_DEFAULT_SCALE = _env_float("JIMENG_DEFAULT_SCALE", 0.5)


def parse_date_input(date_text):
    if not date_text:
        return None
    try:
        return datetime.strptime(date_text, "%Y-%m-%d")
    except ValueError:
        return None


# --- 资料表定义 ---

class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    login_name = db.Column(db.String(150), unique=True, nullable=False)
    team = db.Column(db.String(50), nullable=True)

    consumed_draws = db.Column(db.Integer, default=0, nullable=False)
    remaining_draws = db.Column(db.Integer, default=0, nullable=False)

    first_login_at = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)

    devices = db.relationship("Device", backref="user", lazy=True)
    cards = db.relationship("UserCard", backref="user", lazy=True)
    draw_logs = db.relationship("DrawLog", backref="user", lazy=True)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    device_identifier = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class PendingDevice(db.Model):
    """等待管理员审核的新设备绑定申请"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    device_identifier = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User", backref="pending_devices")


class UserCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    card_id = db.Column(db.Integer, nullable=False)
    obtained_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class DrawLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    card_id = db.Column(db.Integer, nullable=False)
    is_bonus_card6 = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class AdminLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_name = db.Column(db.String(50), nullable=False)
    action = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class GenerateRecord(db.Model):
    """使用者提交生成财神手辦的紀錄"""

    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100), nullable=True)
    prompt = db.Column(db.Text, nullable=False)
    original_image_url = db.Column(db.String(255), nullable=False)
    thumbnail_url = db.Column(db.String(255), nullable=False)
    dream_image_url = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), default="pending", nullable=False)  # pending/approved/rejected
    approved_by = db.Column(db.String(50), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class TeamRankSnapshot(db.Model):
    """战队排名历史快照"""
    id = db.Column(db.Integer, primary_key=True)
    team_name = db.Column(db.String(50), nullable=False)
    rank = db.Column(db.Integer, nullable=False)  # 排名
    total_cards = db.Column(db.Integer, default=0, nullable=False)  # 战队财神卡总数
    total_draws = db.Column(db.Integer, default=0, nullable=False)  # 战队抽卡次数
    snapshot_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # 快照时间
    snapshot_date = db.Column(db.Date, nullable=False)  # 快照日期（用于每日对比）


# --- 小工具 ---

def calculate_team_stats():
    """计算所有战队的统计数据"""
    teams = {}
    
    # 遍历所有用户
    for user in User.query.all():
        if not user.team:
            continue
            
        team_name = user.team
        if team_name not in teams:
            teams[team_name] = {
                "total_cards": set(),  # 使用set去重
                "total_draws": 0,
            }
        
        # 统计该用户集齐的卡种类（去重）
        user_cards = set([uc.card_id for uc in user.cards])
        teams[team_name]["total_cards"].update(user_cards)
        
        # 累加抽卡次数
        teams[team_name]["total_draws"] += user.consumed_draws
    
    # 转换为卡数量
    for team_name in teams:
        teams[team_name]["total_cards"] = len(teams[team_name]["total_cards"])
    
    return teams


def calculate_team_rankings():
    """计算战队排名，返回排序后的列表"""
    teams = calculate_team_stats()
    
    # 转换为列表并排序：先按卡数量降序，再按抽卡次数降序
    team_list = [
        {
            "team_name": name,
            "total_cards": data["total_cards"],
            "total_draws": data["total_draws"],
        }
        for name, data in teams.items()
    ]
    
    # 排序：卡数量降序，相同则抽卡次数降序
    team_list.sort(key=lambda x: (x["total_cards"], x["total_draws"]), reverse=True)
    
    # 添加排名
    for idx, team in enumerate(team_list, 1):
        team["rank"] = idx
    
    return team_list


def get_team_rank_info(team_name):
    """获取指定战队的排名信息"""
    if not team_name:
        return None
    
    rankings = calculate_team_rankings()
    
    # 找到当前战队
    current_team = None
    for team in rankings:
        if team["team_name"] == team_name:
            current_team = team
            break
    
    if not current_team:
        return None
    
    # 计算距离前一名需要的卡数
    cards_to_catch_up = 0
    if current_team["rank"] > 1:
        # 找到前一名
        prev_team = rankings[current_team["rank"] - 2]
        cards_to_catch_up = prev_team["total_cards"] - current_team["total_cards"]
        if cards_to_catch_up < 0:
            cards_to_catch_up = 0
    
    return {
        "team_name": current_team["team_name"],
        "rank": current_team["rank"],
        "total_cards": current_team["total_cards"],
        "total_draws": current_team["total_draws"],
        "cards_to_catch_up": cards_to_catch_up,
    }


def save_team_rank_snapshot():
    """保存战队排名快照（每小时整点调用）"""
    rankings = calculate_team_rankings()
    snapshot_date = datetime.utcnow().date()
    snapshot_time = datetime.utcnow()
    
    for team in rankings:
        snapshot = TeamRankSnapshot(
            team_name=team["team_name"],
            rank=team["rank"],
            total_cards=team["total_cards"],
            total_draws=team["total_draws"],
            snapshot_time=snapshot_time,
            snapshot_date=snapshot_date,
        )
        db.session.add(snapshot)
    
    db.session.commit()


def check_team_rank_improvement(team_name):
    """检查战队排名是否提升（对比昨日18点的快照）"""
    if not team_name:
        return None
    
    today = datetime.utcnow().date()
    yesterday = today - timedelta(days=1)
    
    # 获取今日18点的最新排名
    today_18h = datetime.combine(today, time(18, 0, 0))
    today_snapshot = (
        TeamRankSnapshot.query.filter(
            TeamRankSnapshot.team_name == team_name,
            TeamRankSnapshot.snapshot_date == today,
            TeamRankSnapshot.snapshot_time >= today_18h,
        )
        .order_by(TeamRankSnapshot.snapshot_time.desc())
        .first()
    )
    
    # 获取昨日18点的排名
    yesterday_18h = datetime.combine(yesterday, time(18, 0, 0))
    yesterday_snapshot = (
        TeamRankSnapshot.query.filter(
            TeamRankSnapshot.team_name == team_name,
            TeamRankSnapshot.snapshot_date == yesterday,
            TeamRankSnapshot.snapshot_time >= yesterday_18h,
        )
        .order_by(TeamRankSnapshot.snapshot_time.desc())
        .first()
    )
    
    if not today_snapshot or not yesterday_snapshot:
        return None
    
    rank_improvement = yesterday_snapshot.rank - today_snapshot.rank
    if rank_improvement > 0:
        return rank_improvement
    
    return None


def get_device_identifier():
    ip = request.remote_addr or "unknown_ip"
    ua = request.headers.get("User-Agent", "unknown_ua")
    return f"{ip}|{ua}"


def require_admin():
    if not session.get("admin_name"):
        return redirect(url_for("admin_login"))
    return None


def log_admin_action(admin_name: str, action: str):
    log = AdminLog(admin_name=admin_name, action=action)
    db.session.add(log)
    db.session.commit()


def save_and_compress_image(file_storage, dest_folder, prefix, max_kb=100, max_size=(800, 800)):
    """壓縮並儲存圖片，回傳相對於 static 的路徑"""
    os.makedirs(dest_folder, exist_ok=True)
    filename = f"{prefix}_{uuid.uuid4().hex}.jpg"
    abs_path = os.path.join(dest_folder, filename)

    image = Image.open(file_storage)
    image = image.convert("RGB")
    image.thumbnail(max_size, Image.LANCZOS)

    quality = 85
    output = BytesIO()
    while True:
        output.seek(0)
        output.truncate(0)
        image.save(output, format="JPEG", quality=quality, optimize=True)
        size_kb = output.tell() / 1024
        if size_kb <= max_kb or quality <= 35:
            break
        quality -= 5

    with open(abs_path, "wb") as f:
        f.write(output.getvalue())

    rel_path = abs_path.replace(BASE_DIR + os.sep, "")
    rel_path = rel_path.replace("\\", "/")
    return "/" + rel_path


def generate_volcengine_signature(
    access_key,
    secret_key,
    method,
    service,
    region,
    host,
    path,
    query,
    headers,
    payload,
):
    """
    生成火山引擎API签名（HMAC-SHA256）
    参考文档：https://www.volcengine.com/docs/85621/1747301
    """
    method = method.upper()
    x_date = headers.get("X-Date", datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"))
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # 构建canonical headers，只包含需要签名的header
    canonical_headers_map = {}
    
    # 必须包含的header
    host_lower = host.strip().lower()
    canonical_headers_map["host"] = host_lower
    # header 值需要去除首尾空格，多个连续空格压缩为一个
    x_content_sha256 = headers.get("X-Content-Sha256", payload_hash).strip()
    canonical_headers_map["x-content-sha256"] = " ".join(x_content_sha256.split())
    x_date_value = x_date.strip()
    canonical_headers_map["x-date"] = " ".join(x_date_value.split())
    
    # Content-Type 也需要参与签名（如果存在）
    content_type = headers.get("Content-Type", "").strip()
    if content_type:
        canonical_headers_map["content-type"] = " ".join(content_type.split())
    
    # 处理其他需要签名的header（如果有）
    for key, value in headers.items():
        lower_key = key.strip().lower()
        if lower_key not in ("host", "x-content-sha256", "x-date", "content-type"):
            # header 值需要去除首尾空格，多个连续空格压缩为一个
            canonical_headers_map[lower_key] = " ".join(str(value).strip().split())

    # 按key排序
    sorted_headers = sorted(canonical_headers_map.items())
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted_headers)
    signed_headers = ";".join(k for k, _ in sorted_headers)

    # 构建canonical request
    canonical_request = (
        f"{method}\n"
        f"{path}\n"
        f"{query}\n"
        f"{canonical_headers}\n"
        f"{signed_headers}\n"
        f"{payload_hash}"
    )

    # 计算 canonical request 的哈希
    canonical_request_bytes = canonical_request.encode("utf-8")
    hashed_canonical_request = hashlib.sha256(canonical_request_bytes).hexdigest()
    
    # 验证：hashed_canonical_request 不应该等于 payload_hash
    if hashed_canonical_request == payload_hash:
        print(f"[ERROR] hashed_canonical_request == payload_hash! This is wrong!")
        print(f"[ERROR] canonical_request length: {len(canonical_request_bytes)}")
        print(f"[ERROR] canonical_request first 100 chars: {canonical_request[:100]}")
    
    date_stamp = x_date[:8]
    scope = f"{date_stamp}/{region}/{service}/request"
    string_to_sign = f"HMAC-SHA256\n{x_date}\n{scope}\n{hashed_canonical_request}"

    def _sign(key_bytes, msg):
        return hmac.new(key_bytes, msg.encode("utf-8"), hashlib.sha256).digest()

    # 修复：Secret Key 处理 - 火山引擎的 Secret Key 通常是 base64 编码的，需要先解码
    # 如果解码失败，则使用原始字符串（向后兼容）
    try:
        # 尝试 base64 解码
        k_secret = base64.b64decode(secret_key)
        print(f"[DEBUG] Secret Key decoded from base64, length: {len(k_secret)}")
    except Exception as e:
        # 如果解码失败，直接使用原始字符串
        print(f"[DEBUG] Secret Key base64 decode failed: {e}, using raw string")
        k_secret = secret_key.encode("utf-8")
    
    # 计算签名密钥
    k_date = _sign(k_secret, date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "request")
    
    # 计算最终签名
    signature_bytes = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
    signature = signature_bytes.hex()
    
    # 验证：signature 不应该等于 payload_hash 或 hashed_canonical_request
    if signature == payload_hash or signature == hashed_canonical_request:
        print(f"[ERROR] signature matches payload_hash or hashed_canonical_request! This is wrong!")
        print(f"[ERROR] signature: {signature}")
        print(f"[ERROR] payload_hash: {payload_hash}")
        print(f"[ERROR] hashed_canonical_request: {hashed_canonical_request}")

    authorization = (
        f"HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    # 详细调试日志
    print("=" * 60)
    print("[签名调试信息]")
    print(f"Method: {method}")
    print(f"Path: {repr(path)}")
    print(f"Query: {repr(query)}")
    print(f"Host: {host_lower}")
    print(f"X-Date: {x_date}")
    print(f"Payload Hash: {payload_hash}")
    print(f"Canonical Headers:\n{repr(canonical_headers)}")
    print(f"Signed Headers: {signed_headers}")
    print(f"Canonical Request:\n{repr(canonical_request)}")
    print(f"Hashed Canonical Request: {hashed_canonical_request}")
    print(f"Date Stamp: {date_stamp}")
    print(f"Scope: {scope}")
    print(f"String to Sign:\n{repr(string_to_sign)}")
    print(f"Signature: {signature}")
    print(f"Authorization: {authorization}")
    print("=" * 60)

    return authorization, x_date, payload_hash


def _normalize_api_path(path_text):
    if not path_text:
        return "/"
    if not path_text.startswith("/"):
        return f"/{path_text}"
    return path_text


def _build_jimeng_request_components():
    parsed = urlparse(JIMENG_API_URL)
    scheme = parsed.scheme or "https"
    host = parsed.netloc or parsed.path
    if not host:
        raise RuntimeError("JIMENG_API_URL 配置無效，缺少主機名稱")
    base_path = parsed.path if parsed.netloc else ""
    path = _normalize_api_path(JIMENG_API_PATH or base_path or "/")
    return scheme, host, path


def _jimeng_make_request(action, payload_dict):
    if not action:
        raise RuntimeError("缺少即夢API動作(Action)")

    payload_json = json.dumps(payload_dict, ensure_ascii=False)
    scheme, host, path = _build_jimeng_request_components()

    query_items = [("Action", action)]
    if JIMENG_VERSION:
        query_items.append(("Version", JIMENG_VERSION))
    query_string = urlencode(sorted(query_items))

    headers = {
        "Content-Type": "application/json",
    }
    
    authorization, x_date, payload_hash = generate_volcengine_signature(
        JIMENG_ACCESS_KEY,
        JIMENG_SECRET_KEY,
        "POST",
        JIMENG_SERVICE,
        JIMENG_REGION,
        host,
        path,
        query_string,
        headers,
        payload_json,
    )
    
    headers.update(
        {
            "Authorization": authorization,
            "X-Date": x_date,
            "X-Content-Sha256": payload_hash,
            # 注意：不要手动设置 Host header，requests 会自动处理
        }
    )

    if query_string:
        url = f"{scheme}://{host}{path}?{query_string}"
    else:
        url = f"{scheme}://{host}{path}"

    # 调试日志（生产环境可移除）
    print(f"[DEBUG] Request URL: {url}")
    print(f"[DEBUG] Path: {path}")
    print(f"[DEBUG] Query: {query_string}")
    print(f"[DEBUG] Host: {host}")

    response = requests.post(
        url,
        headers=headers,
        data=payload_json.encode("utf-8"),
        timeout=60,
    )

    if response.status_code != 200:
        raise RuntimeError(f"即夢API調用失敗: {response.status_code} - {response.text}")

    body = response.json()
    error_info = body.get("ResponseMetadata", {}).get("Error")
    if error_info:
        raise RuntimeError(
            f"即夢API錯誤: {error_info.get('Code')} - {error_info.get('Message')}"
        )

    return body


def _extract_task_id(response_json):
    candidates = []
    for key in ("TaskId", "task_id", "TaskID"):
        if isinstance(response_json, dict):
            direct_value = response_json.get(key)
            if direct_value:
                candidates.append(direct_value)
            result_value = response_json.get("Result", {}).get(key)
            if result_value:
                candidates.append(result_value)
    if not candidates and isinstance(response_json, dict):
        result_node = response_json.get("Result") or {}
        if isinstance(result_node, dict):
            for value in result_node.values():
                if isinstance(value, str) and value.startswith("task"):
                    candidates.append(value)
    return candidates[0] if candidates else None


def _wait_for_jimeng_task(task_id):
    deadline = pytime.time() + JIMENG_RESULT_TIMEOUT
    last_status = None
    while pytime.time() < deadline:
        result_resp = _jimeng_make_request(JIMENG_RESULT_ACTION, {"TaskId": task_id})
        result_data = result_resp.get("Result") or {}
        status = (
            result_data.get("Status")
            or result_data.get("TaskStatus")
            or result_data.get("status")
            or result_data.get("State")
            or ""
        ).upper()
        if status in {"FINISHED", "SUCCESS", "SUCCEEDED", "SUCCEED", "DONE"}:
            return result_data
        if status in {"FAILED", "ERROR", "CANCELED", "CANCELLED"}:
            reason = (
                result_data.get("FailReason")
                or result_data.get("Message")
                or "未知錯誤"
            )
            raise RuntimeError(f"即夢任務失敗: {reason}")
        last_status = status or "PENDING"
        pytime.sleep(JIMENG_RESULT_POLL_INTERVAL)

    raise TimeoutError(
        f"即夢任務逾時未完成 (TaskId={task_id}, last_status={last_status})"
    )


def _looks_like_image_data(value: str) -> bool:
    if not value:
        return False
    value = value.strip()
    if value.startswith(("http://", "https://", "data:image")):
        return True
    if len(value) < 128:
        return False
    try:
        base64.b64decode(value, validate=True)
        return True
    except Exception:  # pylint: disable=broad-except
        return False


def _extract_image_from_result(result_node):
    queue = [result_node]
    while queue:
        current = queue.pop(0)
        if isinstance(current, dict):
            for value in current.values():
                if isinstance(value, str) and _looks_like_image_data(value):
                    return value
                if isinstance(value, (dict, list)):
                    queue.append(value)
        elif isinstance(current, list):
            for item in current:
                if isinstance(item, str) and _looks_like_image_data(item):
                    return item
                if isinstance(item, (dict, list)):
                    queue.append(item)
    return None


# 网络错误类型（可重试）
RETRYABLE_EXCEPTIONS = (
    Timeout, ConnectionError, ConnectTimeout, ReadTimeout,
    RequestException, SSLError
)


def retry_with_backoff(max_retries=3, base_delay=1, max_delay=8):
    """
    重试装饰器，使用指数退避策略
    max_retries: 最大重试次数（不包括首次尝试）
    base_delay: 基础延迟（秒）
    max_delay: 最大延迟（秒）
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except RETRYABLE_EXCEPTIONS as e:
                    last_exception = e
                    if attempt < max_retries:
                        # 指数退避：1s, 2s, 4s
                        delay = min(base_delay * (2 ** attempt), max_delay)
                        print(f"[RETRY] {func.__name__} 第 {attempt + 1} 次尝试失败（网络错误）: {type(e).__name__}: {str(e)}")
                        print(f"[RETRY] {delay} 秒后重试...")
                        pytime.sleep(delay)
                    else:
                        print(f"[RETRY] {func.__name__} 重试 {max_retries} 次后仍失败")
                        raise RuntimeError(f"网络请求失败（已重试{max_retries}次）: {type(e).__name__}: {str(e)}") from e
                except Exception as e:
                    # 非网络错误，不重试，直接抛出
                    print(f"[ERROR] {func.__name__} 发生非网络错误（不重试）: {type(e).__name__}: {str(e)}")
                    raise
            if last_exception:
                raise last_exception
        return wrapper
    return decorator


def download_image_with_retry(image_url, max_retries=3, timeout=30):
    """
    下载图片，带重试机制
    """
    last_exception = None
    for attempt in range(max_retries + 1):
        try:
            print(f"[DOWNLOAD] 下载图片 (尝试 {attempt + 1}/{max_retries + 1}): {image_url[:50]}...")
            img_response = requests.get(image_url, timeout=timeout)
            if img_response.status_code == 200:
                return img_response.content
            else:
                raise RuntimeError(f"下载图片失败: HTTP {img_response.status_code}")
        except RETRYABLE_EXCEPTIONS as e:
            last_exception = e
            if attempt < max_retries:
                delay = min(1 * (2 ** attempt), 4)  # 1s, 2s, 4s
                print(f"[RETRY] 图片下载失败，{delay} 秒后重试... ({type(e).__name__})")
                pytime.sleep(delay)
            else:
                raise RuntimeError(f"图片下载失败（已重试{max_retries}次）: {type(e).__name__}: {str(e)}") from e
        except Exception as e:
            # 非网络错误，不重试
            raise RuntimeError(f"图片下载失败: {type(e).__name__}: {str(e)}") from e
    
    if last_exception:
        raise last_exception
    raise RuntimeError("图片下载失败：未知错误")


def call_aihubmix_api(original_abs_path, prompt):
    """
    使用 Aihubmix 统一接口调用即梦4.0（推荐，最简单）。
    参考文档：https://docs.aihubmix.com/cn/api/Image-Gen
    """
    if not AIHUBMIX_API_TOKEN:
        raise RuntimeError("AIHUBMIX_API_TOKEN_MISSING: 请在 https://aihubmix.com 获取API Token")
    
    try:
        # 准备图片 - Aihubmix 支持图生图，需要将图片转换为URL或base64
        source_path = os.path.join(BASE_DIR, original_abs_path.lstrip("/"))
        with open(source_path, "rb") as img_file:
            image_base64 = base64.b64encode(img_file.read()).decode("utf-8")
        
        # Aihubmix API地址
        api_url = "https://aihubmix.com/v1/models/doubao/doubao-seedream-4-0-250828/predictions"
        
        # 构建请求
        headers = {
            "Authorization": f"Bearer {AIHUBMIX_API_TOKEN}",
            "Content-Type": "application/json"
        }
        
        # 根据文档，Aihubmix 的即梦4.0接口格式
        # 注意：文档中只显示了文生图，图生图可能需要不同的参数
        # 尝试多种可能的图生图参数格式
        payload = {
            "input": {
                "prompt": prompt,
                "size": "2K",
                "sequential_image_generation": "disabled",
                "stream": False,
                "response_format": "url",
                "watermark": True,
                # 尝试图生图参数（根据其他模型的格式，可能是 image 或 input_image）
                "image": f"data:image/jpeg;base64,{image_base64}",
            }
        }
        
        print(f"[API] 调用 Aihubmix API: {api_url}")
        
        # API调用带重试
        last_exception = None
        response = None
        for attempt in range(4):  # 最多4次尝试（1次初始 + 3次重试）
            try:
                response = requests.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    timeout=60  # 优化超时时间
                )
                if response.status_code == 200:
                    break
                elif response.status_code in [401, 403]:
                    # 认证错误，不重试
                    raise RuntimeError(f"Aihubmix API认证失败: {response.status_code} - {response.text}")
                elif response.status_code >= 500:
                    # 服务器错误，可重试
                    if attempt < 3:
                        delay = min(1 * (2 ** attempt), 4)
                        print(f"[RETRY] Aihubmix API服务器错误 {response.status_code}，{delay} 秒后重试...")
                        pytime.sleep(delay)
                        continue
                    else:
                        raise RuntimeError(f"Aihubmix API服务器错误（已重试3次）: {response.status_code} - {response.text}")
                else:
                    # 其他客户端错误，不重试
                    raise RuntimeError(f"Aihubmix API调用失败: {response.status_code} - {response.text}")
            except RETRYABLE_EXCEPTIONS as e:
                last_exception = e
                if attempt < 3:
                    delay = min(1 * (2 ** attempt), 4)
                    print(f"[RETRY] Aihubmix API网络错误，{delay} 秒后重试... ({type(e).__name__})")
                    pytime.sleep(delay)
                else:
                    raise RuntimeError(f"Aihubmix API网络请求失败（已重试3次）: {type(e).__name__}: {str(e)}") from e
        
        if not response or response.status_code != 200:
            if last_exception:
                raise last_exception
            raise RuntimeError(f"Aihubmix API调用失败: 未知错误")

        result = response.json()
        print(f"[API] Aihubmix API响应成功")
        
        # 解析返回结果 - 根据文档，返回格式为 {"output": [{"url": "..."}]}
        if "output" in result and len(result["output"]) > 0:
            image_url = result["output"][0].get("url")
            if not image_url:
                raise RuntimeError(f"Aihubmix API返回格式异常: 缺少图片URL")
        else:
            raise RuntimeError(f"Aihubmix API返回格式异常: 缺少output字段")
        
        # 下载生成的圖片（带重试）
        print(f"[DOWNLOAD] 开始下载生成的图片...")
        img_content = download_image_with_retry(image_url, max_retries=3, timeout=30)
        
        # 压缩图片到50KB以下
        image = Image.open(BytesIO(img_content))
        image = image.convert("RGB")
        # 限制最大尺寸为1024x1024
        image.thumbnail((1024, 1024), Image.LANCZOS)
        
        os.makedirs(GENERATED_DIR, exist_ok=True)
        filename = f"dream_{uuid.uuid4().hex}.jpg"
        dest_path = os.path.join(GENERATED_DIR, filename)

        quality = 85
        output = BytesIO()
        while True:
            output.seek(0)
            output.truncate(0)
            image.save(output, format="JPEG", quality=quality, optimize=True)
            size_kb = output.tell() / 1024
            if size_kb <= 50 or quality <= 35:
                break
            quality -= 5
        
        with open(dest_path, "wb") as f:
            f.write(output.getvalue())
        
        rel_path = dest_path.replace(BASE_DIR + os.sep, "")
        rel_path = rel_path.replace("\\", "/")
        return "/" + rel_path
        
    except Exception as exc:
        print(f"Aihubmix API调用失败: {exc}")
        import traceback
        traceback.print_exc()
        if JIMENG_ALLOW_FALLBACK:
            print("使用本地 fallback 圖片")
            return fake_generate_dream_image(original_abs_path)
        raise


def call_jimeng_v4_api(original_abs_path, prompt):
    """
    使用即梦4.0 API进行图生图（使用Bearer Token认证，更简单）。
    参考文档：https://www.volcengine.com/docs/85621/1817045
    """
    # 优先使用4.0的Token，如果没有则尝试使用3.0的AK作为Token（某些API可能支持）
    api_token = JIMENG_V4_API_TOKEN
    if not api_token and JIMENG_ACCESS_KEY:
        # 如果4.0 Token未配置，尝试使用3.0的AK（需要根据实际API调整）
        api_token = JIMENG_ACCESS_KEY
        print("[DEBUG] 使用3.0的AK作为4.0的Token（实验性）")
    
    if not api_token:
        raise RuntimeError("JIMENG_V4_API_TOKEN_MISSING: 请配置JIMENG_V4_API_TOKEN或JIMENG_ACCESS_KEY")
    
    if not JIMENG_V4_API_URL:
        raise RuntimeError("JIMENG_V4_API_URL_MISSING: 请在控制台创建推理接入点获取API地址")
    
    try:
        # 准备图片 - 转换为base64
        source_path = os.path.join(BASE_DIR, original_abs_path.lstrip("/"))
        with open(source_path, "rb") as img_file:
            image_base64 = base64.b64encode(img_file.read()).decode("utf-8")
        
        # 构建请求
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        
        # 根据文档，即梦4.0支持图生图
        # 请求体格式可能需要根据实际API文档调整
        payload = {
            "model": JIMENG_V4_MODEL,
            "prompt": prompt,
            "image": f"data:image/jpeg;base64,{image_base64}",  # 图生图需要传入图片
            "size": "1024x1024",
            "n": 1
        }
        
        print(f"[API] 调用即梦4.0 API: {JIMENG_V4_API_URL}")
        
        # API调用带重试
        last_exception = None
        response = None
        for attempt in range(4):  # 最多4次尝试
            try:
                response = requests.post(
                    JIMENG_V4_API_URL,
                    headers=headers,
                    json=payload,
                    timeout=60
                )
                if response.status_code == 200:
                    break
                elif response.status_code in [401, 403]:
                    raise RuntimeError(f"即梦4.0 API认证失败: {response.status_code} - {response.text}")
                elif response.status_code >= 500:
                    if attempt < 3:
                        delay = min(1 * (2 ** attempt), 4)
                        print(f"[RETRY] 即梦4.0 API服务器错误 {response.status_code}，{delay} 秒后重试...")
                        pytime.sleep(delay)
                        continue
                    else:
                        raise RuntimeError(f"即梦4.0 API服务器错误（已重试3次）: {response.status_code} - {response.text}")
                else:
                    raise RuntimeError(f"即梦4.0 API调用失败: {response.status_code} - {response.text}")
            except RETRYABLE_EXCEPTIONS as e:
                last_exception = e
                if attempt < 3:
                    delay = min(1 * (2 ** attempt), 4)
                    print(f"[RETRY] 即梦4.0 API网络错误，{delay} 秒后重试... ({type(e).__name__})")
                    pytime.sleep(delay)
                else:
                    raise RuntimeError(f"即梦4.0 API网络请求失败（已重试3次）: {type(e).__name__}: {str(e)}") from e
        
        if not response or response.status_code != 200:
            if last_exception:
                raise last_exception
            raise RuntimeError(f"即梦4.0 API调用失败: 未知错误")
        
        result = response.json()
        print(f"[API] 即梦4.0 API响应成功")
        
        # 解析返回结果 - 根据实际API响应格式调整
        if "data" in result and len(result["data"]) > 0:
            image_url = result["data"][0].get("url") or result["data"][0].get("b64_json")
        elif "image" in result:
            image_url = result["image"]
        else:
            raise RuntimeError(f"即梦4.0 API返回格式异常: 缺少图片数据")
        
        # 获取图片数据（带重试）
        image_data_bytes = None
        if image_url.startswith(("http://", "https://")):
            print(f"[DOWNLOAD] 开始下载生成的图片...")
            image_data_bytes = download_image_with_retry(image_url, max_retries=3, timeout=30)
        elif image_url.startswith("data:image"):
            # base64 data URL
            if "," in image_url:
                image_data = image_url.split(",")[1]
            else:
                image_data = image_url
            image_data_bytes = base64.b64decode(image_data)
        else:
            # 直接是base64字符串
            image_data_bytes = base64.b64decode(image_url)
        
        # 压缩图片到50KB以下
        image = Image.open(BytesIO(image_data_bytes))
        image = image.convert("RGB")
        # 限制最大尺寸为1024x1024
        image.thumbnail((1024, 1024), Image.LANCZOS)
        
        os.makedirs(GENERATED_DIR, exist_ok=True)
        filename = f"dream_{uuid.uuid4().hex}.jpg"
        dest_path = os.path.join(GENERATED_DIR, filename)

        quality = 85
        output = BytesIO()
        while True:
            output.seek(0)
            output.truncate(0)
            image.save(output, format="JPEG", quality=quality, optimize=True)
            size_kb = output.tell() / 1024
            if size_kb <= 50 or quality <= 35:
                break
            quality -= 5
        
        with open(dest_path, "wb") as f:
            f.write(output.getvalue())
        
        rel_path = dest_path.replace(BASE_DIR + os.sep, "")
        rel_path = rel_path.replace("\\", "/")
        return "/" + rel_path
        
    except Exception as exc:
        print(f"即梦4.0 API调用失败: {exc}")
        import traceback
        traceback.print_exc()
        if JIMENG_ALLOW_FALLBACK:
            print("使用本地 fallback 圖片")
            return fake_generate_dream_image(original_abs_path)
        raise


def call_jimeng_api(original_abs_path, prompt):
    """
    使用火山引擎同步轉異步接口調用即夢圖生圖3.0。
    """
    if not JIMENG_ACCESS_KEY or not JIMENG_SECRET_KEY:
        raise RuntimeError("JIMENG_API_KEY_MISSING")

    try:
        # 準備圖片資料
        source_path = os.path.join(BASE_DIR, original_abs_path.lstrip("/"))
        with open(source_path, "rb") as img_file:
            image_base64 = base64.b64encode(img_file.read()).decode("utf-8")

        submit_payload = {
            "req_key": JIMENG_REQ_KEY,
            "prompt": prompt,
            "scale": JIMENG_DEFAULT_SCALE,
            "image_base64_list": [image_base64],
        }
        submit_resp = _jimeng_make_request(JIMENG_SUBMIT_ACTION, submit_payload)
        task_id = _extract_task_id(submit_resp)
        if not task_id:
            raise RuntimeError(f"即夢提交成功但無法取得TaskId: {submit_resp}")

        print(f"Jimeng task submitted: {task_id}")
        result_data = _wait_for_jimeng_task(task_id)
        image_data = _extract_image_from_result(result_data)
        if not image_data:
            raise RuntimeError(f"即夢任務完成但無法取得圖像資料: {result_data}")

        # 获取图片数据（带重试）
        image_data_bytes = None
        if image_data.startswith(("http://", "https://")):
            print(f"[DOWNLOAD] 开始下载生成的图片...")
            image_data_bytes = download_image_with_retry(image_data, max_retries=3, timeout=30)
        else:
            if "," in image_data:
                image_data_clean = image_data.split(",")[1]
            else:
                image_data_clean = image_data
            image_data_bytes = base64.b64decode(image_data_clean)
        
        # 压缩图片到50KB以下
        image = Image.open(BytesIO(image_data_bytes))
        image = image.convert("RGB")
        # 限制最大尺寸为1024x1024
        image.thumbnail((1024, 1024), Image.LANCZOS)
        
        os.makedirs(GENERATED_DIR, exist_ok=True)
        filename = f"dream_{uuid.uuid4().hex}.jpg"
        dest_path = os.path.join(GENERATED_DIR, filename)
        
        quality = 85
        output = BytesIO()
        while True:
            output.seek(0)
            output.truncate(0)
            image.save(output, format="JPEG", quality=quality, optimize=True)
            size_kb = output.tell() / 1024
            if size_kb <= 50 or quality <= 35:
                break
            quality -= 5
        
        with open(dest_path, "wb") as f:
            f.write(output.getvalue())

        rel_path = dest_path.replace(BASE_DIR + os.sep, "")
        rel_path = rel_path.replace("\\", "/")
        return "/" + rel_path

    except Exception as exc:
        print(f"即夢API調用失敗: {exc}")
        import traceback
        traceback.print_exc()
        if JIMENG_ALLOW_FALLBACK:
            print("使用本地 fallback 圖片")
            return fake_generate_dream_image(original_abs_path)
        raise


def fake_generate_dream_image(original_abs_path):
    """
    模擬 AI 生成結果（當API未配置或調用失敗時使用）。
    """
    os.makedirs(GENERATED_DIR, exist_ok=True)
    filename = f"dream_{uuid.uuid4().hex}.jpg"
    dest_path = os.path.join(GENERATED_DIR, filename)
    source_path = os.path.join(BASE_DIR, original_abs_path.lstrip("/"))
    with Image.open(source_path) as img:
        img = img.convert("RGB")
        img.save(dest_path, format="JPEG", quality=90, optimize=True)
    rel_path = dest_path.replace(BASE_DIR + os.sep, "")
    rel_path = rel_path.replace("\\", "/")
    return "/" + rel_path


def create_thumbnail(source_rel_path, max_kb=120, max_size=(512, 512)):
    os.makedirs(THUMB_DIR, exist_ok=True)
    filename = f"thumb_{uuid.uuid4().hex}.jpg"
    abs_path = os.path.join(THUMB_DIR, filename)

    source_abs = os.path.join(BASE_DIR, source_rel_path.lstrip("/"))
    image = Image.open(source_abs)
    image = image.convert("RGB")
    image.thumbnail(max_size, Image.LANCZOS)

    quality = 85
    output = BytesIO()
    while True:
        output.seek(0)
        output.truncate(0)
        image.save(output, format="JPEG", quality=quality, optimize=True)
        size_kb = output.tell() / 1024
        if size_kb <= max_kb or quality <= 35:
            break
        quality -= 5

    with open(abs_path, "wb") as f:
        f.write(output.getvalue())

    rel_path = abs_path.replace(BASE_DIR + os.sep, "")
    rel_path = rel_path.replace("\\", "/")
    return "/" + rel_path


# --- 使用者登录 / 登出（前台） ---

@app.route("/")
def landing_page():
    """活动入口页"""
    try:
        # 使用更兼容的排序方式
        approved_images = (
            GenerateRecord.query.filter(GenerateRecord.status == "approved")
            .order_by(
                func.coalesce(GenerateRecord.approved_at, GenerateRecord.created_at).desc(),
                GenerateRecord.created_at.desc()
            )
            .limit(10)
            .all()
        )
    except Exception as exc:
        # 如果查询失败（可能是表不存在），返回空列表
        print(f"查询已审核图片失败: {exc}")
        approved_images = []
    
    approved_gallery_data = [
        {
            "id": item.id,
            "thumbnail_url": item.thumbnail_url or "",
            "dream_image_url": item.dream_image_url or "",
            "user_name": item.user_name or "匿名用户",
        }
        for item in approved_images
    ]
    
    # 检查登录状态
    user_id = session.get("user_id")
    is_logged_in = bool(user_id)
    user_name = None
    if is_logged_in:
        user = User.query.get(user_id)
        if user:
            user_name = user.name
    
    # 获取 flash 消息
    flash_messages = get_flashed_messages(with_categories=True)
    
    return render_template(
        "landing.html",
        approved_images=approved_images,
        approved_gallery_data=approved_gallery_data,
        is_logged_in=is_logged_in,
        user_name=user_name,
        flash_messages=flash_messages,
    )


@app.route("/login", methods=["GET", "POST"])
def user_login_page():
    # 已登录且 session 未过期，检查是否有目标页面
    if request.method == "GET" and session.get("user_id"):
        next_page = request.args.get("next")
        if next_page:
            return redirect(next_page)
        return redirect(url_for("landing_page"))

    error = None

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        phone_last4 = (request.form.get("phone_last4") or "").strip()
        team = (request.form.get("team") or "").strip()

        if not name or not phone_last4 or len(phone_last4) != 4 or not phone_last4.isdigit():
            error = "请输入正确的姓名和手机号后四位。"
            return render_template(
                "user_login.html",
                error=error,
                team_choices=TEAM_CHOICES,
                existing_team=None,
            )

        login_name = f"{name}_{phone_last4}"
        device_id = get_device_identifier()
        now = datetime.utcnow()

        user = User.query.filter_by(login_name=login_name).first()

        if user is None:
            # 首次登录：建立用户、绑定设备、发放 1 次抽卡
            if not team or team not in TEAM_CHOICES:
                error = "请选择战队。"
                return render_template(
                    "user_login.html",
                    error=error,
                    team_choices=TEAM_CHOICES,
                    existing_team=None,
                )

            user = User(
                name=name,
                login_name=login_name,
                team=team,
                consumed_draws=0,
                remaining_draws=1,
                first_login_at=now,
                last_login_at=now,
            )
            db.session.add(user)
            db.session.commit()

            dev = Device(user_id=user.user_id, device_identifier=device_id)
            db.session.add(dev)
            db.session.commit()
        else:
            # 非首次登录：检查设备是否已绑定
            # 如果用户已有战队，忽略表单中的战队选择（不可更改）
            user.last_login_at = now
            db.session.commit()

            bound = Device.query.filter_by(
                user_id=user.user_id, device_identifier=device_id
            ).first()

            if bound is None:
                # 新设备：建立 PendingDevice 申请，等待管理员审核
                exists_pending = PendingDevice.query.filter_by(
                    user_id=user.user_id, device_identifier=device_id
                ).first()
                if not exists_pending:
                    pd = PendingDevice(user_id=user.user_id, device_identifier=device_id)
                    db.session.add(pd)
                    db.session.commit()
                error = "已有同名用户在其他设备登录，建议联系运营人员。"
                return render_template(
                    "user_login.html",
                    error=error,
                    team_choices=TEAM_CHOICES,
                    existing_team=user.team,
                )

        # 設定 7 天免登入
        session.permanent = True
        session["user_id"] = user.user_id
        
        # 设置登录成功提示
        flash("登录成功！", "success")
        
        # 检查是否有目标页面
        next_page = request.args.get("next") or request.form.get("next")
        if next_page:
            return redirect(next_page)
        return redirect(url_for("landing_page"))

    # GET 请求：检查是否有已存在的用户（通过 URL 参数或 session 判断）
    # 这里简化处理，直接显示选择框
    return render_template(
        "user_login.html",
        error=error,
        team_choices=TEAM_CHOICES,
        existing_team=None,
    )


@app.route("/logout")
def user_logout():
    session.pop("user_id", None)
    return redirect(url_for("user_login_page"))


# --- 抽卡主页（前台） ---

@app.route("/draw")
def draw_page():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("user_login_page"))

    user = User.query.get(user_id)
    if not user:
        session.pop("user_id", None)
        return redirect(url_for("user_login_page"))

    owned_cards = [uc.card_id for uc in user.cards]
    
    # 获取战队排名信息
    team_info = get_team_rank_info(user.team) if user.team else None
    
    # 检查排名提升（如果是18点后）
    rank_improvement = None
    if user.team:
        current_hour = datetime.utcnow().hour
        if current_hour >= 18:
            rank_improvement = check_team_rank_improvement(user.team)

    return render_template(
        "draw.html",
        name=user.name,
        remaining=user.remaining_draws,
        consumed=user.consumed_draws,
        owned_cards=owned_cards,
        team_info=team_info,
        rank_improvement=rank_improvement,
    )


# --- 抽卡 API（前台） ---

CARD_WEIGHTS = [
    (1, 5),
    (2, 15),
    (3, 20),
    (4, 30),
    (5, 30),
]


def draw_card_by_weight():
    card_ids = [cid for cid, _ in CARD_WEIGHTS]
    weights = [w for _, w in CARD_WEIGHTS]
    return random.choices(card_ids, weights=weights, k=1)[0]


@app.route("/static/cards/<filename>")
def serve_card_image(filename):
    """动态压缩并返回卡片图片，确保小于50KB"""
    card_path = os.path.join(BASE_DIR, "static", "cards", filename)
    if not os.path.exists(card_path):
        return Response("Not Found", status=404)
    
    try:
        # 打开图片
        image = Image.open(card_path)
        image = image.convert("RGB")
        # 限制最大尺寸为800x800
        image.thumbnail((800, 800), Image.LANCZOS)
        
        # 压缩到50KB以下
        quality = 85
        output = BytesIO()
        while True:
            output.seek(0)
            output.truncate(0)
            image.save(output, format="JPEG", quality=quality, optimize=True)
            size_kb = output.tell() / 1024
            if size_kb <= 50 or quality <= 35:
                break
            quality -= 5
        
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype="image/jpeg",
            headers={"Cache-Control": "public, max-age=86400"}
        )
    except Exception as exc:
        print(f"压缩卡片图片失败: {exc}")
        # 如果压缩失败，返回原图
        with open(card_path, "rb") as f:
            return Response(f.read(), mimetype="image/png")


@app.route("/api/draw", methods=["POST"])
def api_draw():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "NOT_LOGIN"}), 401

    user = User.query.get(user_id)
    if not user:
        session.pop("user_id", None)
        return jsonify({"success": False, "error": "USER_NOT_FOUND"}), 404

    if user.remaining_draws <= 0:
        return jsonify({"success": False, "error": "NO_TIMES"}), 400

    user.remaining_draws -= 1
    user.consumed_draws += 1

    card_id = draw_card_by_weight()

    owned_ids_before = {uc.card_id for uc in user.cards}

    is_new_card = False
    bonus_card6 = False

    if card_id not in owned_ids_before:
        is_new_card = True
        new_card = UserCard(user_id=user.user_id, card_id=card_id)
        db.session.add(new_card)

    log = DrawLog(
        user_id=user.user_id,
        card_id=card_id,
        is_bonus_card6=False,
    )
    db.session.add(log)

    owned_ids_after = owned_ids_before.copy()
    owned_ids_after.add(card_id)

    has_all_1_to_5 = all(cid in owned_ids_after for cid in [1, 2, 3, 4, 5])
    already_has_6 = 6 in owned_ids_after

    if has_all_1_to_5 and not already_has_6:
        bonus_card6 = True
        card6 = UserCard(user_id=user.user_id, card_id=6)
        db.session.add(card6)
        owned_ids_after.add(6)
        bonus_log = DrawLog(
            user_id=user.user_id,
            card_id=6,
            is_bonus_card6=True,
        )
        db.session.add(bonus_log)

    db.session.commit()

    owned_cards_sorted = sorted(owned_ids_after)

    return jsonify(
        {
            "success": True,
            "card_id": card_id,
            "is_new_card": is_new_card,
            "bonus_card6": bonus_card6,
            "remaining": user.remaining_draws,
            "consumed": user.consumed_draws,
            "owned_cards": owned_cards_sorted,
        }
    )


@app.route("/api/team-rank", methods=["GET"])
def api_team_rank():
    """获取战队排名信息（用于前端定时刷新）"""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "NOT_LOGIN"}), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "error": "USER_NOT_FOUND"}), 404

    if not user.team:
        return jsonify({"success": False, "error": "NO_TEAM"}), 400

    # 检查是否是整点，如果是则保存快照
    current_time = datetime.utcnow()
    if current_time.minute == 0:
        try:
            save_team_rank_snapshot()
        except Exception:
            pass  # 如果保存失败，继续返回排名信息

    # 获取战队排名信息
    team_info = get_team_rank_info(user.team)
    
    # 检查排名提升（如果是18点后）
    rank_improvement = None
    current_hour = current_time.hour
    if current_hour >= 18:
        rank_improvement = check_team_rank_improvement(user.team)

    if not team_info:
        return jsonify({"success": False, "error": "TEAM_NOT_FOUND"}), 404

    return jsonify(
        {
            "success": True,
            "team_info": team_info,
            "rank_improvement": rank_improvement,
        }
    )


@app.route("/api/generate-quota", methods=["GET"])
def api_generate_quota():
    """获取用户当天的生成次数配额"""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "NOT_LOGIN"}), 401
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "error": "USER_NOT_FOUND"}), 404
    
    # 获取当天UTC时间范围（0:00 - 23:59:59）
    today_utc = datetime.utcnow().date()
    day_start = datetime.combine(today_utc, time(0, 0, 0))
    day_end = datetime.combine(today_utc, time(23, 59, 59))
    
    # 查询当天成功生成的次数（dream_image_url不为空）
    user_name_lower = (user.name or "").strip().lower()
    today_count = (
        db.session.query(func.count(GenerateRecord.id))
        .filter(
            func.lower(GenerateRecord.user_name) == user_name_lower,
            GenerateRecord.dream_image_url.isnot(None),
            GenerateRecord.created_at >= day_start,
            GenerateRecord.created_at <= day_end,
        )
        .scalar() or 0
    )
    
    max_quota = 5
    remaining = max(0, max_quota - today_count)
    
    return jsonify({
        "success": True,
        "today_count": today_count,
        "max_quota": max_quota,
        "remaining": remaining,
    })


@app.route("/api/generate-figure", methods=["POST"])
def api_generate_figure():
    prompt = (request.form.get("prompt") or "").strip()
    image_file = request.files.get("image")

    if not prompt:
        return jsonify({"success": False, "error": "PROMPT_REQUIRED"}), 400
    if not image_file:
        return jsonify({"success": False, "error": "IMAGE_REQUIRED"}), 400
    
    # 检查用户登录状态和生成配额
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "NOT_LOGIN"}), 401
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "error": "USER_NOT_FOUND"}), 404
    
    # 获取当天UTC时间范围
    today_utc = datetime.utcnow().date()
    day_start = datetime.combine(today_utc, time(0, 0, 0))
    day_end = datetime.combine(today_utc, time(23, 59, 59))
    
    # 查询当天成功生成的次数
    user_name_lower = (user.name or "").strip().lower()
    today_count = (
        db.session.query(func.count(GenerateRecord.id))
        .filter(
            func.lower(GenerateRecord.user_name) == user_name_lower,
            GenerateRecord.dream_image_url.isnot(None),
            GenerateRecord.created_at >= day_start,
            GenerateRecord.created_at <= day_end,
        )
        .scalar() or 0
    )
    
    # 检查是否超过配额
    if today_count >= 5:
        return jsonify({
            "success": False,
            "error": "QUOTA_EXCEEDED",
            "message": "您今天的生成额度已用完，明天再来！"
        }), 400

    try:
        original_rel = save_and_compress_image(
            image_file, ORIGINAL_DIR, "origin", max_kb=100, max_size=(768, 768)
        )
    except Exception as exc:  # pylint: disable=broad-except
        return jsonify({
            "success": False,
            "error": "IMAGE_PROCESS_FAIL",
            "message": "参与人过多，免费服务器带宽不足，麻烦重新加载试试"
        }), 500

    # 調用AI生成圖片（根据配置选择：Aihubmix > 即梦4.0 > 即梦3.0）
    try:
        if USE_AIHUBMIX:
            dream_rel = call_aihubmix_api(original_rel, prompt)
        elif USE_JIMENG_V4:
            dream_rel = call_jimeng_v4_api(original_rel, prompt)
        else:
            dream_rel = call_jimeng_api(original_rel, prompt)
    except RuntimeError as e:
        error_msg = str(e)
        error_type = type(e).__name__
        
        # 详细日志记录
        print(f"[ERROR] API调用失败 - 类型: {error_type}, 消息: {error_msg}")
        import traceback
        traceback.print_exc()
        
        # 统一错误提示
        return jsonify({
            "success": False,
            "error": "API_CALL_FAILED",
            "message": "参与人过多，免费服务器带宽不足，麻烦重新加载试试"
        }), 500
    except Exception as exc:
        error_type = type(exc).__name__
        error_msg = str(exc)
        print(f"[ERROR] 未知错误 - 类型: {error_type}, 消息: {error_msg}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            "success": False,
            "error": "UNKNOWN_ERROR",
            "message": "参与人过多，免费服务器带宽不足，麻烦重新加载试试"
        }), 500
    
    try:
        thumbnail_rel = create_thumbnail(dream_rel, max_kb=120, max_size=(480, 480))
    except Exception as exc:
        return jsonify({
            "success": False,
            "error": "THUMBNAIL_FAIL",
            "message": "参与人过多，免费服务器带宽不足，麻烦重新加载试试"
        }), 500

    try:
        # 使用登录用户的真实姓名，而不是表单中的 user_name
        record = GenerateRecord(
            user_name=user.name if user else None,
            prompt=prompt,
            original_image_url=original_rel,
            thumbnail_url=thumbnail_rel,
            dream_image_url=dream_rel,
            status="pending",
        )
        db.session.add(record)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify({
            "success": False,
            "error": "DB_ERROR",
            "message": "参与人过多，免费服务器带宽不足，麻烦重新加载试试"
        }), 500

    return jsonify(
        {
            "success": True,
            "record_id": record.id,
            "thumbnail_url": thumbnail_rel,
            "dream_image_url": dream_rel,
            "status": record.status,
            "message": "圖片已提交，待管理員審核後即可展示。",
        }
    )


@app.route("/api/approved-generates")
def api_approved_generates():
    limit = request.args.get("limit", default=6, type=int)
    if limit <= 0 or limit > 20:
        limit = 6

    records = (
        GenerateRecord.query.filter(GenerateRecord.status == "approved")
        .order_by(func.random())
        .limit(limit)
        .all()
    )

    return jsonify(
        {
            "success": True,
            "items": [
                {
                    "id": r.id,
                    "thumbnail_url": r.thumbnail_url,
                    "prompt": r.prompt,
                    "user_name": r.user_name or "匿名用户",
                    "dream_image_url": r.dream_image_url,
                }
                for r in records
            ],
        }
    )


# --- 管理员登录 / 登出 / 后台 ---

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_name"] = username
            return redirect(url_for("admin_users"))
        else:
            error = "账号或密码错误。"

    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_name", None)
    return redirect(url_for("admin_login"))


@app.route("/admin/user-stats")
def admin_user_stats():
    need_login = require_admin()
    if need_login:
        return need_login

    keyword = (request.args.get("keyword") or "").strip()
    target_date_str = (request.args.get("date") or "").strip()

    target_dt = parse_date_input(target_date_str)
    mode_daily = bool(target_dt)
    if mode_daily:
        base_date = target_dt.date()
        # 确保日期格式为 YYYY-MM-DD
        target_date_str = base_date.strftime("%Y-%m-%d")
        day_end = datetime.combine(base_date, time(18, 0))
        day_start = day_end - timedelta(days=1)
        window_label = f"{day_start.strftime('%Y-%m-%d %H:%M')} 至 {day_end.strftime('%Y-%m-%d %H:%M')}"
    else:
        day_start = None
        day_end = None
        target_date_str = ""
        window_label = "累计数据（含历史全部记录）"

    user_query = User.query
    if keyword:
        user_query = user_query.filter(User.name.contains(keyword))
    users = user_query.order_by(User.user_id.asc()).all()

    user_ids = [u.user_id for u in users]
    card_counts = {}
    if user_ids:
        # 找到每个用户每种卡的首次获得时间
        card_first_sub = (
            db.session.query(
                UserCard.user_id.label("uid"),
                UserCard.card_id.label("cid"),
                func.min(UserCard.obtained_at).label("first_obtained"),
            )
            .group_by(UserCard.user_id, UserCard.card_id)
            .subquery()
        )

        # 统计每个用户在时间段内首次获得的卡的种类数（使用 distinct 确保每种卡只统计一次）
        card_query = (
            db.session.query(
                card_first_sub.c.uid,
                func.count(func.distinct(card_first_sub.c.cid)).label("cnt")
            )
            .filter(card_first_sub.c.uid.in_(user_ids))
        )

        if day_start:
            card_query = card_query.filter(card_first_sub.c.first_obtained >= day_start)
        if day_end:
            card_query = card_query.filter(card_first_sub.c.first_obtained < day_end)

        # 按用户分组统计
        card_query = card_query.group_by(card_first_sub.c.uid)

        for uid, cnt in card_query.all():
            card_counts[uid] = cnt

    generate_stats = {}
    if user_ids:
        gr_query = (
            db.session.query(
                func.lower(GenerateRecord.user_name).label("uname"),
                func.count(GenerateRecord.id).label("upload_count"),
                func.coalesce(
                    func.sum(
                        case(
                            (GenerateRecord.dream_image_url != None, 1),  # noqa: E711
                            else_=0,
                        )
                    ),
                    0,
                ).label("generate_count"),
            )
            .filter(GenerateRecord.user_name.isnot(None))
            .filter(GenerateRecord.user_name != "")
        )
        if day_start:
            gr_query = gr_query.filter(GenerateRecord.created_at >= day_start)
        if day_end:
            gr_query = gr_query.filter(GenerateRecord.created_at < day_end)

        for row in gr_query.group_by(func.lower(GenerateRecord.user_name)).all():
            generate_stats[row.uname] = {
                "upload": row.upload_count,
                "generate": row.generate_count or 0,
            }

    stats_rows = []
    total_cards = total_uploads = total_generates = 0
    for user in users:
        name_key = (user.name or "").strip().lower()
        gen_info = generate_stats.get(name_key, {"upload": 0, "generate": 0})
        card_count = card_counts.get(user.user_id, 0)
        upload_count = gen_info["upload"]
        generate_count = gen_info["generate"]
        total_cards += card_count
        total_uploads += upload_count
        total_generates += generate_count
        stats_rows.append(
            {
                "user": user,
                "card_count": card_count,
                "upload_count": upload_count,
                "generate_count": generate_count,
            }
        )

    return render_template(
        "admin_user_stats.html",
        admin_name=session.get("admin_name"),
        stats_rows=stats_rows,
        total_cards=total_cards,
        total_uploads=total_uploads,
        total_generates=total_generates,
        keyword=keyword,
        target_date=target_date_str,
        mode_daily=mode_daily,
        window_label=window_label,
    )


@app.route("/admin/users")
def admin_users():
    need_login = require_admin()
    if need_login:
        return need_login

    team_filter = request.args.get("team") or ""
    query = User.query

    if team_filter:
        query = query.filter(User.team == team_filter)

    users = query.order_by(User.user_id.asc()).all()

    users_data = []
    for u in users:
        card_ids = sorted([uc.card_id for uc in u.cards])
        card_str = ",".join(str(cid) for cid in card_ids) if card_ids else ""
        users_data.append(
            {
                "user_id": u.user_id,
                "name": u.name,
                "login_name": u.login_name,
                "team": u.team or "",
                "cards": card_str,
                "consumed": u.consumed_draws,
                "remaining": u.remaining_draws,
                "first_login_at": u.first_login_at,
                "last_login_at": u.last_login_at,
                "device_ids": [d.device_identifier for d in u.devices],
            }
        )

    return render_template(
        "admin_users.html",
        admin_name=session.get("admin_name"),
        users=users_data,
        team_filter=team_filter,
        team_choices=TEAM_CHOICES,
    )


@app.route("/admin/export")
def admin_export():
    need_login = require_admin()
    if need_login:
        return need_login

    team_filter = request.args.get("team") or ""
    query = User.query

    if team_filter:
        query = query.filter(User.team == team_filter)

    users = query.order_by(User.user_id.asc()).all()

    output = StringIO()
    writer = csv.writer(output)

    writer.writerow(
        [
            "user_id",
            "name",
            "team",
            "cards",
            "consumed_draws",
            "remaining_draws",
            "devices",
            "first_login_at",
            "last_login_at",
        ]
    )

    for u in users:
        card_ids = sorted([uc.card_id for uc in u.cards])
        card_str = ",".join(str(cid) for cid in card_ids) if card_ids else ""
        device_ids = [d.device_identifier for d in u.devices]
        device_str = "|".join(device_ids) if device_ids else ""

        writer.writerow(
            [
                u.user_id,
                u.name,
                u.team or "",
                card_str,
                u.consumed_draws,
                u.remaining_draws,
                device_str,
                u.first_login_at.isoformat() if u.first_login_at else "",
                u.last_login_at.isoformat() if u.last_login_at else "",
            ]
        )

    csv_data = output.getvalue()
    output.close()

    filename = "users_export.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/admin/devices")
def admin_devices():
    """待审核设备列表"""
    need_login = require_admin()
    if need_login:
        return need_login

    pending = PendingDevice.query.order_by(PendingDevice.created_at.asc()).all()
    rows = []
    for pd in pending:
        u = pd.user
        rows.append(
            {
                "pending_id": pd.id,
                "user_id": u.user_id,
                "name": u.name,
                "login_name": u.login_name,
                "device_identifier": pd.device_identifier,
                "created_at": pd.created_at,
            }
        )

    return render_template(
        "admin_devices.html",
        admin_name=session.get("admin_name"),
        pending_devices=rows,
    )


@app.route("/admin/device/<int:pending_id>/approve", methods=["POST"])
def admin_approve_device(pending_id):
    need_login = require_admin()
    if need_login:
        return need_login

    pd = PendingDevice.query.get_or_404(pending_id)
    # 新增到正式 Device
    exists = Device.query.filter_by(
        user_id=pd.user_id, device_identifier=pd.device_identifier
    ).first()
    if not exists:
        dev = Device(user_id=pd.user_id, device_identifier=pd.device_identifier)
        db.session.add(dev)

    admin_name = session.get("admin_name") or "unknown"
    log_admin_action(
        admin_name,
        f"approve_device user_id={pd.user_id}, device={pd.device_identifier}",
    )

    db.session.delete(pd)
    db.session.commit()
    return redirect(url_for("admin_devices"))


@app.route("/admin/device/<int:pending_id>/reject", methods=["POST"])
def admin_reject_device(pending_id):
    need_login = require_admin()
    if need_login:
        return need_login

    pd = PendingDevice.query.get_or_404(pending_id)
    admin_name = session.get("admin_name") or "unknown"
    log_admin_action(
        admin_name,
        f"reject_device user_id={pd.user_id}, device={pd.device_identifier}",
    )
    db.session.delete(pd)
    db.session.commit()
    return redirect(url_for("admin_devices"))


@app.route("/admin/user/<int:user_id>/edit", methods=["POST"])
def admin_edit_user(user_id):
    need_login = require_admin()
    if need_login:
        return need_login

    user = User.query.get_or_404(user_id)

    new_name = (request.form.get("name") or "").strip()
    new_team = (request.form.get("team") or "").strip()
    remaining_str = (request.form.get("remaining") or "").strip()

    if not new_name:
        new_name = user.name

    try:
        new_remaining = int(remaining_str)
        if new_remaining < 0:
            raise ValueError()
    except ValueError:
        new_remaining = user.remaining_draws

    old_snapshot = f"name={user.name}, team={user.team}, remaining={user.remaining_draws}"

    user.name = new_name
    user.team = new_team if new_team else None
    user.remaining_draws = new_remaining
    db.session.commit()

    new_snapshot = f"name={user.name}, team={user.team}, remaining={user.remaining_draws}"
    admin_name = session.get("admin_name") or "unknown"
    log_admin_action(
        admin_name,
        f"edit_user user_id={user.user_id}, before=({old_snapshot}), after=({new_snapshot})",
    )

    return redirect(url_for("admin_users", team=request.args.get("team") or ""))


@app.route("/admin/user/<int:user_id>/add_draws", methods=["POST"])
def admin_add_draws(user_id):
    need_login = require_admin()
    if need_login:
        return need_login

    user = User.query.get_or_404(user_id)
    delta_str = (request.form.get("add_amount") or "").strip()

    try:
        delta = int(delta_str)
    except ValueError:
        delta = 0

    if delta <= 0 or delta > 100:
        return redirect(url_for("admin_users", team=request.args.get("team") or ""))

    old_remaining = user.remaining_draws
    user.remaining_draws += delta
    db.session.commit()

    admin_name = session.get("admin_name") or "unknown"
    log_admin_action(
        admin_name,
        f"add_draws user_id={user.user_id}, delta={delta}, before_remaining={old_remaining}, after_remaining={user.remaining_draws}",
    )

    return redirect(url_for("admin_users", team=request.args.get("team") or ""))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
def admin_delete_user(user_id):
    """删除用户及其相关资料"""
    need_login = require_admin()
    if need_login:
        return need_login

    user = User.query.get_or_404(user_id)

    # 删关联资料
    Device.query.filter_by(user_id=user.user_id).delete()
    PendingDevice.query.filter_by(user_id=user.user_id).delete()
    UserCard.query.filter_by(user_id=user.user_id).delete()
    DrawLog.query.filter_by(user_id=user.user_id).delete()

    admin_name = session.get("admin_name") or "unknown"
    log_admin_action(
        admin_name,
        f"delete_user user_id={user.user_id}, name={user.name}, login_name={user.login_name}",
    )

    db.session.delete(user)
    db.session.commit()

    return redirect(url_for("admin_users", team=request.args.get("team") or ""))


@app.route("/admin/generates")
def admin_generates():
    need_login = require_admin()
    if need_login:
        return need_login

    status = request.args.get("status") or "pending"
    query = GenerateRecord.query
    if status != "all":
        query = query.filter(GenerateRecord.status == status)

    records = query.order_by(GenerateRecord.created_at.desc()).limit(200).all()

    return render_template(
        "admin_generates.html",
        admin_name=session.get("admin_name"),
        records=records,
        current_status=status,
    )


@app.route("/admin/generate/<int:record_id>/approve", methods=["POST"])
def admin_approve_generate(record_id):
    need_login = require_admin()
    if need_login:
        return need_login

    record = GenerateRecord.query.get_or_404(record_id)
    record.status = "approved"
    record.approved_by = session.get("admin_name")
    record.approved_at = datetime.utcnow()
    db.session.commit()

    log_admin_action(record.approved_by or "unknown", f"approve_generate record_id={record.id}")
    return redirect(url_for("admin_generates", status=request.args.get("status") or "pending"))


@app.route("/admin/generate/<int:record_id>/reject", methods=["POST"])
def admin_reject_generate(record_id):
    need_login = require_admin()
    if need_login:
        return need_login

    record = GenerateRecord.query.get_or_404(record_id)
    record.status = "rejected"
    record.approved_by = session.get("admin_name")
    record.approved_at = datetime.utcnow()
    db.session.commit()

    log_admin_action(record.approved_by or "unknown", f"reject_generate record_id={record.id}")
    return redirect(url_for("admin_generates", status=request.args.get("status") or "pending"))


# 应用启动时自动初始化数据库表（适用于所有启动方式）
with app.app_context():
    try:
        db.create_all()
        print(f"数据库位置: {db_path}")
        print("数据库表已初始化")
    except Exception as exc:
        print(f"数据库初始化警告: {exc}")

if __name__ == "__main__":
    app.run(debug=False)