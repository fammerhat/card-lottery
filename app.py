from datetime import datetime, timedelta, time, date
from io import StringIO, BytesIO
import csv
import os
import random
import uuid
import base64
import requests
import hmac
import hashlib
import json
from urllib.parse import quote

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    Response,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
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
# 根据火山引擎API文档：https://www.volcengine.com/docs/85621/1747301
JIMENG_API_URL = os.getenv("JIMENG_API_URL", "https://visual.volcengineapi.com")
JIMENG_ACCESS_KEY = os.getenv("JIMENG_ACCESS_KEY", "")  # AK - 从环境变量读取
JIMENG_SECRET_KEY = os.getenv("JIMENG_SECRET_KEY", "")  # SK - 从环境变量读取
JIMENG_SERVICE = os.getenv("JIMENG_SERVICE", "cv")  # 服务名
JIMENG_REGION = os.getenv("JIMENG_REGION", "cn-north-1")  # 区域


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


def generate_volcengine_signature(access_key, secret_key, method, service, region, host, path, query, headers, payload):
    """
    生成火山引擎API签名
    参考文档：https://www.volcengine.com/docs/85621/1747301
    """
    # 获取时间戳
    x_date = headers.get("X-Date", datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"))
    x_content_sha256 = headers.get("X-Content-Sha256", hashlib.sha256(payload.encode("utf-8")).hexdigest())
    
    # 构建待签名字符串
    canonical_request = f"{method}\n{path}\n{query}\nhost:{host}\nx-content-sha256:{x_content_sha256}\nx-date:{x_date}\n\nhost;x-content-sha256;x-date\n{x_content_sha256}"
    
    # 计算签名
    date_stamp = x_date[:8]
    k_date = hmac.new((f"HMAC-SHA256\n{date_stamp}").encode("utf-8"), secret_key.encode("utf-8"), hashlib.sha256).digest()
    k_region = hmac.new(region.encode("utf-8"), k_date, hashlib.sha256).digest()
    k_service = hmac.new(service.encode("utf-8"), k_region, hashlib.sha256).digest()
    k_signing = hmac.new("request".encode("utf-8"), k_service, hashlib.sha256).digest()
    signature = hmac.new(canonical_request.encode("utf-8"), k_signing, hashlib.sha256).hexdigest()
    
    # 构建Authorization头
    authorization = f"HMAC-SHA256 Credential={access_key}/{date_stamp}/{region}/{service}/request, SignedHeaders=host;x-content-sha256;x-date, Signature={signature}"
    
    return authorization, x_date, x_content_sha256


def call_jimeng_api(original_abs_path, prompt):
    """
    調用即夢AI API生成圖片（火山引擎格式）。
    只請求一個生成結果以節省用量。
    参考文档：https://www.volcengine.com/docs/85621/1747301
    """
    if not JIMENG_ACCESS_KEY or not JIMENG_SECRET_KEY:
        # 如果沒有配置API密鑰，回退到模擬模式
        return fake_generate_dream_image(original_abs_path)

    try:
        # 讀取原始圖片並轉換為base64
        source_path = os.path.join(BASE_DIR, original_abs_path.lstrip("/"))
        with open(source_path, "rb") as img_file:
            image_base64 = base64.b64encode(img_file.read()).decode("utf-8")

        # 構建請求體（只生成一個結果，n=1）
        # 根據實際API文檔調整字段名和格式
        payload_dict = {
            "req_key": "lens_video_cover",  # 根據實際API文檔調整
            "prompt": prompt,
            "image": image_base64,  # 或使用 "image_url" 如果API支持URL
            "model": "seedream-3.0",  # 根據實際API文檔調整
            "width": 1024,
            "height": 1024,
            "num_images": 1,  # 只生成一張圖片，節省用量
        }
        
        payload_json = json.dumps(payload_dict, ensure_ascii=False)
        
        # 解析API URL
        from urllib.parse import urlparse
        parsed_url = urlparse(JIMENG_API_URL)
        host = parsed_url.netloc
        path = parsed_url.path or "/"
        if not path.endswith("/"):
            path += "/"
        path += "cv/v1/image_generation"  # 根據實際API文檔調整路徑
        
        # 構建請求頭
        headers = {
            "Content-Type": "application/json",
        }
        
        # 生成簽名
        authorization, x_date, x_content_sha256 = generate_volcengine_signature(
            JIMENG_ACCESS_KEY,
            JIMENG_SECRET_KEY,
            "POST",
            JIMENG_SERVICE,
            JIMENG_REGION,
            host,
            path,
            "",  # query string
            headers,
            payload_json
        )
        
        headers.update({
            "Authorization": authorization,
            "X-Date": x_date,
            "X-Content-Sha256": x_content_sha256,
            "Host": host,
        })

        # 發送POST請求
        full_url = f"{JIMENG_API_URL}{path}"
        response = requests.post(
            full_url,
            headers=headers,
            data=payload_json.encode("utf-8"),
            timeout=60,  # 60秒超時
        )

        if response.status_code != 200:
            raise Exception(f"即夢API調用失敗: {response.status_code} - {response.text}")

        result = response.json()

        # 提取生成的圖片URL或base64
        # 根據實際API響應格式調整
        image_data = None
        if "data" in result:
            if isinstance(result["data"], list) and len(result["data"]) > 0:
                image_data = result["data"][0].get("image") or result["data"][0].get("image_url") or result["data"][0].get("url")
            elif isinstance(result["data"], dict):
                image_data = result["data"].get("image") or result["data"].get("image_url") or result["data"].get("url")
        elif "image" in result:
            image_data = result["image"]
        elif "image_url" in result:
            image_data = result["image_url"]
        elif "url" in result:
            image_data = result["url"]

        if not image_data:
            raise Exception(f"無法從API響應中提取圖片: {result}")

        # 保存生成的圖片
        os.makedirs(GENERATED_DIR, exist_ok=True)
        filename = f"dream_{uuid.uuid4().hex}.jpg"
        dest_path = os.path.join(GENERATED_DIR, filename)

        # 如果是base64格式
        if image_data.startswith("data:image") or len(image_data) > 200:
            # 可能是base64
            if "," in image_data:
                image_data = image_data.split(",")[1]
            image_bytes = base64.b64decode(image_data)
            with open(dest_path, "wb") as f:
                f.write(image_bytes)
        else:
            # 如果是URL，下載圖片
            img_response = requests.get(image_data, timeout=30)
            if img_response.status_code != 200:
                raise Exception(f"下載生成圖片失敗: {img_response.status_code}")
            with open(dest_path, "wb") as f:
                f.write(img_response.content)

        rel_path = dest_path.replace(BASE_DIR + os.sep, "")
        rel_path = rel_path.replace("\\", "/")
        return "/" + rel_path

    except Exception as exc:
        # 如果API調用失敗，記錄錯誤並回退到模擬模式
        print(f"即夢API調用失敗，使用模擬模式: {exc}")
        import traceback
        traceback.print_exc()
        return fake_generate_dream_image(original_abs_path)


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
    
    return render_template("landing.html", approved_images=approved_images)


@app.route("/login", methods=["GET", "POST"])
def user_login_page():
    # 已登录且 session 未过期，直接进抽卡页
    if request.method == "GET" and session.get("user_id"):
        return redirect(url_for("draw_page"))

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
        return redirect(url_for("draw_page"))

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


@app.route("/api/generate-figure", methods=["POST"])
def api_generate_figure():
    prompt = (request.form.get("prompt") or "").strip()
    user_name = (request.form.get("user_name") or "").strip()
    image_file = request.files.get("image")

    if not prompt:
        return jsonify({"success": False, "error": "PROMPT_REQUIRED"}), 400
    if not image_file:
        return jsonify({"success": False, "error": "IMAGE_REQUIRED"}), 400

    try:
        original_rel = save_and_compress_image(
            image_file, ORIGINAL_DIR, "origin", max_kb=100, max_size=(768, 768)
        )
    except Exception as exc:  # pylint: disable=broad-except
        return jsonify({"success": False, "error": "IMAGE_PROCESS_FAIL", "detail": str(exc)}), 500

    # 調用即夢AI生成圖片（只生成一個結果，節省用量）
    dream_rel = call_jimeng_api(original_rel, prompt)
    thumbnail_rel = create_thumbnail(dream_rel, max_kb=120, max_size=(480, 480))

    record = GenerateRecord(
        user_name=user_name or None,
        prompt=prompt,
        original_image_url=original_rel,
        thumbnail_url=thumbnail_rel,
        dream_image_url=dream_rel,
        status="pending",
    )
    db.session.add(record)
    db.session.commit()

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