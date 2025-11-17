from datetime import datetime, timedelta
from io import StringIO
import csv
import os
import random

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

print(">>> app.py 已被執行")

app = Flask(__name__)

# --- 基本設定 ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, "lottery.db")

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "change_this_to_random_string"

# 7 天免登入
app.permanent_session_lifetime = timedelta(days=7)

db = SQLAlchemy(app)

# 管理員帳號
ADMIN_USERNAME = "robot"
ADMIN_PASSWORD = "cs168"

# 固定戰隊列表
TEAM_CHOICES = ["青龍戰隊", "白虎戰隊", "朱雀戰隊", "玄武戰隊", "黃龍戰隊"]


# --- 資料表定義 ---

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
    """等待管理員審核的新設備綁定申請"""
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


# --- 小工具 ---

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


# --- 使用者登入 / 登出（前台） ---

@app.route("/")
def landing_page():
    """活動入口頁"""
    return render_template("landing.html")


@app.route("/login", methods=["GET", "POST"])
def user_login_page():
    # 已登入且 session 未過期，直接進抽卡頁
    if request.method == "GET" and session.get("user_id"):
        return redirect(url_for("draw_page"))

    error = None

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        phone_last4 = (request.form.get("phone_last4") or "").strip()
        team = (request.form.get("team") or "").strip()

        if not name or not phone_last4 or len(phone_last4) != 4 or not phone_last4.isdigit():
            error = "請輸入正確的姓名和手機後四位。"
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
            # 首次登入：建立用戶、綁定設備、發放 1 次抽卡
            if not team or team not in TEAM_CHOICES:
                error = "請選擇戰隊。"
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
            # 非首次登入：檢查設備是否已綁定
            # 如果用戶已有戰隊，忽略表單中的戰隊選擇（不可更改）
            user.last_login_at = now
            db.session.commit()

            bound = Device.query.filter_by(
                user_id=user.user_id, device_identifier=device_id
            ).first()

            if bound is None:
                # 新設備：建立 PendingDevice 申請，等待管理員審核
                exists_pending = PendingDevice.query.filter_by(
                    user_id=user.user_id, device_identifier=device_id
                ).first()
                if not exists_pending:
                    pd = PendingDevice(user_id=user.user_id, device_identifier=device_id)
                    db.session.add(pd)
                    db.session.commit()
                error = "已有同名用戶在其他設備登入，建議聯繫運營人員。"
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

    # GET 請求：檢查是否有已存在的用戶（通過 URL 參數或 session 判斷）
    # 這裡簡化處理，直接顯示選擇框
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


# --- 抽卡主頁（前台） ---

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

    return render_template(
        "draw.html",
        name=user.name,
        remaining=user.remaining_draws,
        consumed=user.consumed_draws,
        owned_cards=owned_cards,
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


# --- 管理員登入 / 登出 / 後台 ---

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
            error = "帳號或密碼錯誤。"

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
    """待審核設備列表"""
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
    """刪除用戶及其相關資料"""
    need_login = require_admin()
    if need_login:
        return need_login

    user = User.query.get_or_404(user_id)

    # 刪關聯資料
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


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print(f"資料庫位置: {db_path}")
    app.run(debug=False)