import ast
import importlib.metadata
import io
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import zipfile
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# =====================================================================
# 1. AUTO-INSTALL MINIMAL DEPENDENCIES (Only pyTelegramBotAPI & requests)
# =====================================================================
def _ensure_packages():
    pkgs = [("telebot", "pyTelegramBotAPI"), ("requests", "requests")]
    missing = []
    for mod, pip_name in pkgs:
        try:
            __import__(mod)
        except ImportError:
            missing.append(pip_name)
    try:
        installed = importlib.metadata.version("pyTelegramBotAPI")
        parts = tuple(int(x) for x in installed.split(".")[:3])
        if parts < (4, 37, 1):
            missing.append("pyTelegramBotAPI>=4.37.1")
    except importlib.metadata.PackageNotFoundError:
        if "pyTelegramBotAPI" not in missing:
            missing.append("pyTelegramBotAPI>=4.37.1")
    if missing:
        print(f"[Setup] Installing required packages: {', '.join(missing)}...")
        for flags in [
            ["--no-cache-dir"],
            ["--no-cache-dir", "--break-system-packages"],
            ["--no-cache-dir", "--user"],
        ]:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "-q", *flags, *missing]
                )
                print("[Setup] Installed successfully!")
                return
            except Exception:
                continue
        sys.exit(f"[Error] Please install manually: pip install {' '.join(missing)}")


_ensure_packages()

import telebot
from telebot import types

# =====================================================================
# 2. CONFIGURATION & CONSTANTS
# =====================================================================
BOT_TOKEN = os.environ.get(
    "BOT_TOKEN", "9035313016:AAE4qvnLx7sNSdEzCuD8yTuUPFCXOrZVtvA"
).strip()
OWNER_ID = int(os.environ.get("OWNER_ID", "8574277447"))

BRAND = "REX 𖣘 HOSTING"
BRAND_VER = "v7.8"
SUPPORT_USR = "@rexofficial_owner"
SUPPORT_URL = "https://t.me/rexofficial_owner"
UPDATE_CH = "https://t.me/rexshadmanapi"
FORCE_CHANNELS = [
    {
        "title": "Rex Shadman API",
        "url": "https://t.me/rexshadmanapi",
        "chat": "@rexshadmanapi",
    },
    {
        "title": "Rex Official Profit Army",
        "url": "https://t.me/rexofiicial_profit_army",
        "chat": "@rexofiicial_profit_army",
    },
]
FOOTER = f"\n\n<blockquote><b>{BRAND} {BRAND_VER}</b></blockquote>"

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
SANDBOX_DIR = BASE_DIR / "sandbox"
DB_FILE = STORAGE_DIR / "database.json"

STORAGE_DIR.mkdir(parents=True, exist_ok=True)
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_PLANS = {
    "free": {
        "name": "Free",
        "max_bots": 2,
        "auto_restart": False,
        "price": 0,
        "days": 0,
    },
    "starter": {
        "name": "Starter",
        "max_bots": 4,
        "auto_restart": True,
        "price": 99,
        "days": 30,
    },
    "pro": {
        "name": "Pro",
        "max_bots": 8,
        "auto_restart": True,
        "price": 499,
        "days": 30,
    },
    "lifetime": {
        "name": "Lifetime",
        "max_bots": 15,
        "auto_restart": True,
        "price": 1999,
        "days": 36500,
    },
    "infinity": {
        "name": "♾️ Infinity",
        "max_bots": -1,
        "auto_restart": True,
        "price": 0,
        "days": 0,
    },
}

DEFAULT_PAYMENTS = {
    "bkash": {"name": "bKash", "number": "01818174252", "type": "Send Money"},
    "nagad": {"name": "Nagad", "number": "01818174252", "type": "Send Money"},
    "binance": {"name": "Binance", "number": "Binance Pay ID", "type": "USDT"},
}

SECRET_ENV_KEYS = {"BOT_TOKEN", "OWNER_ID", "MAIN_BOT_TOKEN", "TELEGRAM_BOT_TOKEN"}
MAX_UPLOAD_MB = 20
LOG_MAX_LINES = 80

# =====================================================================
# 3. DATABASE HELPERS
# =====================================================================
_db_lock = threading.RLock()


def _default_db() -> Dict[str, Any]:
    return {
        "users": {},
        "bots": {},
        "payments": [],
        "coupons": {},
        "tickets": {},
        "plans": json.loads(json.dumps(DEFAULT_PLANS)),
        "payment_methods": json.loads(json.dumps(DEFAULT_PAYMENTS)),
        "settings": {
            "maintenance": False,
            "approval_required": False,
            "owner_id": OWNER_ID,
        },
    }


def load_db() -> Dict[str, Any]:
    with _db_lock:
        if not DB_FILE.exists():
            data = _default_db()
            save_db(data)
            return data
        try:
            data = json.loads(DB_FILE.read_text(encoding="utf-8"))
            base = _default_db()
            for k, v in base.items():
                data.setdefault(k, v)
            if not isinstance(data.get("plans"), dict) or not data["plans"]:
                data["plans"] = json.loads(json.dumps(DEFAULT_PLANS))
            if (
                not isinstance(data.get("payment_methods"), dict)
                or not data["payment_methods"]
            ):
                data["payment_methods"] = json.loads(
                    json.dumps(DEFAULT_PAYMENTS)
                )
            data["plans"].setdefault(
                "infinity", json.loads(json.dumps(DEFAULT_PLANS["infinity"]))
            )
            return data
        except Exception:
            return _default_db()


def save_db(data: Dict[str, Any]) -> None:
    with _db_lock:
        tmp = DB_FILE.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        tmp.replace(DB_FILE)


def get_plans(db: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    d = db or load_db()
    return d.get("plans") or DEFAULT_PLANS


def get_payment_methods(
    db: Optional[Dict[str, Any]] = None,
) -> Dict[str, Dict[str, Any]]:
    d = db or load_db()
    return d.get("payment_methods") or DEFAULT_PAYMENTS


# =====================================================================
# 4. SECURITY SCANNER (AST + Regex)
# =====================================================================
_DANGEROUS_PATTERNS = [
    (
        r'os\.walk\s*\(\s*["\'][/\\](?:root|home|etc|var|proc)["\']',
        "System directory scan detected",
    ),
    (r'shutil\.rmtree\s*\(\s*["\'][/\\]', "Root deletion attempt"),
    (r"fork\s*\(\s*\).*fork\s*\(", "Fork bomb detected"),
    (r"devil-api\.com|elementfx\.io", "Known malicious domain"),
]


def scan_python_code(code: str) -> Tuple[str, List[str]]:
    threats = []
    for pat, desc in _DANGEROUS_PATTERNS:
        if re.search(pat, code, re.IGNORECASE):
            threats.append(desc)
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if (
                    node.func.id in ("eval", "exec")
                    and node.args
                    and isinstance(node.args[0], ast.Call)
                ):
                    threats.append(f"Dynamic {node.func.id}() execution")
                elif node.func.id == "import" and node.args:
                    if (
                        isinstance(node.args[0], ast.Constant)
                        and node.args[0].value == "os"
                    ):
                        threats.append("Dynamic import('os')")
    except SyntaxError as e:
        threats.append(f"SyntaxError: {e}")

    if len(threats) >= 2:
        return "DANGEROUS", threats
    elif len(threats) == 1:
        return "SUSPICIOUS", threats
    return "SAFE", []


# =====================================================================
# 5. SANDBOX BOT RUNNER & PROCESS MANAGER (Persistent Logs)
# =====================================================================
RUNNING_BOTS: Dict[str, Dict[str, Any]] = {}
LAST_LOGS: Dict[str, deque] = {}
_proc_lock = threading.Lock()


def detect_entry_file(bot_dir: Path) -> Tuple[Optional[str], Optional[str]]:
    for py_name in ("bot.py", "main.py", "app.py", "run.py"):
        if (bot_dir / py_name).exists():
            return "python", py_name
    for js_name in ("index.js", "bot.js", "main.js"):
        if (bot_dir / js_name).exists():
            return "node", js_name
    py_files = list(bot_dir.rglob("*.py"))
    if py_files:
        return "python", str(py_files[0].relative_to(bot_dir))
    js_files = list(bot_dir.rglob("*.js"))
    if js_files:
        return "node", str(js_files[0].relative_to(bot_dir))
    return None, None


def _auto_install_bot_deps(bot_dir: Path, kind: str, logs: deque):
    if kind == "python":
        req = bot_dir / "requirements.txt"
        if req.exists():
            logs.append("[System] Installing requirements.txt...")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--no-cache-dir",
                    "--break-system-packages",
                    "-r",
                    str(req),
                ],
                cwd=str(bot_dir),
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                logs.append("[System] requirements install failed:")
                logs.append(
                    (result.stderr or result.stdout or "Unknown pip error")[-1500:]
                )
    elif (
        kind == "node"
        and (bot_dir / "package.json").exists()
        and not (bot_dir / "node_modules").exists()
    ):
        logs.append("[System] Running npm install...")
        subprocess.run(
            ["npm", "install", "--omit=dev"], cwd=str(bot_dir), capture_output=True
        )


def _log_reader(bot_id: str, proc: subprocess.Popen, logs: deque):
    try:
        for raw_line in iter(proc.stdout.readline, b""):
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            logs.append(line)
    except Exception:
        pass
    rc = proc.wait()
    logs.append(f"[System] Process exited with code {rc}")
    LAST_LOGS[bot_id] = logs

    with _proc_lock:
        info = RUNNING_BOTS.get(bot_id)
        manual = info.get("manual_stop", False) if info else True
        RUNNING_BOTS.pop(bot_id, None)

    db = load_db()
    plans = get_plans(db)
    b = db["bots"].get(bot_id)
    if b:
        b["status"] = "stopped" if manual else "crashed"
        b["last_exit"] = rc
        save_db(db)
        if not manual and rc != 0:
            owner = db["users"].get(str(b["owner"]), {})
            plan = owner.get("plan", "free")
            if plans.get(plan, {}).get("auto_restart"):
                time.sleep(3)
                start_bot_process(bot_id)


def start_bot_process(bot_id: str) -> Tuple[bool, str]:
    db = load_db()
    b = db["bots"].get(bot_id)
    if not b:
        return False, "Bot not found (Container may have restarted, upload again)."
    if b.get("approval") == "pending":
        return False, "Waiting for admin approval."

    with _proc_lock:
        if bot_id in RUNNING_BOTS and RUNNING_BOTS[bot_id]["proc"].poll() is None:
            return False, "Bot is already running."

    bot_dir = Path(b["dir"])
    if not bot_dir.exists():
        return False, "Bot directory missing on disk. Please re-upload your file."

    kind, entry = detect_entry_file(bot_dir)
    if not kind or not entry:
        return False, "No valid entry file (bot.py / main.py / index.js) found."

    logs = deque(maxlen=LOG_MAX_LINES)
    LAST_LOGS[bot_id] = logs
    logs.append(f"[System] Starting {entry} ({kind})...")

    try:
        _auto_install_bot_deps(bot_dir, kind, logs)
    except Exception as e:
        logs.append(f"[Error] Dependency install error: {e}")
        return False, f"Dependency installation failed: {e}"

    env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV_KEYS}
    env["PYTHONUNBUFFERED"] = "1"
    for k, v in b.get("env", {}).items():
        if k not in SECRET_ENV_KEYS:
            env[k] = str(v)

    cmd = [sys.executable, "-u", entry] if kind == "python" else ["node", entry]
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(bot_dir),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid if os.name == "posix" else None,
        )
    except Exception as e:
        logs.append(f"[Error] Launch failed: {e}")
        return False, f"Failed to launch: {e}"

    with _proc_lock:
        RUNNING_BOTS[bot_id] = {
            "proc": proc,
            "logs": logs,
            "started": time.time(),
            "manual_stop": False,
        }

    b["status"] = "running"
    save_db(db)
    threading.Thread(
        target=_log_reader, args=(bot_id, proc, logs), daemon=True
    ).start()

    # Wait 1.2s to verify the child bot didn't immediately crash on startup
    time.sleep(1.2)
    if proc.poll() is not None:
        err_tail = "\n".join(list(logs)[-6:])
        return False, f"Bot crashed immediately!\n{err_tail}"

    return True, f"Started & Running (PID: {proc.pid})"


def stop_bot_process(bot_id: str) -> Tuple[bool, str]:
    with _proc_lock:
        info = RUNNING_BOTS.get(bot_id)
    if not info:
        db = load_db()
        if bot_id in db["bots"]:
            db["bots"][bot_id]["status"] = "stopped"
            save_db(db)
        return True, "Bot stopped."

    info["manual_stop"] = True
    proc = info["proc"]
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except Exception:
            pass

    with _proc_lock:
        RUNNING_BOTS.pop(bot_id, None)

    db = load_db()
    if bot_id in db["bots"]:
        db["bots"][bot_id]["status"] = "stopped"
        save_db(db)
    return True, "Bot stopped successfully."


# =====================================================================
# 6. TELEGRAM BOT INITIALIZATION & UI HELPERS
# =====================================================================
if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE" or not BOT_TOKEN:
    sys.exit("[Error] Please set your BOT_TOKEN in the script or environment variable!")

bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML", threaded=True)
USER_STATES: Dict[int, Dict[str, Any]] = {}


def esc(text: Any) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def fmt_uptime(sec: float) -> str:
    s = int(sec)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{h}h {m}m {s}s" if h else f"{m}m {s}s"


def get_owner_id() -> int:
    db = load_db()
    return int(db["settings"].get("owner_id") or OWNER_ID)


def is_admin(uid: int) -> bool:
    return uid == get_owner_id()


def get_user(
    tg_user: types.User, ref_id: Optional[int] = None
) -> Tuple[Dict[str, Any], bool]:
    db = load_db()
    uid_str = str(tg_user.id)
    is_new = uid_str not in db["users"]
    if is_new:
        db["users"][uid_str] = {
            "id": tg_user.id,
            "name": tg_user.first_name or "User",
            "username": tg_user.username or "",
            "plan": "free",
            "plan_expires": None,
            "wallet": 0,
            "banned": False,
            "ref_count": 0,
            "bonus_slots": 0,
            "joined": now_iso(),
        }
        if ref_id and ref_id != tg_user.id and str(ref_id) in db["users"]:
            db["users"][str(ref_id)]["ref_count"] += 1
            db["users"][str(ref_id)]["bonus_slots"] += 1
            db["users"][str(ref_id)]["wallet"] += 1
            try:
                bot.send_message(
                    ref_id,
                    f"🎉 <b>Referral Bonus!</b>\n@{tg_user.username or tg_user.first_name} joined using your link.\nReward: <b>+1 Bot Slot & +1৳</b>",
                )
            except Exception:
                pass
        if tg_user.id == get_owner_id():
            db["users"][uid_str]["plan"] = "infinity"
            db["users"][uid_str]["plan_expires"] = None
        save_db(db)
    else:
        db["users"][uid_str]["name"] = tg_user.first_name or db["users"][
            uid_str
        ].get("name", "User")
        db["users"][uid_str]["username"] = tg_user.username or db["users"][
            uid_str
        ].get("username", "")
        if tg_user.id == get_owner_id():
            db["users"][uid_str]["plan"] = "infinity"
            db["users"][uid_str]["plan_expires"] = None
        save_db(db)
    return db["users"][uid_str], is_new


def user_max_bots(
    user: Dict[str, Any], plans: Optional[Dict[str, Any]] = None
) -> int:
    p_map = plans or get_plans()
    if int(user.get("id", 0) or 0) == get_owner_id():
        return 10**9
    plan_key = user.get("plan", "free")
    base = p_map.get(plan_key, p_map.get("free", {"max_bots": 2})).get(
        "max_bots", 2
    )
    if int(base) < 0:
        return 10**9
    return int(base) + int(user.get("bonus_slots", 0))


def plan_limit_label(
    user: Dict[str, Any], plans: Optional[Dict[str, Any]] = None
) -> str:
    if int(user.get("id", 0) or 0) == get_owner_id():
        return "∞ Unlimited"
    p_map = plans or get_plans()
    plan_key = user.get("plan", "free")
    base = p_map.get(plan_key, p_map.get("free", {"max_bots": 2})).get(
        "max_bots", 2
    )
    return (
        "∞ Unlimited"
        if int(base) < 0
        else str(int(base) + int(user.get("bonus_slots", 0)))
    )


def check_force_join(uid: int) -> Tuple[bool, List[Dict[str, str]]]:
    if is_admin(uid):
        return True, []
    missing = []
    for ch in FORCE_CHANNELS:
        try:
            member = bot.get_chat_member(ch["chat"], uid)
            status = getattr(member, "status", "")
            if (
                status in ("left", "kicked", "restricted")
                and getattr(member, "is_member", True) is False
            ):
                missing.append(ch)
            elif status in ("left", "kicked"):
                missing.append(ch)
        except Exception:
            missing.append(ch)
    return (len(missing) == 0), missing


def send_force_join_prompt(chat_id: int):
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
    kb.add(types.KeyboardButton("✅ Verify Join"))
    ch_lines = "\n".join(
        f"• {esc(c['title'])}: {c['url']}" for c in FORCE_CHANNELS
    )
    txt = (
        f"🔒 <b>Channel Join Required</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"বটটি ব্যবহার করতে নিচের চ্যানেলগুলোতে জয়েন করুন:\n\n"
        f"{ch_lines}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"জয়েন করার পর নিচের <b>✅ Verify Join</b> বাটনে চাপ দিন।{FOOTER}"
    )
    bot.send_message(chat_id, txt, reply_markup=kb, disable_web_page_preview=True)


# =====================================================================
# 7. KEYBOARD BUILDERS
# =====================================================================
def kb_main_menu(uid: int) -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        types.KeyboardButton("🤖 My Bots", style="primary"),
        types.KeyboardButton("📤 Upload Bot", style="success"),
    )
    kb.add(
        types.KeyboardButton("💎 Plans", style="primary"),
        types.KeyboardButton("💳 Buy Plan", style="success"),
    )
    kb.add(
        types.KeyboardButton("👤 Profile", style="primary"),
        types.KeyboardButton("💰 Wallet", style="success"),
    )
    kb.add(
        types.KeyboardButton("🎟 Coupon", style="primary"),
        types.KeyboardButton("🔗 Referral", style="success"),
    )
    kb.add(
        types.KeyboardButton("🎫 Tickets", style="primary"),
        types.KeyboardButton("ℹ️ Help", style="primary"),
    )
    kb.add(types.KeyboardButton("🆘 Support", style="success"))
    if is_admin(uid):
        kb.add(types.KeyboardButton("🛡️ Admin Panel", style="primary"))
    return kb


def kb_cancel_menu() -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        types.KeyboardButton("⬅️ Back", style="primary"),
        types.KeyboardButton("❌ Cancel", style="danger"),
    )
    return kb


def kb_bots_menu(uid: int) -> types.ReplyKeyboardMarkup:
    db = load_db()
    my_bots = [b for b in db["bots"].values() if b["owner"] == uid]
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    for b in my_bots:
        is_run = (
            b["id"] in RUNNING_BOTS
            and RUNNING_BOTS[b["id"]]["proc"].poll() is None
        )
        icon = "🟢" if is_run else "🔴"
        kb.add(types.KeyboardButton(f"{icon} {b['name']} [{b['id']}]"))
    kb.add(types.KeyboardButton("📤 Upload Bot"))
    kb.add(types.KeyboardButton("❌ Cancel"))
    return kb


def kb_single_bot_menu(bid: str, is_run: bool) -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    if is_run:
        kb.add(
            types.KeyboardButton(f"⏹ Stop [{bid}]"),
            types.KeyboardButton(f"🔄 Restart [{bid}]"),
        )
    else:
        kb.add(types.KeyboardButton(f"▶️ Start [{bid}]"))
    kb.add(
        types.KeyboardButton(f"📜 Logs [{bid}]"),
        types.KeyboardButton(f"⚙️ Env [{bid}]"),
    )
    kb.add(
        types.KeyboardButton(f"📦 Pip [{bid}]"),
        types.KeyboardButton(f"🗑 Delete [{bid}]"),
    )
    kb.add(types.KeyboardButton("❌ Cancel"))
    return kb


def kb_plans_menu(plans: Dict[str, Dict[str, Any]]) -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    for k, p in plans.items():
        if k != "infinity" and int(p.get("price", 0)) > 0:
            kb.add(
                types.KeyboardButton(f"💎 Buy {p['name']} ({p['price']}৳) [{k}]")
            )
    kb.add(types.KeyboardButton("❌ Cancel"))
    return kb


def kb_payment_methods_menu(
    plan_key: str, pay_methods: Dict[str, Dict[str, Any]]
) -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    for mk, mv in pay_methods.items():
        kb.add(types.KeyboardButton(f"💳 Pay {mv['name']} [{mk}|{plan_key}]"))
    kb.add(types.KeyboardButton("❌ Cancel"))
    return kb


def kb_support_inline() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(
        types.InlineKeyboardButton("🚀 Contact Owner", url=SUPPORT_URL),
        types.InlineKeyboardButton("📢 Update Channel", url=UPDATE_CH),
    )
    return kb


def kb_admin_menu(maint: bool, appr: bool) -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        types.KeyboardButton("📊 Statistics", style="primary"),
        types.KeyboardButton("💎 Edit Plans", style="success"),
    )
    kb.add(
        types.KeyboardButton("💳 Wallet Methods", style="success"),
        types.KeyboardButton(
            f"🔧 Maint: {'ON' if maint else 'OFF'}", style="primary"
        ),
    )
    kb.add(
        types.KeyboardButton(
            f"🛡 Approval: {'ON' if appr else 'OFF'}", style="primary"
        ),
        types.KeyboardButton("📢 Broadcast", style="success"),
    )
    kb.add(
        types.KeyboardButton("🎁 Give Plan", style="success"),
        types.KeyboardButton("🚫 Ban/Unban", style="danger"),
    )
    kb.add(
        types.KeyboardButton("🎟 Create Coupon", style="success"),
        types.KeyboardButton("🤖 All Bots", style="primary"),
    )
    kb.add(types.KeyboardButton("⏹ Stop All Bots"))
    kb.add(types.KeyboardButton("❌ Cancel"))
    return kb


def kb_admin_wallet_list(
    pay_methods: Dict[str, Dict[str, Any]],
) -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    for mk, mv in pay_methods.items():
        kb.add(types.KeyboardButton(f"💳 {mv['name']} [{mk}]"))
    kb.add(types.KeyboardButton("➕ Add Wallet Method"))
    kb.add(types.KeyboardButton("🛡️ Admin Panel"))
    kb.add(types.KeyboardButton("❌ Cancel"))
    return kb


def kb_admin_single_wallet(mk: str) -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        types.KeyboardButton(f"✏️ Edit Wallet [{mk}]"),
        types.KeyboardButton(f"🗑 Remove Wallet [{mk}]"),
    )
    kb.add(types.KeyboardButton("💳 Wallet Methods"))
    kb.add(types.KeyboardButton("❌ Cancel"))
    return kb


def kb_admin_plans_list(
    plans: Dict[str, Dict[str, Any]],
) -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    for k, p in plans.items():
        if k != "infinity":
            kb.add(types.KeyboardButton(f"💎 {p['name']} [{k}]"))
    kb.add(types.KeyboardButton("➕ Add Plan"))
    kb.add(types.KeyboardButton("🛡️ Admin Panel"))
    kb.add(types.KeyboardButton("❌ Cancel"))
    return kb


def kb_admin_single_plan(k: str) -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(types.KeyboardButton(f"✏️ Edit Plan [{k}]"))
    if k != "free":
        kb.add(types.KeyboardButton(f"🗑 Remove Plan [{k}]"))
    kb.add(types.KeyboardButton("💎 Edit Plans"))
    kb.add(types.KeyboardButton("❌ Cancel"))
    return kb


def kb_admin_users_manage(db: Dict[str, Any]) -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    for uid_str, u in list(db["users"].items())[:20]:
        tag = "🚫" if u.get("banned") else "✅"
        name_short = (u.get("name") or "User")[:14]
        kb.add(types.KeyboardButton(f"{tag} {name_short} [{uid_str}]"))
    kb.add(types.KeyboardButton("❌ Cancel"))
    return kb


def kb_admin_files_list(db: Dict[str, Any]) -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    for bid, b in list(db["bots"].items())[:24]:
        st_icon = "🟢" if b.get("status") == "running" else "📄"
        kb.add(types.KeyboardButton(f"{st_icon} {b['name']} [{bid}]"))
    kb.add(types.KeyboardButton("❌ Cancel"))
    return kb


def kb_admin_single_file(bid: str) -> types.ReplyKeyboardMarkup:
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        types.KeyboardButton(f"🔍 Inspect [{bid}]"),
        types.KeyboardButton(f"🗑 Delete [{bid}]"),
    )
    kb.add(types.KeyboardButton("🤖 All Bots"))
    kb.add(types.KeyboardButton("❌ Cancel"))
    return kb


def send_box(
    chat_id: int,
    text: str,
    reply_kb: types.ReplyKeyboardMarkup,
    inline_kb: Optional[types.InlineKeyboardMarkup] = None,
):
    bot.send_message(
        chat_id,
        f"<blockquote><b>{text}</b></blockquote>",
        reply_markup=inline_kb if inline_kb else reply_kb,
        disable_web_page_preview=True,
    )
    if inline_kb:
        bot.send_message(
            chat_id,
            "👇 নিচের কিবোর্ড মেনু ব্যবহার করুন:",
            reply_markup=reply_kb,
        )


# =====================================================================
# 8. START, VERIFY & CANCEL HANDLERS
# =====================================================================
def send_welcome_main(chat_id: int, uid: int):
    USER_STATES.pop(uid, None)
    db = load_db()
    plans = get_plans(db)
    u = db["users"].get(str(uid), {})
    if uid == get_owner_id():
        u["plan"] = "infinity"
        u["plan_expires"] = None
        db["users"][str(uid)] = u
        save_db(db)
    my_bots = [b for b in db["bots"].values() if b["owner"] == uid]
    running_cnt = sum(
        1
        for b in my_bots
        if b["id"] in RUNNING_BOTS
        and RUNNING_BOTS[b["id"]]["proc"].poll() is None
    )
    plan_info = plans.get(
        "infinity" if uid == get_owner_id() else u.get("plan", "free"),
        plans.get("free", DEFAULT_PLANS["free"]),
    )
    txt = (
        f"✨ {esc(BRAND)} {BRAND_VER}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"👋 Welcome, {esc(u.get('name', 'User'))}\n"
        f"💎 Plan: {esc(plan_info['name'])}\n"
        f"🤖 Bots: {len(my_bots)} / {plan_limit_label(u, plans)} (Running: {running_cnt})\n"
        f"💰 Wallet: {u.get('wallet', 0)}৳\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"Choose an option from keyboard menu:{FOOTER}"
    )
    bot.send_message(
        chat_id,
        f"<blockquote><b>{txt}</b></blockquote>",
        reply_markup=kb_main_menu(uid),
        disable_web_page_preview=True,
    )


@bot.message_handler(commands=["start"])
def handle_start(m: types.Message):
    if m.chat.type != "private":
        return
    uid = m.from_user.id
    db = load_db()

    if get_owner_id() == 0:
        db["settings"]["owner_id"] = uid
        save_db(db)

    ref = None
    parts = (m.text or "").split(maxsplit=1)
    if len(parts) == 2 and parts[1].isdigit():
        ref = int(parts[1])

    user, _ = get_user(m.from_user, ref)
    if user.get("banned"):
        bot.reply_to(
            m, f"🚫 <b>You are banned from using this bot.</b>\nContact {SUPPORT_USR}"
        )
        return

    if db["settings"].get("maintenance") and not is_admin(uid):
        bot.reply_to(
            m, "🔧 <b>Panel is under maintenance.</b> Please check back later."
        )
        return

    joined, _ = check_force_join(uid)
    if not joined:
        send_force_join_prompt(m.chat.id)
        return

    send_welcome_main(m.chat.id, uid)


@bot.message_handler(func=lambda m: (m.text or "").strip() == "✅ Verify Join")
def handle_verify_join(m: types.Message):
    if m.chat.type != "private":
        return
    uid = m.from_user.id
    joined, _ = check_force_join(uid)
    if not joined:
        bot.reply_to(
            m,
            "❌ আপনি এখনো দুটি চ্যানেলে জয়েন করেননি। জয়েন করে আবার <b>✅ Verify Join</b> চাপুন।",
        )
        send_force_join_prompt(m.chat.id)
        return
    bot.send_message(m.chat.id, "✅ <b>Verification successful!</b>")
    send_welcome_main(m.chat.id, uid)


@bot.message_handler(commands=["cancel"])
@bot.message_handler(func=lambda m: (m.text or "").strip() == "❌ Cancel")
def handle_cancel(m: types.Message):
    if m.chat.type != "private":
        return
    send_welcome_main(m.chat.id, m.from_user.id)


# =====================================================================
# 9. ADMIN INSPECTORS & CALLBACK HANDLERS
# =====================================================================
def _show_wallet_methods_panel(chat_id: int, db: Dict[str, Any]):
    pay_methods = get_payment_methods(db)
    lines = []
    for mk, mv in pay_methods.items():
        lines.append(
            f"• <b>{esc(mv['name'])}</b> (<code>{esc(mk)}</code>): <code>{esc(mv['number'])}</code> — {esc(mv['type'])}"
        )
    txt = (
        f"💳 <b>Wallet / Payment Methods</b>\n━━━━━━━━━━━━━━━━━━━━\n"
        + ("\n".join(lines) or "কোনো মেথড নেই।")
        + f"\n━━━━━━━━━━━━━━━━━━━━\n"
        f"নিচের বাটন থেকে কোনো মেথডে চাপলে নম্বর বদলাতে বা ডিলিট করতে পারবেন, অথবা <b>➕ Add Wallet Method</b> চাপুন:{FOOTER}"
    )
    send_box(chat_id, txt, kb_admin_wallet_list(pay_methods))


def _show_plans_panel(chat_id: int, db: Dict[str, Any]):
    plans = get_plans(db)
    lines = []
    for k, p in plans.items():
        price_txt = "Free" if int(p.get("price", 0)) == 0 else f"{p['price']}৳"
        days_txt = (
            "Unlimited" if int(p.get("days", 0)) == 0 else f"{p['days']} দিন"
        )
        bots_txt = (
            "Unlimited"
            if int(p.get("max_bots", 0)) < 0
            else f"{p['max_bots']} Bots"
        )
        lines.append(
            f"• <b>{esc(p['name'])}</b> (<code>{esc(k)}</code>): {bots_txt} | {price_txt} | {days_txt}"
        )
    txt = (
        f"💎 <b>Plans Manager</b>\n━━━━━━━━━━━━━━━━━━━━\n"
        + ("\n".join(lines) or "কোনো প্ল্যান নেই।")
        + f"\n━━━━━━━━━━━━━━━━━━━━\n"
        f"নিচের বাটন থেকে কোনো প্ল্যানে চাপলে দাম/দিন/বট বদলাতে বা ডিলিট করতে পারবেন, অথবা <b>➕ Add Plan</b> চাপুন:{FOOTER}"
    )
    send_box(chat_id, txt, kb_admin_plans_list(plans))


def _inspect_bot_file(chat_id: int, bid: str):
    db = load_db()
    b = db["bots"].get(bid)
    if not b:
        bot.send_message(chat_id, "❌ Bot/File not found.")
        return

    bot_dir = Path(b.get("dir", ""))
    if not bot_dir.exists():
        bot.send_message(chat_id, "❌ Directory not found on disk.")
        return

    target_files = sorted(
        [
            p
            for p in bot_dir.rglob("*")
            if p.is_file() and "node_modules" not in p.parts
        ]
    )
    if not target_files:
        bot.send_message(chat_id, "📂 Folder is empty.")
        return

    main_file = target_files[0]
    for pref in ("bot.py", "main.py", "app.py", "run.py", "index.js"):
        cand = bot_dir / pref
        if cand.exists():
            main_file = cand
            break

    file_list_txt = "\n".join(
        f"• <code>{esc(p.relative_to(bot_dir))}</code> ({p.stat().st_size} B)"
        for p in target_files[:15]
    )

    try:
        raw_text = main_file.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        bot.send_message(chat_id, f"❌ Could not read file: {esc(e)}")
        return

    header = (
        f"🔍 <b>File Inspector</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"• Bot ID: <code>{bid}</code>\n"
        f"• Owner ID: <code>{b['owner']}</code>\n"
        f"• Status: {b.get('status', 'stopped')}\n"
        f"• Entry File: <code>{esc(main_file.name)}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"<b>Files in package:</b>\n{file_list_txt}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
    )

    if len(raw_text) <= 3200:
        bot.send_message(
            chat_id,
            f"{header}<pre>{esc(raw_text)}</pre>{FOOTER}",
            reply_markup=kb_admin_single_file(bid),
            disable_web_page_preview=True,
        )
    else:
        preview = raw_text[:2500]
        bot.send_message(
            chat_id,
            f"{header}<b>Preview (first 2500 chars):</b>\n<pre>{esc(preview)}</pre>\n\n📎 Full file attached below:{FOOTER}",
            reply_markup=kb_admin_single_file(bid),
            disable_web_page_preview=True,
        )
        bio = io.BytesIO(raw_text.encode("utf-8"))
        bio.name = f"{b['owner']}_{main_file.name}"
        bot.send_document(chat_id, bio)


def _show_bot_view(chat_id: int, uid: int, bid: str):
    db = load_db()
    b = db["bots"].get(bid)
    if not b or (b["owner"] != uid and not is_admin(uid)):
        send_box(
            chat_id,
            "❌ এই বটটি বর্তমানে ডাটাবেসে নেই (সার্ভার রিস্টার্ট হয়ে থাকলে আবার আপলোড করুন)।\nনিচ থেকে আপনার বর্তমান বটগুলো দেখুন:",
            kb_bots_menu(uid),
        )
        return

    info = RUNNING_BOTS.get(bid)
    is_run = bool(info and info["proc"].poll() is None)
    uptime = fmt_uptime(time.time() - info["started"]) if is_run else "0s"
    status_txt = (
        f"🟢 Running (PID: {info['proc'].pid})"
        if is_run
        else f"🔴 {b.get('status', 'Stopped').title()}"
    )

    txt = (
        f"🤖 Bot: {esc(b['name'])}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"• Status: {status_txt}\n"
        f"• Uptime: {uptime}\n"
        f"• ID: <code>{bid}</code>\n"
        f"• Env Vars: {len(b.get('env', {}))} set\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"Tap ❌ Cancel to return to main menu.{FOOTER}"
    )
    send_box(chat_id, txt, kb_single_bot_menu(bid, is_run))


def _show_statistics(chat_id: int, uid: int):
    db = load_db()
    users_list = list(db["users"].values())
    run_cnt = sum(1 for x in RUNNING_BOTS.values() if x["proc"].poll() is None)
    banned_cnt = sum(1 for u in users_list if u.get("banned"))

    lines = []
    for u in users_list[:25]:
        u_id = u.get("id")
        u_name = esc(u.get("name") or "User")
        u_handle = (
            f"@{esc(u['username'])}" if u.get("username") else "No username"
        )
        u_state = "🚫 Banned" if u.get("banned") else "🟢 Active"
        lines.append(
            f"• <code>{u_id}</code> | {u_name} ({u_handle}) — {u_state}"
        )

    txt = (
        f"📊 <b>Bot Statistics & Users</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"• Total Users: <b>{len(users_list)}</b>\n"
        f"• Banned Users: <b>{banned_cnt}</b>\n"
        f"• Total Bots: <b>{len(db['bots'])}</b>\n"
        f"• Running Bots: <b>{run_cnt}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"{chr(10).join(lines) or 'No users yet.'}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"নিচের বাটন থেকে যেকোনো ইউজার সিলেক্ট করে Ban / Unban করুন:{FOOTER}"
    )
    send_box(chat_id, txt, kb_admin_users_manage(db))


@bot.callback_query_handler(func=lambda c: True)
def handle_inline_callbacks(call: types.CallbackQuery):
    uid = call.from_user.id
    data = call.data or ""
    db = load_db()
    plans = get_plans(db)

    try:
        bot.answer_callback_query(call.id)
    except Exception:
        pass

    if not is_admin(uid):
        return

    if data.startswith("kyc_ok_") or data.startswith("pay_ok_"):
        pid = data.split("_", 2)[2]
        for p in db["payments"]:
            if p["id"] == pid and p["status"] == "pending":
                p["status"] = "approved"
                target_uid = str(p["uid"])
                plan_key = p["plan"]
                pl_info = plans.get(plan_key, DEFAULT_PLANS["starter"])
                days = int(pl_info.get("days", 30))
                if target_uid in db["users"]:
                    db["users"][target_uid]["plan"] = plan_key
                    db["users"][target_uid]["plan_expires"] = (
                        None
                        if days <= 0
                        else (
                            datetime.now(timezone.utc) + timedelta(days=days)
                        ).isoformat()
                    )
                save_db(db)
                if call.message:
                    try:
                        bot.edit_message_reply_markup(
                            call.message.chat.id,
                            call.message.message_id,
                            reply_markup=None,
                        )
                    except Exception:
                        pass
                bot.send_message(
                    call.message.chat.id if call.message else uid,
                    f"✅ Approved <code>{esc(pid)}</code> for user <code>{esc(target_uid)}</code> (Plan: <b>{esc(pl_info['name'])}</b>).",
                )
                try:
                    bot.send_message(
                        int(target_uid),
                        f"🎉 <b>Approved!</b>\nআপনার <b>{esc(pl_info['name'])}</b> প্ল্যান সক্রিয় হয়েছে ({days} দিন)। এখন অ্যাপ্রুভাল ছাড়াই বট হোস্ট করতে পারবেন!",
                    )
                except Exception:
                    pass
                return

    elif data.startswith("kyc_no_") or data.startswith("pay_no_"):
        pid = data.split("_", 2)[2]
        for p in db["payments"]:
            if p["id"] == pid and p["status"] == "pending":
                p["status"] = "rejected"
                target_uid = p["uid"]
                save_db(db)
                if call.message:
                    try:
                        bot.edit_message_reply_markup(
                            call.message.chat.id,
                            call.message.message_id,
                            reply_markup=None,
                        )
                    except Exception:
                        pass
                bot.send_message(
                    call.message.chat.id if call.message else uid,
                    f"❌ Rejected <code>{esc(pid)}</code>.",
                )
                try:
                    bot.send_message(
                        int(target_uid),
                        "❌ আপনার ই-কেওয়াইসি / পেমেন্ট প্রুফ রিজেক্ট করা হয়েছে।",
                    )
                except Exception:
                    pass
                return

    elif data.startswith("bot_ok_"):
        bid = data.split("_", 2)[2]
        if bid in db["bots"]:
            db["bots"][bid]["approval"] = "approved"
            save_db(db)
            if call.message:
                try:
                    bot.edit_message_reply_markup(
                        call.message.chat.id,
                        call.message.message_id,
                        reply_markup=None,
                    )
                except Exception:
                    pass
            ok, msg = start_bot_process(bid)
            bot.send_message(
                call.message.chat.id if call.message else uid,
                f"✅ Bot <code>{esc(bid)}</code> approved! {esc(msg)}",
            )
            try:
                bot.send_message(
                    db["bots"][bid]["owner"],
                    f"✅ আপনার <b>{esc(db['bots'][bid]['name'])}</b> বটটি অ্যাডমিন অ্যাপ্রুভ করেছেন এবং চালু হয়েছে!",
                )
            except Exception:
                pass


# =====================================================================
# 10. KEYBOARD MENU BUTTON ROUTER
# =====================================================================
@bot.message_handler(
    content_types=["text"],
    func=lambda m: m.chat.type == "private"
    and (m.text or "").strip() not in ("❌ Cancel", "✅ Verify Join")
    and not (m.text or "").strip().startswith("/"),
)
def handle_menu_text(m: types.Message):
    uid = m.from_user.id
    chat_id = m.chat.id
    text = (m.text or "").strip()
    db = load_db()
    plans = get_plans(db)
    pay_methods = get_payment_methods(db)
    u = db["users"].get(str(uid))
    if not u:
        u, _ = get_user(m.from_user)

    if u.get("banned"):
        bot.reply_to(
            m, f"🚫 <b>You are banned from using this bot.</b>\nContact {SUPPORT_USR}"
        )
        return

    if db["settings"].get("maintenance") and not is_admin(uid):
        bot.reply_to(m, "🔧 <b>Panel is under maintenance.</b>")
        return

    joined, _ = check_force_join(uid)
    if not joined:
        send_force_join_prompt(chat_id)
        return

    if text == "⬅️ Back":
        previous_state = USER_STATES.pop(uid, None) or {}
        previous_flow = previous_state.get("flow", "")
        if previous_flow in (
            "add_wallet_num",
            "edit_wallet_num",
            "add_wallet_name",
        ):
            _show_wallet_methods_panel(chat_id, load_db())
        elif previous_flow in (
            "add_plan_price",
            "add_plan_days",
            "add_plan_bots",
            "add_plan_name",
            "edit_plan_price",
            "edit_plan_days",
            "edit_plan_bots",
        ):
            _show_plans_panel(chat_id, load_db())
        elif previous_flow in ("await_env", "await_pip"):
            _show_bot_view(chat_id, uid, previous_state.get("bot_id", ""))
        elif previous_flow in (
            "adm_broadcast",
            "adm_giveplan",
            "adm_ban",
            "adm_mkcoupon",
        ):
            db_back = load_db()
            send_box(
                chat_id,
                "🛡️ Admin Panel",
                kb_admin_menu(
                    db_back["settings"].get("maintenance", False),
                    db_back["settings"].get("approval_required", False),
                ),
            )
        else:
            send_welcome_main(chat_id, uid)
        return

    st = USER_STATES.get(uid)
    if st:
        handle_state_input(m, st)
        return

    my_bots = [b for b in db["bots"].values() if b["owner"] == uid]
    max_b = user_max_bots(u, plans)

    if text == "🤖 My Bots":
        txt = (
            f"🤖 Your Bots ({len(my_bots)} / {plan_limit_label(u, plans)})\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"Select a bot from keyboard below or tap ❌ Cancel:{FOOTER}"
        )
        send_box(chat_id, txt, kb_bots_menu(uid))

    elif text == "📤 Upload Bot":
        if len(my_bots) >= max_b:
            send_box(
                chat_id,
                f"⚠️ Bot slot limit reached ({len(my_bots)}/{plan_limit_label(u, plans)}).\nUpgrade your plan or tap ❌ Cancel.",
                kb_cancel_menu(),
            )
            return
        USER_STATES[uid] = {"flow": "await_bot_file"}
        txt = (
            f"📤 <b>Supported Formats Chart</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🐍 <b>Python File</b> (<code>.py</code>)\n"
            f"   └ এন্ট্রি: <code>bot.py</code>, <code>main.py</code>, <code>app.py</code>, <code>run.py</code>\n"
            f"📦 <b>ZIP Archive</b> (<code>.zip</code>)\n"
            f"   └ মাল্টি-ফাইল প্রজেক্ট + <code>requirements.txt</code> অটো-ইনস্টল\n"
            f"🟢 <b>Node.js File</b> (<code>.js</code>)\n"
            f"   └ এন্ট্রি: <code>index.js</code>, <code>bot.js</code>, <code>main.js</code>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"এখন আপনার ফাইলটি চ্যাটে সেন্ড করুন (বা ❌ Cancel চাপুন):{FOOTER}"
        )
        send_box(chat_id, txt, kb_cancel_menu())

    elif text in ("💎 Plans", "💳 Buy Plan"):
        lines = []
        for k, p in plans.items():
            if k == "infinity":
                continue
            price = "Free" if int(p.get("price", 0)) == 0 else f"{p['price']}৳"
            dur = (
                "Unlimited"
                if int(p.get("days", 0)) == 0
                else f"{p['days']} Days"
            )
            lines.append(
                f"• <b>{esc(p['name'])}</b>: {p['max_bots']} Bots | {dur} | Auto-Restart: {'Yes' if p.get('auto_restart') else 'No'} | <b>{price}</b>"
            )
        txt = (
            f"💎 Hosting Plans\n━━━━━━━━━━━━━━━━━━━━\n"
            + "\n".join(lines)
            + f"\n━━━━━━━━━━━━━━━━━━━━\nSelect a plan to buy or tap ❌ Cancel:{FOOTER}"
        )
        send_box(chat_id, txt, kb_plans_menu(plans))

    elif text.startswith("💎 Buy ") and "[" in text and text.endswith("]"):
        plan_key = text.rsplit("[", 1)[1][:-1].strip()
        p = plans.get(plan_key)
        if p:
            txt = (
                f"💳 Checkout: <b>{esc(p['name'])}</b> ({p['price']}৳ / {p['days']}d)\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"Choose payment method from keyboard or tap ❌ Cancel:{FOOTER}"
            )
            send_box(
                chat_id, txt, kb_payment_methods_menu(plan_key, pay_methods)
            )

    elif text.startswith("💳 Pay ") and "[" in text and text.endswith("]"):
        inside = text.rsplit("[", 1)[1][:-1].strip()
        if "|" in inside:
            mk, plan_key = inside.split("|", 1)
            pm = pay_methods.get(mk.strip())
            pl = plans.get(plan_key.strip())
            if pm and pl:
                USER_STATES[uid] = {
                    "flow": "await_pay_proof",
                    "method": pm["name"],
                    "plan": plan_key.strip(),
                    "amount": pl["price"],
                }
                txt = (
                    f"💳 Pay via <b>{esc(pm['name'])}</b>\n━━━━━━━━━━━━━━━━━━━━\n"
                    f"• Number/ID: <code>{esc(pm['number'])}</code>\n"
                    f"• Type: {esc(pm['type'])}\n"
                    f"• Amount: <b>{pl['price']}৳</b>\n"
                    f"━━━━━━━━━━━━━━━━━━━━\n"
                    f"Send your Transaction ID / eKYC details or Screenshot now (or ❌ Cancel):{FOOTER}"
                )
                send_box(chat_id, txt, kb_cancel_menu())

    elif text == "👤 Profile":
        p_name = plans.get(
            "infinity" if uid == get_owner_id() else u.get("plan", "free"),
            DEFAULT_PLANS["free"],
        )["name"]
        txt = (
            f"👤 User Profile\n━━━━━━━━━━━━━━━━━━━━\n"
            f"• Name: {esc(u['name'])}\n"
            f"• ID: <code>{uid}</code>\n"
            f"• Plan: {esc(p_name)}\n"
            f"• Bot Limit: {plan_limit_label(u, plans)}\n"
            f"• Wallet: {u['wallet']}৳\n"
            f"• Referrals: {u['ref_count']} (+{u['bonus_slots']} slots)\n"
            f"• Joined: {u['joined'][:10]}{FOOTER}"
        )
        send_box(chat_id, txt, kb_cancel_menu())

    elif text == "💰 Wallet":
        txt = (
            f"💰 Your Wallet\n━━━━━━━━━━━━━━━━━━━━\n"
            f"Current Balance: <b>{u['wallet']}৳</b>\n"
            f"Earn wallet credit by referring friends!\n"
            f"Tap ❌ Cancel to go back.{FOOTER}"
        )
        send_box(chat_id, txt, kb_cancel_menu())

    elif text == "🎟 Coupon":
        USER_STATES[uid] = {"flow": "await_coupon"}
        send_box(
            chat_id,
            f"🎟 Send your coupon code now (or tap ❌ Cancel):{FOOTER}",
            kb_cancel_menu(),
        )

    elif text == "🔗 Referral":
        me = bot.get_me()
        link = f"https://t.me/{me.username}?start={uid}"
        txt = (
            f"🔗 Referral Program\n━━━━━━━━━━━━━━━━━━━━\n"
            f"Invite friends and get <b>+1 Bot Slot & +1৳</b> per referral!\n\n"
            f"Your Link:\n<code>{link}</code>\n\n"
            f"Total Referrals: {u['ref_count']}{FOOTER}"
        )
        send_box(chat_id, txt, kb_cancel_menu())

    elif text == "🎫 Tickets":
        USER_STATES[uid] = {"flow": "await_ticket"}
        send_box(
            chat_id,
            f"🎫 Support Ticket\nDescribe your issue in one message (or tap ❌ Cancel):{FOOTER}",
            kb_cancel_menu(),
        )

    elif text == "ℹ️ Help":
        txt = (
            f"ℹ️ Quick Guide\n━━━━━━━━━━━━━━━━━━━━\n"
            f"1. Tap 📤 Upload Bot and send a .py, .zip, or .js file.\n"
            f"2. Go to 🤖 My Bots -> Select Bot -> Start.\n"
            f"3. Set API keys in Env if needed.\n"
            f"4. View real-time errors in Logs.{FOOTER}"
        )
        send_box(chat_id, txt, kb_cancel_menu())

    elif text == "🆘 Support":
        bot.send_message(
            chat_id,
            f"<blockquote><b>🆘 Support\n━━━━━━━━━━━━━━━━━━━━\nOwner: {SUPPORT_USR}\nUpdates: {UPDATE_CH}{FOOTER}</b></blockquote>",
            reply_markup=kb_support_inline(),
            disable_web_page_preview=True,
        )
        send_box(
            chat_id,
            "নিচের বাটন থেকে সরাসরি কানেক্ট করুন অথবা ❌ Cancel চাপুন:",
            kb_cancel_menu(),
        )

    # Admin Wallet Button Menu Actions
    elif text == "💳 Wallet Methods" and is_admin(uid):
        _show_wallet_methods_panel(chat_id, db)

    elif text == "➕ Add Wallet Method" and is_admin(uid):
        USER_STATES[uid] = {"flow": "add_wallet_name"}
        send_box(
            chat_id,
            f"➕ নতুন ওয়ালেট মেথডের নাম লিখুন (যেমন: <code>Rocket</code> বা <code>Upay</code>)\nঅথবা ❌ Cancel চাপুন:{FOOTER}",
            kb_cancel_menu(),
        )

    elif text.startswith("💳 ") and text.endswith("]") and is_admin(uid):
        mk = text.rsplit("[", 1)[1][:-1].strip()
        mv = pay_methods.get(mk)
        if mv:
            txt = (
                f"💳 <b>{esc(mv['name'])}</b> (<code>{esc(mk)}</code>)\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"• Number/ID: <code>{esc(mv['number'])}</code>\n"
                f"• Type: {esc(mv['type'])}\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"নিচের বাটন থেকে এডিট বা রিমুভ করুন:{FOOTER}"
            )
            send_box(chat_id, txt, kb_admin_single_wallet(mk))

    elif (
        text.startswith("✏️ Edit Wallet [")
        and text.endswith("]")
        and is_admin(uid)
    ):
        mk = text[16:-1].strip()
        if mk in pay_methods:
            USER_STATES[uid] = {"flow": "edit_wallet_num", "mk": mk}
            send_box(
                chat_id,
                f"✏️ <b>{esc(pay_methods[mk]['name'])}</b> এর নতুন নম্বর বা আইডি লিখুন (বা ❌ Cancel চাপুন):{FOOTER}",
                kb_cancel_menu(),
            )

    elif (
        text.startswith("🗑 Remove Wallet [")
        and text.endswith("]")
        and is_admin(uid)
    ):
        mk = text[18:-1].strip()
        if mk in db["payment_methods"]:
            removed = db["payment_methods"].pop(mk)
            save_db(db)
            bot.send_message(
                chat_id,
                f"🗑 <b>{esc(removed.get('name', mk))}</b> মেথড বাদ দেওয়া হয়েছে।",
            )
        _show_wallet_methods_panel(chat_id, load_db())

    # Admin Plans Button Menu Actions
    elif text == "💎 Edit Plans" and is_admin(uid):
        _show_plans_panel(chat_id, db)

    elif text == "➕ Add Plan" and is_admin(uid):
        USER_STATES[uid] = {"flow": "add_plan_name"}
        send_box(
            chat_id,
            f"➕ নতুন প্ল্যানের নাম লিখুন (যেমন: <code>Starter</code> বা <code>Gold Pack</code>)\nঅথবা ❌ Cancel চাপুন:{FOOTER}",
            kb_cancel_menu(),
        )

    elif text.startswith("💎 ") and text.endswith("]") and is_admin(uid):
        k = text.rsplit("[", 1)[1][:-1].strip()
        p = plans.get(k)
        if p:
            price_txt = "Free" if int(p.get("price", 0)) == 0 else f"{p['price']}৳"
            days_txt = (
                "Unlimited" if int(p.get("days", 0)) == 0 else f"{p['days']} দিন"
            )
            bots_txt = (
                "Unlimited" if int(p.get("max_bots", 0)) < 0 else str(p["max_bots"])
            )
            txt = (
                f"💎 <b>{esc(p['name'])}</b> (<code>{esc(k)}</code>)\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"• Bots Limit: <b>{bots_txt}</b>\n"
                f"• Price: <b>{price_txt}</b>\n"
                f"• Duration: <b>{days_txt}</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"নিচের বাটন থেকে এডিট বা ডিলিট করুন:{FOOTER}"
            )
            send_box(chat_id, txt, kb_admin_single_plan(k))

    elif (
        text.startswith("✏️ Edit Plan [")
        and text.endswith("]")
        and is_admin(uid)
    ):
        k = text[14:-1].strip()
        if k in plans and k != "infinity":
            USER_STATES[uid] = {"flow": "edit_plan_price", "pkey": k}
            send_box(
                chat_id,
                f"✏️ <b>{esc(plans[k]['name'])}</b> প্ল্যানের নতুন <b>টাকার পরিমাণ</b> লিখুন (শুধু সংখ্যা, যেমন: <code>150</code>)\nঅথবা ❌ Cancel চাপুন:{FOOTER}",
                kb_cancel_menu(),
            )

    elif (
        text.startswith("🗑 Remove Plan [")
        and text.endswith("]")
        and is_admin(uid)
    ):
        k = text[16:-1].strip()
        if k in db["plans"] and k not in ("free", "infinity"):
            removed = db["plans"].pop(k)
            save_db(db)
            bot.send_message(
                chat_id,
                f"🗑 <b>{esc(removed.get('name', k))}</b> প্ল্যান বাদ দেওয়া হয়েছে।",
            )
        _show_plans_panel(chat_id, load_db())

    # Admin File Inspect / Delete actions
    elif text.startswith("🔍 Inspect [") and text.endswith("]") and is_admin(uid):
        bid = text[11:-1].strip()
        _inspect_bot_file(chat_id, bid)

    elif text.startswith("📄 ") and text.endswith("]") and is_admin(uid):
        bid = text.rsplit("[", 1)[1][:-1].strip()
        _inspect_bot_file(chat_id, bid)

    elif (text.startswith("🟢 ") or text.startswith("🔴 ")) and text.endswith(
        "]"
    ):
        bid = text.rsplit("[", 1)[1][:-1].strip()
        b_item = db["bots"].get(bid)
        if is_admin(uid) and b_item and b_item.get("owner") != uid:
            _inspect_bot_file(chat_id, bid)
        else:
            _show_bot_view(chat_id, uid, bid)

    elif text.startswith("▶️ Start [") and text.endswith("]"):
        bid = text[9:-1].strip()
        ok, msg = start_bot_process(bid)
        bot.send_message(chat_id, f"{'✅' if ok else '❌'} {esc(msg)}")
        _show_bot_view(chat_id, uid, bid)

    elif text.startswith("⏹ Stop [") and text.endswith("]"):
        bid = text[8:-1].strip()
        ok, msg = stop_bot_process(bid)
        bot.send_message(chat_id, f"⏹ {esc(msg)}")
        _show_bot_view(chat_id, uid, bid)

    elif text.startswith("🔄 Restart [") and text.endswith("]"):
        bid = text[11:-1].strip()
        stop_bot_process(bid)
        time.sleep(1)
        ok, msg = start_bot_process(bid)
        bot.send_message(chat_id, f"🔄 {esc(msg)}")
        _show_bot_view(chat_id, uid, bid)

    elif text.startswith("📜 Logs [") and text.endswith("]"):
        bid = text[8:-1].strip()
        info = RUNNING_BOTS.get(bid)
        saved_q = info["logs"] if info else LAST_LOGS.get(bid)
        lines = (
            list(saved_q)[-35:]
            if saved_q
            else ["(No logs recorded yet — tap Start first)"]
        )
        log_str = esc("\n".join(lines))[-3000:]
        send_box(
            chat_id,
            f"📜 Live / Last Logs:\n<pre>{log_str}</pre>{FOOTER}",
            kb_single_bot_menu(
                bid, bool(info and info["proc"].poll() is None)
            ),
        )

    elif text.startswith("⚙️ Env [") and text.endswith("]"):
        bid = text[7:-1].strip()
        b = db["bots"].get(bid)
        if b:
            USER_STATES[uid] = {"flow": "await_env", "bot_id": bid}
            envs = (
                "\n".join(
                    f"• <code>{esc(k)}</code> = <code>{esc(v)}</code>"
                    for k, v in b.get("env", {}).items()
                )
                or "None"
            )
            txt = (
                f"⚙️ Environment Variables\n━━━━━━━━━━━━━━━━━━━━\n"
                f"{envs}\n━━━━━━━━━━━━━━━━━━━━\n"
                f"Send <code>KEY=VALUE</code> to add/update, or <code>DEL KEY</code> to remove (or ❌ Cancel):{FOOTER}"
            )
            send_box(chat_id, txt, kb_cancel_menu())

    elif text.startswith("📦 Pip [") and text.endswith("]"):
        bid = text[7:-1].strip()
        USER_STATES[uid] = {"flow": "await_pip", "bot_id": bid}
        send_box(
            chat_id,
            f"📦 Send package name(s) to install (e.g. <code>requests bs4</code>) or ❌ Cancel:{FOOTER}",
            kb_cancel_menu(),
        )

    elif text.startswith("🗑 Delete [") and text.endswith("]"):
        bid = text[10:-1].strip()
        stop_bot_process(bid)
        LAST_LOGS.pop(bid, None)
        b = db["bots"].pop(bid, None)
        if b:
            shutil.rmtree(b["dir"], ignore_errors=True)
            save_db(db)
        bot.send_message(chat_id, "🗑 Bot deleted permanently.")
        if is_admin(uid):
            send_box(
                chat_id, "🤖 Updated All Bots List:", kb_admin_files_list(db)
            )
        else:
            send_box(chat_id, "🤖 Updated Bot List:", kb_bots_menu(uid))

    # Admin Menu & Statistics
    elif text == "🛡️ Admin Panel" and is_admin(uid):
        USER_STATES.pop(uid, None)
        run_cnt = sum(
            1 for x in RUNNING_BOTS.values() if x["proc"].poll() is None
        )
        maint = db["settings"].get("maintenance", False)
        appr = db["settings"].get("approval_required", False)
        txt = (
            f"🛡️ Admin Control Panel\n━━━━━━━━━━━━━━━━━━━━\n"
            f"• Total Users: {len(db['users'])}\n"
            f"• Total Bots: {len(db['bots'])}\n"
            f"• Running Bots: {run_cnt}\n"
            f"• Pending Proofs: {sum(1 for p in db['payments'] if p['status'] == 'pending')}{FOOTER}"
        )
        send_box(chat_id, txt, kb_admin_menu(maint, appr))

    elif text == "📊 Statistics" and is_admin(uid):
        _show_statistics(chat_id, uid)

    elif (
        (text.startswith("✅ ") or text.startswith("🚫 "))
        and text.endswith("]")
        and is_admin(uid)
    ):
        target_uid_str = text.rsplit("[", 1)[1][:-1].strip()
        if target_uid_str in db["users"]:
            now_banned = not bool(db["users"][target_uid_str].get("banned"))
            db["users"][target_uid_str]["banned"] = now_banned
            save_db(db)
            bot.send_message(
                chat_id,
                f"{'🚫 Banned' if now_banned else '✅ Unbanned'} user <code>{esc(target_uid_str)}</code>.",
            )
            _show_statistics(chat_id, uid)

    elif text.startswith("🔧 Maint:") and is_admin(uid):
        db["settings"]["maintenance"] = not db["settings"].get(
            "maintenance", False
        )
        save_db(db)
        send_box(
            chat_id,
            f"🔧 Maintenance set to: <b>{'ON' if db['settings']['maintenance'] else 'OFF'}</b>",
            kb_admin_menu(
                db["settings"]["maintenance"],
                db["settings"].get("approval_required", False),
            ),
        )

    elif text.startswith("🛡 Approval:") and is_admin(uid):
        db["settings"]["approval_required"] = not db["settings"].get(
            "approval_required", False
        )
        save_db(db)
        send_box(
            chat_id,
            f"🛡 Approval set to: <b>{'ON' if db['settings']['approval_required'] else 'OFF'}</b>",
            kb_admin_menu(
                db["settings"].get("maintenance", False),
                db["settings"]["approval_required"],
            ),
        )

    elif text == "📢 Broadcast" and is_admin(uid):
        USER_STATES[uid] = {"flow": "adm_broadcast"}
        send_box(
            chat_id,
            "📢 Send broadcast message text (or ❌ Cancel):",
            kb_cancel_menu(),
        )

    elif text == "🎁 Give Plan" and is_admin(uid):
        USER_STATES[uid] = {"flow": "adm_giveplan"}
        send_box(
            chat_id,
            f"🎁 Send: <code>USER_ID PLAN_KEY DAYS</code>\nAvailable plans: {', '.join(plans.keys())}\n(or ❌ Cancel)",
            kb_cancel_menu(),
        )

    elif text == "🚫 Ban/Unban" and is_admin(uid):
        USER_STATES[uid] = {"flow": "adm_ban"}
        send_box(
            chat_id,
            "🚫 Send <code>ban USER_ID</code> or <code>unban USER_ID</code> (or ❌ Cancel):",
            kb_cancel_menu(),
        )

    elif text == "🎟 Create Coupon" and is_admin(uid):
        USER_STATES[uid] = {"flow": "adm_mkcoupon"}
        send_box(
            chat_id,
            "🎟 Send: <code>CODE PLAN_KEY DAYS USES</code>\nExample: <code>FREEPRO pro 7 50</code>\n(or ❌ Cancel)",
            kb_cancel_menu(),
        )

    elif text == "🤖 All Bots" and is_admin(uid):
        lines = [
            f"• {esc(b['name'])} (<code>{b['id']}</code>) | Owner: <code>{b['owner']}</code> | {b['status']}"
            for b in list(db["bots"].values())[:25]
        ]
        send_box(
            chat_id,
            "🤖 All Hosted Bots & Files:\n"
            + ("\n".join(lines) or "No bots yet.")
            + "\n\nনিচের বাটন থেকে যেকোনো ফাইলে চাপলে ভেতরের কোড দেখতে পারবেন:{FOOTER}",
            kb_admin_files_list(db),
        )

    elif text == "⏹ Stop All Bots" and is_admin(uid):
        for bid in list(RUNNING_BOTS.keys()):
            stop_bot_process(bid)
        bot.send_message(chat_id, "⏹ All running bots stopped.")


# =====================================================================
# 11. FILE UPLOAD & ACTIVE STATE HANDLERS
# =====================================================================
@bot.message_handler(content_types=["document"])
def handle_document(m: types.Message):
    if m.chat.type != "private":
        return
    uid = m.from_user.id
    db = load_db()
    plans = get_plans(db)
    u, _ = get_user(m.from_user)
    if u.get("banned"):
        return

    joined, _ = check_force_join(uid)
    if not joined:
        send_force_join_prompt(m.chat.id)
        return

    my_bots = [b for b in db["bots"].values() if b["owner"] == uid]
    max_b = user_max_bots(u, plans)
    if len(my_bots) >= max_b:
        send_box(
            m.chat.id,
            f"⚠️ Bot slot limit reached ({len(my_bots)}/{plan_limit_label(u, plans)}).",
            kb_main_menu(uid),
        )
        return

    doc = m.document
    fname = doc.file_name or "bot.py"
    if not fname.lower().endswith((".py", ".js", ".zip")):
        bot.reply_to(
            m,
            "❌ Only <code>.py</code>, <code>.js</code>, or <code>.zip</code> files are supported.",
        )
        return
    if (doc.file_size or 0) > MAX_UPLOAD_MB * 1024 * 1024:
        bot.reply_to(
            m,
            f"❌ ফাইলটি {MAX_UPLOAD_MB} MB-এর বেশি। সর্বোচ্চ 20 MB সমর্থিত।",
        )
        return

    msg_wait = bot.reply_to(m, "⏳ Downloading & scanning file...")
    try:
        file_info = bot.get_file(doc.file_id)
        raw_bytes = bot.download_file(file_info.file_path)
    except Exception as e:
        bot.edit_message_text(
            f"❌ Download failed: {esc(e)}", m.chat.id, msg_wait.message_id
        )
        return

    bot_id = secrets.token_hex(6)
    bot_dir = SANDBOX_DIR / f"{uid}_{bot_id}"
    bot_dir.mkdir(parents=True, exist_ok=True)

    if fname.lower().endswith(".zip"):
        zip_path = bot_dir / fname
        zip_path.write_bytes(raw_bytes)
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                total_uncompressed = sum(info.file_size for info in zf.infolist())
                if total_uncompressed > 200 * 1024 * 1024:
                    raise ValueError("ZIP expands beyond 200 MB limit")
                for info in zf.infolist():
                    member_path = Path(info.filename.replace("\\", "/"))
                    mode = (info.external_attr >> 16) & 0o170000
                    if (
                        member_path.is_absolute()
                        or ".." in member_path.parts
                        or mode == 0o120000
                    ):
                        shutil.rmtree(bot_dir, ignore_errors=True)
                        bot.edit_message_text(
                            "🚫 Unsafe ZIP path or symlink blocked!",
                            m.chat.id,
                            msg_wait.message_id,
                        )
                        return
                zf.extractall(bot_dir)
            zip_path.unlink(missing_ok=True)
        except Exception as e:
            shutil.rmtree(bot_dir, ignore_errors=True)
            bot.edit_message_text(
                f"❌ Invalid ZIP: {esc(e)}", m.chat.id, msg_wait.message_id
            )
            return
    else:
        (bot_dir / fname).write_bytes(raw_bytes)

    for pyf in bot_dir.rglob("*.py"):
        verdict, threats = scan_python_code(pyf.read_text(errors="ignore"))
        if verdict == "DANGEROUS" and not is_admin(uid):
            shutil.rmtree(bot_dir, ignore_errors=True)
            bot.edit_message_text(
                f"🚫 <b>Security Blocked!</b>\nThreats: {esc(', '.join(threats))}",
                m.chat.id,
                msg_wait.message_id,
            )
            return

    is_free_user = (u.get("plan") or "free") == "free"
    needs_appr = (
        bool(db["settings"].get("approval_required", False))
        and is_free_user
        and not is_admin(uid)
    )
    bot_name = Path(fname).stem[:25]

    db["bots"][bot_id] = {
        "id": bot_id,
        "owner": uid,
        "name": bot_name,
        "dir": str(bot_dir),
        "env": {},
        "status": "stopped",
        "approval": "pending" if needs_appr else "approved",
        "created": now_iso(),
    }
    save_db(db)
    USER_STATES.pop(uid, None)

    if needs_appr:
        bot.edit_message_text(
            "⏳ <b>Bot Uploaded!</b>\nফ্রি প্ল্যানে অ্যাডমিন অ্যাপ্রুভালের অপেক্ষায় রয়েছে।",
            m.chat.id,
            msg_wait.message_id,
        )
        owner_id = get_owner_id()
        if owner_id:
            kb_appr = types.InlineKeyboardMarkup().add(
                types.InlineKeyboardButton(
                    "✅ Approve", callback_data=f"bot_ok_{bot_id}"
                ),
                types.InlineKeyboardButton(
                    "❌ Reject", callback_data=f"bot_no_{bot_id}"
                ),
            )
            bot.send_message(
                owner_id,
                f"🆕 <b>Free Slot Bot Approval</b>\nUser: <code>{uid}</code>\nBot: <b>{esc(bot_name)}</b>\nBot ID: <code>{bot_id}</code>",
                reply_markup=kb_appr,
            )
    else:
        ok, res_msg = start_bot_process(bot_id)
        bot.edit_message_text(
            f"{'✅ <b>Bot Deployed!</b>' if ok else '⚠️ <b>Bot Uploaded (Start Issue):</b>'}\n"
            f"Name: <b>{esc(bot_name)}</b> (<code>{bot_id}</code>)\n"
            f"Status: {esc(res_msg)}",
            m.chat.id,
            msg_wait.message_id,
        )
        _show_bot_view(m.chat.id, uid, bot_id)


def handle_state_input(m: types.Message, st: Dict[str, Any]):
    uid = m.from_user.id
    flow = st.get("flow")
    text = (m.text or m.caption or "").strip()
    db = load_db()
    plans = get_plans(db)

    if flow == "await_bot_file":
        bot.reply_to(
            m,
            "📎 অনুগ্রহ করে টেক্সট নয়, একটি <code>.py</code>, <code>.js</code> অথবা <code>.zip</code> ফাইল (Document) সেন্ড করুন—অথবা ❌ Cancel চাপুন।",
            reply_markup=kb_cancel_menu(),
        )
        return

    # Step-by-step Wallet Method Add / Edit
    if flow == "add_wallet_name" and is_admin(uid):
        if not text:
            return
        mkey = (
            re.sub(r"[^a-z0-9_]", "", text.lower().replace(" ", "_"))
            or f"m_{secrets.token_hex(2)}"
        )
        USER_STATES[uid] = {
            "flow": "add_wallet_num",
            "mkey": mkey,
            "mname": text[:25],
        }
        send_box(
            m.chat.id,
            f"<b>{esc(text[:25])}</b> এর নম্বর বা ওয়ালেট আইডি লিখুন (বা ❌ Cancel চাপুন):{FOOTER}",
            kb_cancel_menu(),
        )

    elif flow == "add_wallet_num" and is_admin(uid):
        USER_STATES.pop(uid, None)
        mkey = st["mkey"]
        mname = st["mname"]
        db["payment_methods"][mkey] = {
            "name": mname,
            "number": text[:60],
            "type": "Send Money",
        }
        save_db(db)
        bot.send_message(
            m.chat.id,
            f"✅ নতুন মেথড <b>{esc(mname)}</b> যুক্ত হয়েছে (<code>{esc(text[:60])}</code>)।",
        )
        _show_wallet_methods_panel(m.chat.id, load_db())

    elif flow == "edit_wallet_num" and is_admin(uid):
        USER_STATES.pop(uid, None)
        mk = st["mk"]
        if mk in db["payment_methods"]:
            db["payment_methods"][mk]["number"] = text[:60]
            save_db(db)
            bot.send_message(
                m.chat.id,
                f"✅ <b>{esc(db['payment_methods'][mk]['name'])}</b> এর নম্বর আপডেট হয়েছে: <code>{esc(text[:60])}</code>",
            )
        _show_wallet_methods_panel(m.chat.id, load_db())

    # Step-by-step Plan Add / Edit
    elif flow == "add_plan_name" and is_admin(uid):
        if not text:
            return
        pkey = (
            re.sub(r"[^a-z0-9_]", "", text.lower().replace(" ", "_"))
            or f"p_{secrets.token_hex(2)}"
        )
        USER_STATES[uid] = {
            "flow": "add_plan_price",
            "pkey": pkey,
            "pname": text[:30],
        }
        send_box(
            m.chat.id,
            f"<b>{esc(text[:30])}</b> প্ল্যানের দাম (টাকায়) লিখুন (যেমন: <code>100</code> বা <code>0</code>)\nঅথবা ❌ Cancel চাপুন:{FOOTER}",
            kb_cancel_menu(),
        )

    elif flow == "add_plan_price" and is_admin(uid):
        if not text.isdigit():
            bot.reply_to(
                m,
                "❌ শুধু সংখ্যায় দাম লিখুন (যেমন: <code>100</code>)।",
                reply_markup=kb_cancel_menu(),
            )
            return
        USER_STATES[uid] = {
            "flow": "add_plan_days",
            "pkey": st["pkey"],
            "pname": st["pname"],
            "price": int(text),
        }
        send_box(
            m.chat.id,
            f"কত দিনের প্ল্যান হবে? দিন সংখ্যা লিখুন (যেমন: <code>30</code> বা <code>90</code>)\nঅথবা ❌ Cancel চাপুন:{FOOTER}",
            kb_cancel_menu(),
        )

    elif flow == "add_plan_days" and is_admin(uid):
        if not text.isdigit():
            bot.reply_to(
                m,
                "❌ শুধু সংখ্যায় দিন লিখুন (যেমন: <code>30</code>)।",
                reply_markup=kb_cancel_menu(),
            )
            return
        USER_STATES[uid] = {
            "flow": "add_plan_bots",
            "pkey": st["pkey"],
            "pname": st["pname"],
            "price": st["price"],
            "days": int(text),
        }
        send_box(
            m.chat.id,
            f"এই প্ল্যানে কয়টি বট চালানো যাবে? সংখ্যা লিখুন (যেমন: <code>5</code>)\nঅথবা ❌ Cancel চাপুন:{FOOTER}",
            kb_cancel_menu(),
        )

    elif flow == "add_plan_bots" and is_admin(uid):
        if not text.isdigit() or int(text) < 1:
            bot.reply_to(
                m, "❌ ১ বা তার বেশি সংখ্যা লিখুন।", reply_markup=kb_cancel_menu()
            )
            return
        USER_STATES.pop(uid, None)
        pkey = st["pkey"]
        db["plans"][pkey] = {
            "name": st["pname"],
            "price": st["price"],
            "days": st["days"],
            "max_bots": int(text),
            "auto_restart": st["price"] > 0,
        }
        save_db(db)
        bot.send_message(
            m.chat.id,
            f"✅ প্ল্যান <b>{esc(st['pname'])}</b> সেভ হয়েছে ({text} Bots, {st['price']}৳, {st['days']} দিন)।",
        )
        _show_plans_panel(m.chat.id, load_db())

    elif flow == "edit_plan_price" and is_admin(uid):
        if not text.isdigit():
            bot.reply_to(
                m, "❌ শুধু সংখ্যায় দাম লিখুন।", reply_markup=kb_cancel_menu()
            )
            return
        USER_STATES[uid] = {
            "flow": "edit_plan_days",
            "pkey": st["pkey"],
            "price": int(text),
        }
        send_box(
            m.chat.id,
            f"নতুন কত দিন মেয়াদ হবে? দিন সংখ্যা লিখুন (যেমন: <code>30</code>)\nঅথবা ❌ Cancel চাপুন:{FOOTER}",
            kb_cancel_menu(),
        )

    elif flow == "edit_plan_days" and is_admin(uid):
        if not text.isdigit():
            bot.reply_to(
                m, "❌ শুধু সংখ্যায় দিন লিখুন।", reply_markup=kb_cancel_menu()
            )
            return
        USER_STATES[uid] = {
            "flow": "edit_plan_bots",
            "pkey": st["pkey"],
            "price": st["price"],
            "days": int(text),
        }
        send_box(
            m.chat.id,
            f"নতুন বট লিমিট কত হবে? সংখ্যা লিখুন (যেমন: <code>6</code>)\nঅথবা ❌ Cancel চাপুন:{FOOTER}",
            kb_cancel_menu(),
        )

    elif flow == "edit_plan_bots" and is_admin(uid):
        if not text.isdigit() or int(text) < 1:
            bot.reply_to(
                m, "❌ ১ বা তার বেশি সংখ্যা লিখুন।", reply_markup=kb_cancel_menu()
            )
            return
        USER_STATES.pop(uid, None)
        pkey = st["pkey"]
        if pkey in db["plans"]:
            db["plans"][pkey]["price"] = st["price"]
            db["plans"][pkey]["days"] = st["days"]
            db["plans"][pkey]["max_bots"] = int(text)
            db["plans"][pkey]["auto_restart"] = st["price"] > 0
            save_db(db)
            bot.send_message(
                m.chat.id,
                f"✅ <b>{esc(db['plans'][pkey]['name'])}</b> আপডেট হয়েছে ({text} Bots, {st['price']}৳, {st['days']} দিন)।",
            )
        _show_plans_panel(m.chat.id, load_db())

    elif flow == "await_env":
        bid = st["bot_id"]
        b = db["bots"].get(bid)
        if not b:
            USER_STATES.pop(uid, None)
            send_welcome_main(m.chat.id, uid)
            return
        if text.upper().startswith("DEL "):
            key = text[4:].strip()
            b.get("env", {}).pop(key, None)
            save_db(db)
            bot.reply_to(
                m,
                f"🗑 Removed <code>{esc(key)}</code>",
                reply_markup=kb_cancel_menu(),
            )
        elif "=" in text:
            k, v = text.split("=", 1)
            k = k.strip()
            if k in SECRET_ENV_KEYS:
                bot.reply_to(
                    m,
                    "🚫 Reserved variable name.",
                    reply_markup=kb_cancel_menu(),
                )
                return
            b.setdefault("env", {})[k] = v.strip()
            save_db(db)
            bot.reply_to(
                m,
                f"✅ Saved <code>{esc(k)}</code>. Restart bot to apply.",
                reply_markup=kb_cancel_menu(),
            )
        else:
            bot.reply_to(
                m,
                "❌ Format must be <code>KEY=VALUE</code> (or tap ❌ Cancel)",
                reply_markup=kb_cancel_menu(),
            )

    elif flow == "await_pip":
        bid = st["bot_id"]
        b = db["bots"].get(bid)
        USER_STATES.pop(uid, None)
        if not b:
            send_welcome_main(m.chat.id, uid)
            return
        pkgs = [
            p
            for p in text.split()
            if re.match(r"^[a-zA-Z0-9_.\-\[\]=<>!]+$", p)
        ]
        if not pkgs:
            bot.reply_to(
                m, "❌ Invalid package name.", reply_markup=kb_main_menu(uid)
            )
            return
        wait = bot.reply_to(
            m, f"⏳ Installing <code>{esc(' '.join(pkgs))}</code>..."
        )
        r = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-cache-dir",
                "-q",
                "--break-system-packages",
                *pkgs,
            ],
            cwd=b["dir"],
            capture_output=True,
            text=True,
        )
        if r.returncode == 0:
            bot.edit_message_text(
                "✅ Installed successfully! Restart your bot.",
                m.chat.id,
                wait.message_id,
            )
        else:
            bot.edit_message_text(
                f"❌ Error:\n<pre>{esc(r.stderr[-800:])}</pre>",
                m.chat.id,
                wait.message_id,
            )
        _show_bot_view(m.chat.id, uid, bid)

    elif flow == "await_pay_proof":
        USER_STATES.pop(uid, None)
        pid = secrets.token_hex(4).upper()
        db["payments"].append(
            {
                "id": pid,
                "uid": uid,
                "plan": st["plan"],
                "amount": st["amount"],
                "method": st["method"],
                "proof": text or "[Photo]",
                "status": "pending",
                "ts": now_iso(),
            }
        )
        save_db(db)
        bot.reply_to(
            m,
            f"✅ ই-কেওয়াইসি / পেমেন্ট প্রুফ জমা হয়েছে (ID: <code>{pid}</code>)। অ্যাডমিন যাচাই করে অ্যাপ্রুভ করবেন!",
            reply_markup=kb_main_menu(uid),
        )
        owner_id = get_owner_id()
        if owner_id:
            kb_kyc = types.InlineKeyboardMarkup().add(
                types.InlineKeyboardButton(
                    "✅ Approve", callback_data=f"kyc_ok_{pid}"
                ),
                types.InlineKeyboardButton(
                    "❌ Reject", callback_data=f"kyc_no_{pid}"
                ),
            )
            caption = (
                f"🪪 <b>eKYC / Payment Proof</b>\n"
                f"• ID: <code>{pid}</code>\n"
                f"• User: <code>{uid}</code> (@{esc(m.from_user.username or 'N/A')})\n"
                f"• Plan: <b>{esc(st['plan'])}</b> ({st['amount']}৳)\n"
                f"• Method: <b>{esc(st['method'])}</b>\n"
                f"• Details: {esc(text or '[Screenshot]')}"
            )
            if m.photo:
                bot.send_photo(
                    owner_id,
                    m.photo[-1].file_id,
                    caption=caption,
                    reply_markup=kb_kyc,
                )
            else:
                bot.send_message(owner_id, caption, reply_markup=kb_kyc)

    elif flow == "await_coupon":
        USER_STATES.pop(uid, None)
        code = text.upper()
        cp = db["coupons"].get(code)
        if not cp or cp.get("uses", 0) <= 0:
            bot.reply_to(
                m,
                "❌ Invalid or expired coupon.",
                reply_markup=kb_main_menu(uid),
            )
            return
        if uid in cp.get("used_by", []):
            bot.reply_to(
                m,
                "⚠️ You already used this coupon.",
                reply_markup=kb_main_menu(uid),
            )
            return
        cp["uses"] -= 1
        cp.setdefault("used_by", []).append(uid)
        plan = cp["plan"]
        days = cp["days"]
        db["users"][str(uid)]["plan"] = plan
        db["users"][str(uid)]["plan_expires"] = (
            None
            if days <= 0
            else (
                datetime.now(timezone.utc) + timedelta(days=days)
            ).isoformat()
        )
        save_db(db)
        p_label = plans.get(plan, DEFAULT_PLANS["pro"])["name"]
        bot.reply_to(
            m,
            f"🎉 Coupon redeemed! Activated <b>{esc(p_label)}</b> for {days} days.",
            reply_markup=kb_main_menu(uid),
        )

    elif flow == "await_ticket":
        USER_STATES.pop(uid, None)
        owner_id = get_owner_id()
        if owner_id:
            bot.send_message(
                owner_id,
                f"🎫 <b>New Ticket from</b> <code>{uid}</code>:\n\n{esc(text)}",
            )
        bot.reply_to(
            m,
            "✅ Ticket sent to admin! You will receive a reply soon.",
            reply_markup=kb_main_menu(uid),
        )

    elif flow == "adm_broadcast" and is_admin(uid):
        USER_STATES.pop(uid, None)
        sent = 0
        for target_id in db["users"].keys():
            try:
                bot.send_message(
                    int(target_id), f"📢 <b>Announcement</b>\n\n{esc(text)}"
                )
                sent += 1
                time.sleep(0.05)
            except Exception:
                pass
        bot.reply_to(
            m,
            f"✅ Broadcast sent to {sent} users.",
            reply_markup=kb_admin_menu(
                db["settings"].get("maintenance", False),
                db["settings"].get("approval_required", False),
            ),
        )

    elif flow == "adm_giveplan" and is_admin(uid):
        USER_STATES.pop(uid, None)
        parts = text.split()
        if len(parts) < 3 or parts[1] not in plans:
            bot.reply_to(
                m,
                f"❌ Format: <code>USER_ID PLAN_KEY DAYS</code>\nPlans: {', '.join(plans.keys())}",
                reply_markup=kb_admin_menu(
                    db["settings"].get("maintenance", False),
                    db["settings"].get("approval_required", False),
                ),
            )
            return
        t_uid, plan_k, days = parts[0], parts[1], int(parts[2])
        if t_uid not in db["users"]:
            bot.reply_to(m, "❌ User not found.")
            return
        db["users"][t_uid]["plan"] = plan_k
        db["users"][t_uid]["plan_expires"] = (
            None
            if days <= 0
            else (
                datetime.now(timezone.utc) + timedelta(days=days)
            ).isoformat()
        )
        save_db(db)
        p_name = plans[plan_k]["name"]
        bot.reply_to(
            m,
            f"✅ Granted <b>{esc(p_name)}</b> to {t_uid} for {days} days.",
            reply_markup=kb_admin_menu(
                db["settings"].get("maintenance", False),
                db["settings"].get("approval_required", False),
            ),
        )
        try:
            bot.send_message(
                int(t_uid),
                f"🎁 Admin gifted you <b>{esc(p_name)}</b> plan for {days} days!",
            )
        except Exception:
            pass

    elif flow == "adm_ban" and is_admin(uid):
        USER_STATES.pop(uid, None)
        parts = text.split()
        if len(parts) < 2:
            return
        act, t_uid = parts[0].lower(), parts[1]
        if t_uid in db["users"]:
            db["users"][t_uid]["banned"] = act == "ban"
            save_db(db)
            bot.reply_to(
                m,
                f"✅ User {t_uid} {'banned' if act == 'ban' else 'unbanned'}.",
                reply_markup=kb_admin_menu(
                    db["settings"].get("maintenance", False),
                    db["settings"].get("approval_required", False),
                ),
            )

    elif flow == "adm_mkcoupon" and is_admin(uid):
        USER_STATES.pop(uid, None)
        parts = text.split()
        if len(parts) < 4 or parts[1] not in plans:
            bot.reply_to(m, "❌ Format: <code>CODE PLAN_KEY DAYS USES</code>")
            return
        code, plan_k, days, uses = (
            parts[0].upper(),
            parts[1],
            int(parts[2]),
            int(parts[3]),
        )
        db["coupons"][code] = {
            "plan": plan_k,
            "days": days,
            "uses": uses,
            "used_by": [],
        }
        save_db(db)
        bot.reply_to(
            m,
            f"✅ Coupon <code>{code}</code> created ({plan_k}, {days}d, {uses} uses).",
            reply_markup=kb_admin_menu(
                db["settings"].get("maintenance", False),
                db["settings"].get("approval_required", False),
            ),
        )


@bot.message_handler(content_types=["photo"])
def handle_photo_input(m: types.Message):
    if m.chat.type != "private":
        return
    st = USER_STATES.get(m.from_user.id)
    if st:
        handle_state_input(m, st)


# =====================================================================
# 12. BACKGROUND EXPIRY WATCHDOG & BOOT
# =====================================================================
def _expiry_watcher():
    while True:
        time.sleep(3600)
        db = load_db()
        changed = False
        now = datetime.now(timezone.utc)
        for uid_str, u in db["users"].items():
            if int(uid_str) == get_owner_id():
                u["plan"] = "infinity"
                u["plan_expires"] = None
                continue
            if u.get("plan") not in ("free", "infinity") and u.get(
                "plan_expires"
            ):
                try:
                    exp = datetime.fromisoformat(u["plan_expires"])
                    if now > exp:
                        u["plan"] = "free"
                        u["plan_expires"] = None
                        changed = True
                except Exception:
                    pass
        if changed:
            save_db(db)


if __name__ == "__main__":
    print(f"[{BRAND} {BRAND_VER}] Booting up...")
    db_boot = load_db()
    for bid, b_data in db_boot["bots"].items():
        if b_data.get("status") == "running":
            start_bot_process(bid)

    threading.Thread(target=_expiry_watcher, daemon=True).start()
    print(f"[{BRAND}] Bot is online and polling!")
    bot.infinity_polling(skip_pending=True, timeout=30)