#!/usr/bin/env python3
"""Android 10/Termux: package grid and local Roblox session import/export.

Standard library only. Run with Termux Python; grant su when requested.
Session stores vary by APK. Only recognized, existing plaintext cookie stores
are modified. Never create an invented preference key or claim UI login success.
"""

import datetime as dt
from contextlib import contextmanager
from getpass import getpass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from http.cookies import SimpleCookie
from typing import NamedTuple

GAP = 8
MIN_CELL = 100
LAUNCH_DELAY = 0.7
WINDOWING_MODE_FREEFORM = 5
BASE = Path(__file__).resolve().parent
CONFIG = BASE / "grid_packages.json"
COOKIE_NAME = ".ROBLOSECURITY"
AUTH_URL = "https://users.roblox.com/v1/users/authenticated"
PACKAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+")
MAX_FILE = 8 * 1024 * 1024


class ToolError(Exception):
    """Safe user-facing message: never embed cookie content."""


class CookieEntry(NamedTuple):
    package: str
    username: str
    password: str
    cookie: str


def normalize_password(password):
    """Use the literal ``none`` whenever an account has no password."""
    return password if password else "none"


def check_account_fields(username, password):
    if not re.fullmatch(r"[A-Za-z0-9_]+", username):
        raise ToolError("Tài khoản phải là username Roblox (chữ, số, dấu gạch dưới).")
    if any(c == ":" or ord(c) < 32 or ord(c) == 127 for c in password):
        raise ToolError("Mật khẩu không được chứa dấu hai chấm hoặc ký tự xuống dòng/tab.")


def cookie_fingerprint(cookie):
    return hashlib.sha256(cookie.encode("utf-8")).hexdigest()


def load_account_data():
    path = BASE / "cookie_accounts.json"
    if not path.exists():
        return {"version": 1, "users": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
            raise ValueError
        for accounts in data["users"].values():
            if not isinstance(accounts, dict):
                raise ValueError
            for pkg, entry in accounts.items():
                if not package_ok(pkg) or not isinstance(entry, dict):
                    raise ValueError
                if any(not isinstance(entry.get(k), str) for k in ("username", "password", "cookie_sha256")):
                    raise ValueError
                entry["password"] = normalize_password(entry["password"])
                check_account_fields(entry["username"], entry["password"])
        return data
    except (ValueError, OSError, ToolError):
        raise ToolError("Không đọc được cookie_accounts.json; kiểm tra file trước khi tiếp tục.") from None


def remember_account(pkg, user_id, entry):
    password = normalize_password(entry.password)
    check_account_fields(entry.username, password)
    data = load_account_data()
    data["users"].setdefault(str(user_id), {})[pkg] = {
        "username": entry.username, "password": password,
        "cookie_sha256": cookie_fingerprint(entry.cookie),
    }
    atomic_text(BASE / "cookie_accounts.json", json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def export_account(pkg, user_id, cookie, accounts):
    saved = accounts.get(pkg)
    if saved and saved["cookie_sha256"] == cookie_fingerprint(cookie):
        return CookieEntry(pkg, saved["username"],
                           normalize_password(saved["password"]), cookie)
    print(f"[*] {pkg}: chưa có tk/mk khớp cookie hiện tại.")
    username = input("Tài khoản Roblox (Enter = bỏ qua acc): ").strip()
    if not username:
        return None
    password = normalize_password(getpass("Mật khẩu (ẩn; Enter = để none): "))
    check_account_fields(username, password)
    entry = CookieEntry(pkg, username, password, cookie)
    remember_account(pkg, user_id, entry)
    return entry


def package_ok(value):
    return bool(PACKAGE_RE.fullmatch(value))


def run(cmd, root=False, timeout=20, input_text=None):
    command = shlex.join(cmd) if isinstance(cmd, list) else cmd
    args = ["su", "-c", command] if root else (
        cmd if isinstance(cmd, list) else ["sh", "-c", cmd])
    try:
        p = subprocess.run(args, input=input_text, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ToolError("Lệnh Android quá thời gian; hãy thử lại.") from None
    except OSError:
        raise ToolError("Không chạy được lệnh. Tool cần Python trong Termux và su.") from None
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def android(cmd, timeout=20):
    rc, out, err = run(cmd, root=True, timeout=timeout)
    if rc or re.search(r"(?im)^\s*(?:error:|exception|securityexception)", out + "\n" + err):
        raise ToolError("Lệnh Android thất bại: " + shlex.join(cmd[:3]))
    return out


def current_user():
    out = android(["am", "get-current-user"])
    if not out.isdigit():
        raise ToolError("Không xác định được Android user; dừng để tránh chọn nhầm profile.")
    return int(out)


def natural_key(value):
    return [int(p) if p.isdigit() else p.lower() for p in re.split(r"(\d+)", value)]


def list_packages(prefix="", user_id=0):
    out = android(["pm", "list", "packages", "--user", str(user_id)])
    return sorted({line[8:].strip() for line in out.splitlines()
                   if line.startswith("package:") and package_ok(line[8:].strip())
                   and line[8:].strip().startswith(prefix)}, key=natural_key)


def parse_selection(value, count):
    value = value.strip().lower()
    if value in ("all", "a", "*"):
        return list(range(count))
    if not value:
        raise ToolError("Chưa chọn tài khoản.")
    indices = []
    for part in re.split(r"[\s,]+", value):
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not match:
            raise ToolError("Nhập dạng 1,3,5-8 hoặc all.")
        first, last = int(match[1]), int(match[2] or match[1])
        if not 1 <= first <= last <= count:
            raise ToolError("Số tài khoản hoặc dải số nằm ngoài danh sách.")
        for i in range(first - 1, last):
            if i not in indices:
                indices.append(i)
    return indices


def select_packages(packages):
    for i, pkg in enumerate(packages, 1):
        print(f"  {i:02d}. {pkg}")
    answer = input("Chọn acc (1,3,5-8 / all; Enter = hủy): ")
    return [packages[i] for i in parse_selection(answer, len(packages))] if answer.strip() else []


def atomic_text(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        os.chmod(tmp, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_packages(user_id):
    if not CONFIG.exists():
        return []
    try:
        data = json.loads(CONFIG.read_text(encoding="utf-8"))
        values = data.get("users", {}).get(str(user_id), [])
        if not isinstance(values, list) or any(not isinstance(p, str) or not package_ok(p) for p in values):
            raise ValueError
        return list(dict.fromkeys(values))
    except (ValueError, OSError, AttributeError):
        print("[!] grid_packages.json không hợp lệ; chọn mục 1 để nhập lại.")
        return []


def import_packages(user_id):
    installed = list_packages(user_id=user_id)
    query = input("Nhập tiền tố package hoặc nhiều package cách nhau bằng dấu phẩy: ").strip()
    if not query:
        return None
    if "," in query or " " in query:
        wanted = list(dict.fromkeys(re.split(r"[\s,]+", query)))
        missing = [p for p in wanted if p not in installed]
        if missing:
            raise ToolError("Package chưa cài cho user hiện tại: " + ", ".join(missing))
        candidates = wanted
    else:
        candidates = [p for p in installed if p.startswith(query)]
    if not candidates:
        raise ToolError("Không có package khớp với nội dung vừa nhập.")
    selected = select_packages(candidates)
    if not selected:
        return None
    data = {"version": 1, "users": {}}
    if CONFIG.exists():
        try:
            old = json.loads(CONFIG.read_text(encoding="utf-8"))
            if isinstance(old.get("users"), dict):
                data["users"] = old["users"]
        except (ValueError, AttributeError):
            pass
    data["users"][str(user_id)] = selected
    atomic_text(CONFIG, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    print(f"[+] Đã lưu {len(selected)} package cho Android user {user_id}.")
    return selected


def resolve_launcher(pkg, user_id):
    out = android(["cmd", "package", "resolve-activity", "--brief", "--user", str(user_id),
                   "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER", pkg])
    return next((s.strip() for s in reversed(out.splitlines())
                 if re.fullmatch(re.escape(pkg) + r"/[A-Za-z0-9_.$]+", s.strip())), None)


def get_screen_size():
    out = android(["wm", "size"])
    sizes = re.findall(r"(\d+)x(\d+)", out)
    if not sizes:
        raise ToolError("Không đọc được kích thước màn hình.")
    w, h = map(int, sizes[-1])
    _, rotations, _ = run(["dumpsys", "input"], root=True)
    match = re.search(r"SurfaceOrientation:\s*(\d+)", rotations)
    if match and int(match[1]) in (1, 3):
        w, h = h, w
    return w, h


def get_stable_area(w, h):
    _, out, _ = run(["dumpsys", "window", "displays"], root=True)
    patterns = (r"mStable=Rect\((\d+),\s*(\d+)\s*-\s*(\d+),\s*(\d+)\)",
                r"mStable=\[(\d+),(\d+)\]\[(\d+),(\d+)\]")
    for pat in patterns:
        for match in re.finditer(pat, out):
            l, t, r, b = map(int, match.groups())
            if 0 <= l < r <= w and 0 <= t < b <= h:
                return l, t, r, b
    return 0, 0, w, h


def choose_grid(n, width, height):
    if n < 1 or width < 1 or height < 1:
        raise ToolError("Số cửa sổ hoặc vùng màn hình không hợp lệ.")
    choices = []
    for cols in range(1, n + 1):
        rows = math.ceil(n / cols)
        cw = (width - GAP * (cols + 1)) // cols
        ch = (height - GAP * (rows + 1)) // rows
        if min(cw, ch) >= MIN_CELL:
            # Favor balanced cells, then less unused screen space.
            choices.append((abs(math.log(cw / ch)) + (cols * rows - n) / n * 0.25, cols, rows))
    if not choices:
        raise ToolError("Quá nhiều cửa sổ cho màn hình này; hãy chọn ít package hơn ở mục 1.")
    _, cols, rows = min(choices)
    return cols, rows


def build_bounds(n, area):
    l, t, r, b = area
    cols, rows = choose_grid(n, r - l, b - t)
    iw, ih = r - l - GAP * (cols + 1), b - t - GAP * (rows + 1)
    result = []
    for i in range(n):
        row, col = divmod(i, cols)
        result.append((l + GAP * (col + 1) + col * iw // cols,
                       t + GAP * (row + 1) + row * ih // rows,
                       l + GAP * (col + 1) + (col + 1) * iw // cols,
                       t + GAP * (row + 1) + (row + 1) * ih // rows))
    return result, cols, rows


def parse_task_id(text, pkg, user_id, stack=False):
    # A '.' is part of a package: com.game must not match com.game.clone.
    exact = re.compile(r"(?<![\w.])" + re.escape(pkg) + r"(?=/|[\s},]|$)")
    ids = []
    for line in text.splitlines():
        if not exact.search(line):
            continue
        user = re.search(r"\buserId=(\d+)\b|\bu(\d+)\b|\bU=(\d+)\b", line)
        if user and int(next(g for g in user.groups() if g is not None)) != user_id:
            continue
        if not user:  # Never resize an unscoped task from another Android profile.
            continue
        match = re.search(r"\btaskId=(\d+)\b|\bTask(?:Record)?\{[^\n]*?#(\d+)\b|\bt(\d+)\b", line)
        if match:
            ids.append(int(next(g for g in match.groups() if g is not None)))
    return ids[0] if ids else None


def get_task_id(pkg, user_id, retries=6):
    for _ in range(retries):
        for cmd in (["am", "stack", "list"], ["dumpsys", "activity", "activities"]):
            rc, out, _ = run(cmd, root=True, timeout=25)
            if not rc:
                task_id = parse_task_id(out, pkg, user_id)
                if task_id is not None:
                    return task_id
        time.sleep(0.25)
    return None


def open_grid(packages, user_id):
    launchable = []
    for pkg in packages:
        try:
            component = resolve_launcher(pkg, user_id)
            if not component:
                raise ToolError("Không có launcher activity.")
            launchable.append((pkg, component))
        except ToolError as exc:
            print(f"[!] {pkg}: {exc}")
    if not launchable:
        raise ToolError("Không có app nào mở được.")
    w, h = get_screen_size()
    bounds_list, cols, rows = build_bounds(len(launchable), get_stable_area(w, h))
    for setting in ("force_resizable_activities", "enable_freeform_support"):
        android(["settings", "put", "global", setting, "1"])
        if android(["settings", "get", "global", setting]) != "1":
            raise ToolError("Không bật được " + setting)
    print(f"[*] Màn hình {w}x{h}; lưới {cols} cột × {rows} hàng.")
    good = 0
    for (pkg, component), bounds in zip(launchable, bounds_list):
        try:
            android(["am", "start", "--user", str(user_id), "--windowingMode",
                     str(WINDOWING_MODE_FREEFORM), "-n", component])
            time.sleep(LAUNCH_DELAY)
            task_id = get_task_id(pkg, user_id)
            if task_id is None:
                raise ToolError("Không tìm được taskId đúng package/profile.")
            android(["am", "task", "resize", str(task_id), *map(str, bounds)])
            print(f"[OK] {pkg}: task {task_id}, bounds={bounds}")
            good += 1
        except ToolError as exc:
            print(f"[!] {pkg}: {exc}")
    print(f"[+] Đã gửi lệnh xếp lưới: {good}/{len(launchable)} app.")
    print("[*] Nếu vẫn toàn màn hình: ROM cần hỗ trợ freeform; lần đầu có thể cần reboot.")


def normalize_cookie(value):
    value = value.strip()
    if value.startswith(COOKIE_NAME + "="):
        value = value[len(COOKIE_NAME) + 1:].split(";", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    # Opaque value: do not depend on the historical warning prefix/hex format.
    if not value or len(value) > 32768 or any(ord(c) <= 32 or ord(c) >= 127 or c in ';"\\' for c in value):
        raise ToolError("Cookie trống hoặc chứa ký tự không hợp lệ.")
    return value


def read_cookie_file(path):
    path = Path(path).expanduser()
    if path.stat().st_size > MAX_FILE:
        raise ToolError("File cookie vượt quá 8 MB.")
    rows = []
    pending_package = None
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = line.strip()
        if line.startswith("# package: "):
            if pending_package is not None:
                raise ToolError(f"Thiếu dòng tài khoản trước dòng {number}.")
            pending_package = line[len("# package: "):].strip()
            if not package_ok(pending_package):
                raise ToolError(f"Package sai định dạng ở dòng {number}.")
            continue
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t", 1)
        pkg, value = (fields[0], fields[1]) if len(fields) == 2 else (pending_package, fields[0])
        if pending_package is not None and pkg != pending_package:
            raise ToolError(f"Package không khớp chú thích ở dòng {number}.")
        pending_package = None
        if pkg is not None and not package_ok(pkg):
            raise ToolError(f"Package sai định dạng ở dòng {number}.")
        try:
            username, password = "", "none"
            # Split only the first two colons: the cookie's warning/token may
            # itself contain colons. Canonicalize only a missing password.
            if not value.startswith((COOKIE_NAME + "=", "_|WARNING:")) and value.count(":") >= 2:
                username, password, value = value.split(":", 2)
                password = normalize_password(password)
                check_account_fields(username, password)
            rows.append(CookieEntry(pkg, username, password, normalize_cookie(value)))
        except ToolError:
            raise ToolError(f"Dòng {number} không hợp lệ; dùng tk:mk:cookie.") from None
    if pending_package is not None:
        raise ToolError("Thiếu dòng tài khoản sau chú thích package cuối file.")
    if not rows:
        raise ToolError("File không có cookie.")
    mapped = [row.package for row in rows if row.package is not None]
    if mapped and len(mapped) != len(rows):
        raise ToolError("Không trộn dòng có ánh xạ package với dòng không có ánh xạ.")
    if len(mapped) != len(set(mapped)):
        raise ToolError("File chứa package trùng; mỗi package chỉ được có một dòng.")
    return rows


def map_cookies(rows, packages):
    if rows[0].package is not None:
        values = {row.package: row for row in rows}
        missing = [p for p in packages if p not in values]
        if missing:
            raise ToolError("File thiếu cookie cho: " + ", ".join(missing))
        return [(p, values[p]) for p in packages]
    if len(rows) != len(packages):
        raise ToolError(f"Có {len(rows)} cookie nhưng chọn {len(packages)} acc; số lượng phải bằng nhau.")
    return [(p, row._replace(package=p)) for p, row in zip(packages, rows)]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def authenticate_cookie(cookie):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(AUTH_URL, headers={
        "Cookie": COOKIE_NAME + "=" + normalize_cookie(cookie),
        "Accept": "application/json", "User-Agent": "AndroidGridSessionTool/2.0"})
    try:
        with opener.open(request, timeout=20) as response:
            data = json.loads(response.read(65536))
            if not isinstance(data, dict) or type(data.get("id")) is not int or data["id"] <= 0:
                raise ToolError("Roblox trả về thông tin tài khoản không hợp lệ.")
            # Persist a rotated token to the app rather than installing its old value.
            for header in response.headers.get_all("Set-Cookie", []):
                jar = SimpleCookie()
                jar.load(header)
                if COOKIE_NAME in jar:
                    cookie = normalize_cookie(jar[COOKIE_NAME].value)
            return cookie, data["id"], str(data.get("name", data["id"]))
    except urllib.error.HTTPError as exc:
        messages = {401: "Cookie hết hạn hoặc đã bị thu hồi.",
                    403: "Roblox từ chối phiên này; cần đăng nhập lại trong app.",
                    429: "Roblox giới hạn yêu cầu; thử lại sau."}
        raise ToolError(messages.get(exc.code, f"Roblox trả HTTP {exc.code}.")) from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise ToolError("Không kiểm tra được cookie với Roblox; kiểm tra mạng và giờ hệ thống.") from None


def roblox_host(host):
    host = host.removeprefix("#HttpOnly_").lstrip(".").lower()
    return host == "roblox.com" or host.endswith(".roblox.com")


@contextmanager
def sqlite_db(path, **kwargs):
    db = sqlite3.connect(path, **kwargs)
    try:
        with db:
            yield db
    finally:
        db.close()


def xml_entries(raw):
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None, []
    if root.tag != "map":
        return None, []
    entries = []
    for node in root.findall("string"):
        key, value = node.get("name", ""), node.text or ""
        if key.upper().lstrip(".") == "ROBLOSECURITY" and value:
            entries.append((node, normalize_cookie(value), "direct"))
        elif "cookie" in key.lower():
            matches = list(re.finditer(r"(?:^|;\s*)(\.ROBLOSECURITY=)([^;\r\n]+)", value))
            if matches:
                entries.append((node, normalize_cookie(matches[0][2]), "header"))
    return root, entries


def netscape_entries(raw):
    try:
        lines = raw.decode("utf-8").splitlines(keepends=True)
    except UnicodeError:
        return [], []
    entries = []
    for i, line in enumerate(lines):
        fields = line.rstrip("\r\n").split("\t")
        if len(fields) == 7 and fields[5] == COOKIE_NAME and roblox_host(fields[0]):
            entries.append((i, normalize_cookie(fields[6]), fields))
    return lines, entries


def sqlite_cookies(path):
    with sqlite_db(path.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(cookies)")}
        if not {"host_key", "name", "value"} <= columns:
            return []
        encrypted = "encrypted_value" if "encrypted_value" in columns else "X''"
        rows = db.execute(f"SELECT host_key, value, {encrypted} FROM cookies WHERE name=?", (COOKIE_NAME,)).fetchall()
        entries = []
        for host, value, ciphertext in rows:
            if roblox_host(host):
                if ciphertext:
                    raise ToolError("Kho cookie được mã hóa; phiên bản này không hỗ trợ định dạng đó.")
                if value:
                    entries.append(normalize_cookie(value))
        return entries


def discover_stores(data_dir):
    """Inspect only cookie files/preferences inside one explicitly selected app."""
    candidates = list((data_dir / "shared_prefs").glob("*.xml"))
    for rel in ("app_webview/Cookies", "app_webview/Default/Cookies",
                "app_webview/Default/Network/Cookies"):
        candidates.append(data_dir / rel)
    files_dir = data_dir / "files"
    visited = 0
    for parent, dirs, files in os.walk(files_dir, followlinks=False):
        visited += 1
        if visited > 2000:
            raise ToolError("Thư mục app quá lớn để nhận diện kho cookie an toàn.")
        relative = Path(parent).relative_to(files_dir)
        dirs[:] = [d for d in dirs if not (Path(parent) / d).is_symlink()
                   and len(relative.parts) < 5 and d.lower() not in ("logs", "cache")]
        for name in files:
            if "cookie" in name.lower() and not name.endswith(("-wal", "-shm", "-journal")):
                candidates.append(Path(parent) / name)
    stores, issues = [], []
    for path in dict.fromkeys(candidates):
        if not path.is_file() or path.is_symlink():
            continue
        if not path.resolve().is_relative_to(data_dir.resolve()):
            continue
        try:
            if path.stat().st_size > MAX_FILE:
                continue
            with path.open("rb") as handle:
                signature = handle.read(16)
            if signature == b"SQLite format 3\x00":
                values = sqlite_cookies(path)
                kind = "sqlite"
            else:
                raw = path.read_bytes()
                if path.suffix == ".xml":
                    _, entries = xml_entries(raw)
                    values = [v for _, v, _ in entries]
                    kind = "xml"
                else:
                    _, entries = netscape_entries(raw)
                    values = [v for _, v, _ in entries]
                    kind = "netscape"
            if values:
                stores.append((path, kind, values))
        except (ToolError, sqlite3.Error, OSError, UnicodeError):
            issues.append(path.relative_to(data_dir).as_posix())
    if issues:
        raise ToolError("Kho cookie không đọc được/không hỗ trợ: " + ", ".join(issues))
    if not stores:
        raise ToolError("Chưa có kho .ROBLOSECURITY được hỗ trợ. Mở app và đăng nhập thủ công một lần; "
                        "nếu vẫn lỗi, APK này dùng định dạng cookie khác.")
    return stores


def replace_app_file(path, raw):
    """Atomic replacement preserving app ownership, permissions and SELinux xattrs."""
    old = path.stat()
    fd, temp = tempfile.mkstemp(prefix=".grid_cookie_", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temp, old.st_uid, old.st_gid)
        os.chmod(temp, stat.S_IMODE(old.st_mode))
        for attr in os.listxattr(path):
            os.setxattr(temp, attr, os.getxattr(path, attr))
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def backup_store(path, kind, target):
    if kind == "sqlite":
        with sqlite_db(path.as_uri() + "?mode=ro", uri=True) as src:
            with sqlite_db(target) as dest:
                src.backup(dest)
    else:
        target.write_bytes(path.read_bytes())
    target.chmod(0o600)


def write_store(path, kind, cookie):
    if kind == "sqlite":
        with sqlite_db(path, timeout=10) as db:
            columns = {row[1] for row in db.execute("PRAGMA table_info(cookies)")}
            updates = {"value": cookie}
            if "encrypted_value" in columns:
                updates["encrypted_value"] = b""
            now = int((time.time() + 11644473600) * 1000000)
            if "expires_utc" in columns:
                updates["expires_utc"] = now + 30 * 86400 * 1000000
            for col, val in (("has_expires", 1), ("is_persistent", 1), ("is_secure", 1),
                             ("is_httponly", 1), ("last_access_utc", now), ("last_update_utc", now)):
                if col in columns:
                    updates[col] = val
            hosts = {row[0] for row in db.execute("SELECT host_key FROM cookies WHERE name=?", (COOKIE_NAME,))
                     if roblox_host(row[0])}
            if not hosts:
                raise ToolError("Kho cookie thay đổi trong lúc xử lý.")
            assignments = ", ".join('"' + key + '"=?' for key in updates)
            for host in hosts:
                db.execute(f"UPDATE cookies SET {assignments} WHERE name=? AND host_key=?",
                           [*updates.values(), COOKIE_NAME, host])
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ToolError("SQLite không vượt qua kiểm tra toàn vẹn.")
    elif kind == "xml":
        root, entries = xml_entries(path.read_bytes())
        if not entries:
            raise ToolError("Kho cookie thay đổi trong lúc xử lý.")
        for node, _, form in entries:
            node.text = cookie if form == "direct" else re.sub(
                r"(^|;\s*)(\.ROBLOSECURITY=)[^;\r\n]+", lambda m: m[1] + m[2] + cookie, node.text)
        replace_app_file(path, ET.tostring(root, encoding="utf-8", xml_declaration=True))
    else:
        lines, entries = netscape_entries(path.read_bytes())
        if not entries:
            raise ToolError("Kho cookie thay đổi trong lúc xử lý.")
        for i, _, fields in entries:
            fields[4], fields[6] = str(int(time.time()) + 30 * 86400), cookie
            lines[i] = "\t".join(fields) + "\n"
        replace_app_file(path, "".join(lines).encode("utf-8"))


def restore_store(path, kind, backup):
    if kind == "sqlite":
        with sqlite_db(backup) as src:
            with sqlite_db(path) as dest:
                src.backup(dest)
    else:
        replace_app_file(path, backup.read_bytes())


def install_cookie(data_dir, stores, cookie):
    backup_dir = data_dir / ".grid_cookie_backups" / (dt.datetime.now().strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:8])
    backup_dir.mkdir(parents=True, mode=0o700)
    backup_dir.parent.chmod(0o700)
    backups, changed = [], []
    for i, (path, kind, _) in enumerate(stores):
        target = backup_dir / str(i)
        backup_store(path, kind, target)
        backups.append((path, kind, target))
    atomic_text(backup_dir / "manifest.json", json.dumps([
        {"path": p.relative_to(data_dir).as_posix(), "kind": k, "backup": b.name}
        for p, k, b in backups], indent=2))
    try:
        for path, kind, backup in backups:
            changed.append((path, kind, backup))
            write_store(path, kind, cookie)
        verified = discover_stores(data_dir)
        if any(value != cookie for _, _, values in verified for value in values):
            raise ToolError("Đọc lại cookie không khớp.")
    except BaseException:
        rollback_failed = False
        for path, kind, backup in reversed(changed):
            try:
                restore_store(path, kind, backup)
            except Exception:
                rollback_failed = True
        if rollback_failed:
            raise ToolError("Khôi phục chưa đầy đủ. Bản sao lưu: " + str(backup_dir)) from None
        raise ToolError("Ghi cookie thất bại; đã khôi phục dữ liệu cũ. Backup: " + str(backup_dir)) from None
    return str(backup_dir)


def cookie_worker(request):
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise ToolError("Tiến trình cookie chưa được cấp root.")
    pkg, uid = request.get("package", ""), request.get("user_id")
    if not package_ok(pkg) or type(uid) is not int or uid < 0:
        raise ToolError("Package/profile không hợp lệ.")
    operation = request.get("operation")
    if operation not in ("inspect", "export", "import"):
        raise ToolError("Thao tác cookie không hợp lệ.")
    if current_user() != uid or pkg not in list_packages(user_id=uid):
        raise ToolError("Profile đã đổi hoặc package không được cài cho profile này.")
    data_dir = Path(f"/data/user/{uid}/{pkg}")
    if not data_dir.is_dir():
        raise ToolError("Chưa có dữ liệu app cho profile này; hãy mở app trước.")
    if operation == "import":
        cookie = normalize_cookie(request.get("cookie", ""))
        android(["am", "force-stop", "--user", str(uid), pkg])
        time.sleep(0.3)
    stores = discover_stores(data_dir)
    if operation == "inspect":
        return {"stores": len(stores)}
    if operation == "export":
        values = {value for _, _, entries in stores for value in entries}
        if len(values) != 1:
            raise ToolError("Có nhiều cookie khác nhau trong app; mở app đăng nhập lại trước khi xuất.")
        return {"cookie": values.pop()}
    backup = install_cookie(data_dir, stores, cookie)
    return {"stores": len(stores), "backup": backup}


def worker_request(operation, pkg, user_id, cookie=None):
    payload = {"operation": operation, "package": pkg, "user_id": user_id}
    if cookie is not None:
        payload["cookie"] = cookie
    # Tokens travel through stdin/stdout pipes, never shell arguments or logs.
    rc, out, _ = run([sys.executable, str(Path(__file__).resolve()), "--cookie-worker"],
                     root=True, timeout=90, input_text=json.dumps(payload))
    try:
        result = json.loads(out)
    except ValueError:
        raise ToolError("Root helper không trả kết quả; kiểm tra quyền su và Python Termux.") from None
    if rc or not result.get("ok"):
        raise ToolError(result.get("error", "Root helper thất bại."))
    return result


def find_cookie_file(user_id):
    candidates = list(dict.fromkeys([BASE / "cookie.txt", Path.cwd() / "cookie.txt",
                                    Path(f"/storage/emulated/{user_id}/Download/cookie.txt"),
                                    Path(f"/storage/emulated/{user_id}/cookie.txt")]))
    found = [p for p in candidates if p.is_file()]
    if len(found) == 1:
        print("[*] File cookie: " + str(found[0]))
        return found[0]
    if found:
        for i, path in enumerate(found, 1):
            print(f"  {i}. {path}")
        answer = input("Chọn số file hoặc nhập đường dẫn cookie.txt: ").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(found):
            return found[int(answer) - 1]
    else:
        answer = input("Đường dẫn cookie.txt (Enter = hủy): ").strip()
    return Path(answer).expanduser() if answer else None


def login_cookies(packages, user_id):
    selected = select_packages(packages)
    if not selected:
        return
    path = find_cookie_file(user_id)
    if path is None:
        return
    pairs = map_cookies(read_cookie_file(path), selected)
    print("[*] Dòng tk:mk:cookie được ghép theo thứ tự acc chọn; file xuất có chú thích package sẽ ghép theo package.")
    print("[*] App được chọn sẽ dừng để cập nhật phiên, sau đó mở lại.")
    done = 0
    for pkg, entry in pairs:
        try:
            component = resolve_launcher(pkg, user_id)
            if not component:
                raise ToolError("Không có launcher để mở app.")
            worker_request("inspect", pkg, user_id)
            cookie, account_id, name = authenticate_cookie(entry.cookie)
            if entry.username and entry.username.casefold() != name.casefold():
                raise ToolError("Tài khoản trong dòng tk:mk:cookie không khớp tài khoản của cookie; không ghi vào app.")
            result = worker_request("import", pkg, user_id, cookie)
            try:
                remember_account(pkg, user_id, CookieEntry(pkg, name, entry.password, cookie))
            except (ToolError, OSError):
                print("[!] Đã ghi cookie nhưng chưa lưu được tk/mk; khi xuất sẽ cần nhập lại.")
            print(f"[+] {pkg}: đã ghi phiên của {name} (ID {account_id}); backup: {result['backup']}")
            android(["am", "start", "--user", str(user_id), "-n", component])
            print("    Đã mở app; kiểm tra tài khoản hiển thị trong app.")
            done += 1
        except (ToolError, OSError, UnicodeError):
            exc = sys.exc_info()[1]
            print(f"[!] {pkg}: {exc if isinstance(exc, ToolError) else 'Không đọc/ghi được file.'}")
    print(f"[+] Đã cập nhật phiên và mở {done}/{len(pairs)} app.")


def save_export(records, folder, user_id, day=None):
    day = day or dt.datetime.now().strftime("%y%m%d")
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = folder / f"cookie_export_{day}.txt"
    # A lock prevents concurrent runs from losing another export in the same day.
    lock = folder / ".export.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise ToolError("Đang có phiên xuất khác; nếu lần trước bị tắt đột ngột, xóa .export.lock rồi thử lại.") from None
    try:
        os.close(fd)
        merged = {}
        if target.exists():
            header = target.read_text(encoding="utf-8").splitlines()[:2]
            if f"# Android user: {user_id}" not in header:
                raise ToolError("File xuất hôm nay thuộc Android user khác; không ghi đè.")
            old_rows = read_cookie_file(target)
            if any(not row.package for row in old_rows):
                raise ToolError("File xuất cũ thiếu ánh xạ package; đổi tên file cũ rồi xuất lại.")
            merged.update({row.package: row for row in old_rows})
        merged.update(records)
        content = f"# Android user: {user_id}\n# tk:mk:cookie; dòng # package giữ ánh xạ khi nhập lại\n"
        for pkg, entry in merged.items():
            if not package_ok(pkg) or entry.package != pkg:
                raise ToolError("Package xuất không hợp lệ.")
            if not entry.username:
                raise ToolError("File xuất cũ còn acc thiếu tk/mk; xuất lại tất cả hoặc đổi tên file cũ trước.")
            password = normalize_password(entry.password)
            check_account_fields(entry.username, password)
            value = normalize_cookie(entry.cookie)
            content += f"# package: {pkg}\n{entry.username}:{password}:{value}\n"
        atomic_text(target, content)
    finally:
        lock.unlink(missing_ok=True)
    return target


def export_cookies(packages, user_id):
    print("\n1. Xuất acc chọn\n2. Xuất tất cả acc đã nhập ở mục 1\n0. Quay lại")
    mode = input("Chọn: ").strip()
    if mode == "0":
        return
    if mode not in ("1", "2"):
        raise ToolError("Chọn 1, 2 hoặc 0.")
    selected = select_packages(packages) if mode == "1" else packages
    if not selected:
        return
    accounts = load_account_data()["users"].get(str(user_id), {})
    records = {}
    for pkg in selected:
        try:
            cookie = normalize_cookie(worker_request("export", pkg, user_id)["cookie"])
            entry = export_account(pkg, user_id, cookie, accounts)
            if entry is None:
                print(f"[*] Bỏ qua {pkg}.")
                continue
            records[pkg] = entry
            print(f"[OK] Đã đọc cookie: {pkg}")
        except (ToolError, OSError) as exc:
            print(f"[!] {pkg}: {exc if isinstance(exc, ToolError) else 'Không lưu được tk/mk.'}")
    if records:
        target = save_export(records, BASE / "cookie_export", user_id)
        print(f"[+] Đã xuất {len(records)}/{len(selected)} acc vào: {target}")
    elif selected:
        print("[!] Không có cookie hợp lệ để xuất; không tạo file rỗng.")


def main():
    print("=" * 60)
    print(" Android 10 Root — Package Grid + Roblox Cookie")
    print("=" * 60)
    if os.name != "posix":
        raise ToolError("Chạy file này trên Android bằng Termux Python, không phải Windows.")
    if "uid=0" not in android(["id"]):
        raise ToolError("Hãy cấp quyền su cho Termux.")
    user_id = current_user()
    packages = load_packages(user_id)
    while True:
        print(f"\nAndroid user: {user_id} | Đã nhập: {len(packages)} package")
        print("1. Nhập/chọn package\n2. Mở tất cả + xếp lưới\n3. Login with cookie (cookie.txt)\n4. Xuất cookie\n0. Thoát")
        try:
            choice = input("Chọn tính năng: ").strip()
            if choice == "0":
                return
            active_user = current_user()
            if active_user != user_id:
                user_id, packages = active_user, load_packages(active_user)
                print("[*] Android user đã đổi; đã nạp lại danh sách package.")
            if choice == "1":
                selected = import_packages(user_id)
                if selected:
                    packages = selected
            elif choice in ("2", "3", "4"):
                if not packages:
                    raise ToolError("Nhập package ở mục 1 trước.")
                {"2": open_grid, "3": login_cookies, "4": export_cookies}[choice](packages, user_id)
            else:
                print("[!] Chọn số từ 0 đến 4.")
        except ToolError as exc:
            print(f"[!] {exc}")
        except (OSError, UnicodeError, ValueError):
            print("[!] Không đọc/ghi được dữ liệu; kiểm tra file, quyền truy cập và định dạng.")
        except KeyboardInterrupt:
            print("\n[*] Đã hủy thao tác; quay lại menu.")
        except EOFError:
            return


if __name__ == "__main__":
    if sys.argv[1:] == ["--cookie-worker"]:
        try:
            payload = json.loads(sys.stdin.read(MAX_FILE + 1))
            result = cookie_worker(payload)
            print(json.dumps({"ok": True, **result}))
        except BaseException as exc:
            print(json.dumps({"ok": False, "error": str(exc) if isinstance(exc, ToolError)
                              else "Không xử lý được kho cookie (quyền truy cập hoặc định dạng)."}))
            sys.exit(1)
    else:
        try:
            main()
        except ToolError as exc:
            print(f"[!] {exc}")
            sys.exit(1)
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Đã thoát.")
