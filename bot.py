import base64
import json
import requests
from datetime import datetime, timedelta
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

REPO_OWNER = "htxcorps-a11y"
REPO_NAME = "HTXDEVICEACTIVATION"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
BOT_TOKEN = os.environ.get("BOT_TOKEN")
KEYS_FILE_PATH = "Userinfo.json"
LIMITS_FILE = "limits.json"
USERS_FILE_PATH = "users.json"
UPDATE_FILE_PATH = "update.json"
ADMIN_USER_ID = 7653387182

user_cooldowns = {}
COOLDOWN_SECONDS = 10

headers = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

def get_file_sha(file_path):
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path}"
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return r.json().get("sha")
    return None

def update_limits_file(new_data: dict):
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{LIMITS_FILE}"
    sha = get_file_sha(LIMITS_FILE)
    content = base64.b64encode(json.dumps(new_data, indent=2).encode()).decode()
    data = {
        "message": "Update limits.json",
    "content": content,
        "sha": sha
    }
    r = requests.put(url, headers=headers, json=data)
    return r.status_code in [200, 201]

def get_keys():
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{KEYS_FILE_PATH}"
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        content = r.json().get('content')
        decoded = base64.b64decode(content).decode()
        return json.loads(decoded), r.json().get('sha')
    return [], None

def update_keys(keys, sha):
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{KEYS_FILE_PATH}"
    content = base64.b64encode(json.dumps(keys, indent=2).encode()).decode()
    data = {
    "message": "Update keys",
        "content": content,
        "sha": sha
    }
    r = requests.put(url, headers=headers, json=data)
    return r.status_code in [200, 201]

def load_json_from_github(filepath):
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{filepath}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        content = response.json()["content"]
        decoded = base64.b64decode(content).decode("utf-8")
        return json.loads(decoded)
    else:
        print(f"Failed to load {filepath}:", response.text)
        return {}

def save_json_to_github(filepath, data, commit_message):
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{filepath}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    # Get the current file SHA (required for update)
    get_resp = requests.get(url, headers=headers)
    if get_resp.status_code != 200:
        print("Error fetching SHA:", get_resp.text)
        return False

    sha = get_resp.json()["sha"]
    encoded_content = base64.b64encode(json.dumps(data, indent=2).encode()).decode()

    payload = {
        "message": commit_message,
        "content": encoded_content,
        "sha": sha
    }

    put_resp = requests.put(url, headers=headers, json=payload)
    return put_resp.status_code == 200 or put_resp.status_code == 201

def is_on_cooldown(user_id):
    now = datetime.now()
    last_used = user_cooldowns.get(user_id)
    if last_used and now - last_used < timedelta(seconds=COOLDOWN_SECONDS):
        return True
    user_cooldowns[user_id] = now
    return False

def load_limits():
    return load_json_from_github(LIMITS_FILE)

def save_limits(data):
    return save_json_to_github(LIMITS_FILE, data, "Update limits file")

def load_keys():
    data = load_json_from_github(KEYS_FILE_PATH)
    if not isinstance(data, list):
        return []  # fallback in case file is corrupted or empty
    return data

def save_keys(data):
    return save_json_to_github(KEYS_FILE_PATH, data, "Update keys file")

def load_users():
    data = load_json_from_github(USERS_FILE_PATH)
    if not isinstance(data, list):
        return []
    return data

def save_users(data):
    return save_json_to_github(USERS_FILE_PATH, data, "Update users.json")

def load_update_info():
    return load_json_from_github(UPDATE_FILE_PATH)

def save_update_info(data):
    return save_json_to_github(UPDATE_FILE_PATH, data, "Update app version info")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome to the Key Management Bot!")

async def add_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    args = context.args

    if user_id == str(ADMIN_USER_ID):
        # Admin usage: expects 4 args: device_id, key, validity_days, allow_offline
        if len(args) != 4:
            await update.message.reply_text("Usage: /addkey <device_id> <key> <validity_days> <allow_offline(True/False)>")
            return
        device_id, key, validity_days, allow_offline = args
        try:
            validity_days = int(validity_days)  # Convert validity to int days
        except ValueError:
            await update.message.reply_text("Validity days must be a number.")
            return
        allow_offline = allow_offline.lower() == "true"
        expiry = (datetime.now() + timedelta(days=validity_days)).strftime("%d-%m-%Y")

        # Load from GitHub
        keys = load_keys()
        keys.append({
            "device_id": device_id,
            "key": key,
            "expirydate": expiry,
            "Allowoffline": allow_offline,
            "added_by": user_id,
            "validity_days": validity_days
        })

        if save_keys(keys):
            msg = (
                f"✅ Key added successfully:\n"
                f"Device ID: {device_id}\n"
                f"Key: {key}\n"
                f"Validity: {validity_days} days (Expires: {expiry})\n"
                f"Allow Offline: {allow_offline}"
            )
            await update.message.reply_text(msg)
        else:
            await update.message.reply_text("❌ Failed to update keys on GitHub.")

    else:
        if len(args) != 3:
            await update.message.reply_text("Usage: /addkey <device_id> <key> <validity_days>")
            return

        device_id, key, validity_days = args

        try:
            validity_days = int(validity_days)
        except ValueError:
            await update.message.reply_text("Validity days must be a number.")
            return

        limits = load_limits()
        user_data = limits.get("users", {}).get(user_id)

        if not user_data:
            await update.message.reply_text("No limits found for you. Contact admin.")
            return

        if user_data.get("banned", False):
            await update.message.reply_text("You are banned from using this bot.")
            return

        user_limits = user_data.get("limits", [])
        matching_entry = next((entry for entry in user_limits if entry.get("valid_days") == validity_days), None)

        if not matching_entry:
            allowed = [entry.get("valid_days") for entry in user_limits]
            await update.message.reply_text(f"Allowed validity days: {allowed}")
            return

        if matching_entry.get("key_used", 0) >= matching_entry.get("max_keys", 0):
            await update.message.reply_text("You've used all your keys for this validity.")
            return

        expiry = (datetime.now() + timedelta(days=validity_days)).strftime("%d-%m-%Y")

        # Load keys (userinfo) from GitHub
        keys = load_keys()
        keys.append({
            "device_id": device_id,
            "key": key,
            "expirydate": expiry,
            "Allowoffline": False,  # Always false for normal users
            "added_by": user_id,
            "validity_days": validity_days
        })

        # Update usage
        matching_entry["key_used"] = matching_entry.get("key_used", 0) + 1

        # Save updates
        save_keys(keys)
        save_limits(limits)

        await update.message.reply_text(f"✅ Key added!\nDevice ID: {device_id}\nKey: {key}\nValidity: {validity_days} days (Expires: {expiry})"
        )

async def listkeys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)

    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("You are not authorized to use this command.")
        return

    keys = load_keys()
    if not keys:
        await update.message.reply_text("No keys found.")
        return

    messages = []
    for i, k in enumerate(keys, 1):
        key_info = (
            f"{i}. 🔑 *Key Info:*\n"
            f"• *Device ID:* `{k['device_id']}`\n"
            f"• *Key:* `{k['key']}`\n"
            f"• *Expiry:* `{k['expirydate']}`\n"
            f"• *Validity:* `{k['validity_days']} days`\n"
            f"• *Offline Allowed:* `{k['Allowoffline']}`\n"
            f"• *Added by:* `{k['added_by']}`"
        )
        messages.append(key_info)

    for chunk in split_messages(messages, max_chars=4000):
        await update.message.reply_text(chunk, parse_mode="Markdown")

def split_messages(lines, max_chars=4000):
    chunks = []
    current = ""
    for line in lines:
        if len(current) + len(line) + 2 > max_chars:
            chunks.append(current)
            current = line + "\n\n"
        else:
            current += line + "\n\n"
    if current:
        chunks.append(current)
    return chunks

async def userkeys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("You are not authorized to use this command.")
        return

    if not context.args:
        await update.message.reply_text("Usage: /userkeys <user_id>")
        return

    filter_id = context.args[0]
    keys = load_keys()
    filtered = [k for k in keys if k["added_by"] == filter_id]

    if not filtered:
        await update.message.reply_text(f"No keys found for user ID {filter_id}.")
        return

    messages = []
    for i, k in enumerate(filtered, 1):
        key_info = (
            f"{i}. 🔑 *Key Info:*\n"
            f"• *Device ID:* `{k['device_id']}`\n"
            f"• *Key:* `{k['key']}`\n"
            f"• *Expiry:* `{k['expirydate']}`\n"
            f"• *Validity:* `{k['validity_days']} days`\n"
            f"• *Offline Allowed:* `{k['Allowoffline']}`"
        )
        messages.append(key_info)

    for chunk in split_messages(messages):
        await update.message.reply_text(chunk, parse_mode="Markdown")

async def myid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    await update.message.reply_text(f"Your Telegram user ID is: {user_id}")

async def set_limit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    args = context.args
    if len(args) != 4:
        await update.message.reply_text("Usage: /setlimit <telegram_user_id> <max_keys> <valid_days> <period_days>")
        return

    try:
        target_user = args[0]
        max_keys = int(args[1])
        valid_days = int(args[2])
        period_days = int(args[3])
    except ValueError:
        await update.message.reply_text("Please enter valid numbers for max_keys, valid_days, and period_days.")
        return

    limits_data = load_limits()

    from datetime import datetime
    start_date = datetime.now().strftime("%Y-%m-%d")

    # Ensure 'users' key exists
    if "users" not in limits_data:
        limits_data["users"] = {}

    # Set or update the user limits with the new structure
    limits_data["users"][target_user] = {
        "banned": False,
        "limits": [
            {
                "max_keys": max_keys,
                "valid_days": valid_days,
                "start_date": start_date,
                "period_days": period_days,
                "key_used": 0
            }
        ]
    }

    save_limits(limits_data)

    await update.message.reply_text(f"✅ Limit set successfully for user {target_user} and updated on GitHub.")

async def delkey(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("Only admin can delete keys.")
        return

    args = context.args
    if len(args) != 1:
        await update.message.reply_text("Usage: /delkey <key>")
        return

    key_to_delete = args[0]
    keys = load_keys()
    new_keys = [k for k in keys if k.get("key") != key_to_delete]

    if len(keys) == len(new_keys):
        await update.message.reply_text("Key not found.")
        return

    if save_keys(new_keys):
        await update.message.reply_text("Key deleted successfully.")
    else:
        await update.message.reply_text("Failed to delete key.")

async def my_keys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if is_on_cooldown(user_id):
        await update.message.reply_text("⏳ Please wait a few seconds before using this command again.")
        return
    keys = load_keys()
    now = datetime.now()

    user_keys = [k for k in keys if k.get("added_by") == user_id]

    if not user_keys:
        await update.message.reply_text("You haven't added any keys yet.")
        return

    msg = ""
    for idx, k in enumerate(user_keys, start=1):
        key = k.get("key", "N/A")
        expiry_str = k.get("expirydate", "N/A")
        validity = k.get("validity_days", "N/A")

        try:
            expiry_date = datetime.strptime(expiry_str, "%d-%m-%Y")
            days_left = (expiry_date - now).days
            if days_left < 0:
                left = "(expired)"
            elif days_left == 0:
                left = "(expires today)"
            else:
                left = f"({days_left} days left)"
        except:
            left = ""

        msg += f"{idx}. 🔑 *Key Info:*\n"
        msg += f"• Key: `{key}`\n"
        msg += f"• Expiry: *{expiry_str}* {left}\n"
        msg += f"• Validity: *{validity} days*\n\n"

    await update.message.reply_text(msg.strip(), parse_mode="Markdown")

async def renew_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)

    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("Only the admin can use this command.")
        return

    args = context.args
    if len(args) != 2:
        await update.message.reply_text("Usage: /renewkey <key> <extra_days>")
        return

    key_input, extra_days = args
    try:
        extra_days = int(extra_days)
    except ValueError:
        await update.message.reply_text("Extra days must be a number.")
        return

    keys = load_keys()
    updated = False

    try:
        for k in keys:
            if k["key"] == key_input:
                current_expiry = datetime.strptime(k["expirydate"], "%d-%m-%Y")
                new_expiry = current_expiry + timedelta(days=extra_days)
                k["expirydate"] = new_expiry.strftime("%d-%m-%Y")
                updated = True
                break

        if updated and save_keys(keys):
            await update.message.reply_text("Key renewed successfully.")
        else:
            await update.message.reply_text("Key not found or renewal failed.")
    except Exception as e:await update.message.reply_text(f"Error: {str(e)}")

async def myinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if is_on_cooldown(user_id):
        await update.message.reply_text("⏳ Please wait a few seconds before using this command again.")
        return
    limits = load_limits()
    user_data = limits.get("users", {}).get(user_id)

    if not user_data:
        await update.message.reply_text("❌ No data found for you.")
        return

    entries = user_data.get("limits", [])

    if not entries:
        await update.message.reply_text("⚠️ No active limit entries found.")
        return

    msg = f"👤 *Your Info*\n\n"

    for idx, entry in enumerate(entries, 1):
        max_keys = entry.get("max_keys", 0)
        used = entry.get("key_used", 0)
        remaining = max(0, max_keys - used)

        start_date = datetime.strptime(entry["start_date"], "%Y-%m-%d")
        period_days = entry.get("period_days", 0)
        expiry_date = start_date + timedelta(days=period_days)
        days_left = max(0, (expiry_date - datetime.now()).days)
        status = "Expired" if days_left == 0 else "Active"

        msg += f"*📦 Entry {idx}:*\n"
        msg += f"🔢 Max Keys: {max_keys}\n"
        msg += f"🕒 Key Validity: {entry.get('valid_days')} days\n"
        msg += f"✅ Keys Used: {used}/{max_keys}\n"
        msg += f"🔓 Keys Remaining: {remaining}/{max_keys}\n"
        msg += f"📅 Start Date: {entry['start_date']}\n"
        msg += f"📆 Expiry Date: {expiry_date.strftime('%d-%m-%Y')}\n"
        msg += f"⏳ Days Remaining: {days_left}\n"
        msg += f"📌 Status: {status}\n\n"

    await update.message.reply_text(msg, parse_mode="Markdown")

async def edit_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("You are not authorized to use this command.")
        return

    args = context.args
    if len(args) != 4:
        await update.message.reply_text("Usage: /editkey <device_id> <new_key> <validity_days> <allow_offline(True/False)>")
        return

    device_id, new_key, validity_days_str, allow_offline_str = args

    try:
        validity_days = int(validity_days_str)
    except ValueError:
        await update.message.reply_text("Validity days must be a number.")
        return

    allow_offline = allow_offline_str.lower() == "true"
    expiry = (datetime.now() + timedelta(days=validity_days)).strftime("%d-%m-%Y")

    keys = load_keys()
    for key_entry in keys:
        if key_entry.get("device_id") == device_id:
            key_entry["key"] = new_key
            key_entry["expirydate"] = expiry
            key_entry["Allowoffline"] = allow_offline
            break
    else:
        await update.message.reply_text("Device ID not found.")
        return

    if save_keys(keys):
        await update.message.reply_text("Key updated successfully.")
    else:
        await update.message.reply_text("Failed to update key.")

async def add_max_keys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    args = context.args

    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("You are not authorized to use this command.")
        return

    if len(args) != 4:
        await update.message.reply_text("Usage: /addmaxkeys <user_id> <additional_keys> <valid_days> <additional_period_days>")
        return

    target_user_id, add_keys, valid_days, add_period_days = args

    try:
        add_keys = int(add_keys)
        valid_days = int(valid_days)
        add_period_days = int(add_period_days)
    except ValueError:
        await update.message.reply_text("Keys, validity days and period days must be integers.")
        return

    limits_data = load_limits()
    users = limits_data.get("users", {})

    # Ensure target user exists
    if target_user_id not in users:
        users[target_user_id] = {
            "banned": False,
            "limits": []
        }

    user_data = users[target_user_id]
    user_limits = user_data.get("limits", [])
    today = datetime.now().strftime("%Y-%m-%d")

    # Try to merge with existing entry with same valid_days
    merged = False
    for entry in user_limits:
        if entry.get("valid_days") == valid_days:
            entry["max_keys"] = entry.get("max_keys", 0) + add_keys
            entry["period_days"] = entry.get("period_days", 0) + add_period_days

            # Update start_date if missing or future
            if not entry.get("start_date") or datetime.strptime(entry["start_date"], "%Y-%m-%d") > datetime.now():
                entry["start_date"] = today

            merged = True
            break

    if not merged:
        user_limits.append({
            "max_keys": add_keys,
            "valid_days": valid_days,
            "start_date": today,
            "period_days": add_period_days,
            "key_used": 0
        })

    # Save back to GitHub
    users[target_user_id]["limits"] = user_limits
    limits_data["users"] = users
    save_limits(limits_data)

    await update.message.reply_text(f"✅ Added {add_keys} keys with {valid_days} days validity and {add_period_days} period days "
        f"for user {target_user_id}."
    )

async def user_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    args = context.args

    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    if len(args) != 1:
        await update.message.reply_text("Usage: /userinfo <user_id>")
        return

    target_user_id = args[0]
    limits = load_limits()
    user_data = limits.get("users", {}).get(target_user_id)

    if not user_data:
        await update.message.reply_text("No data found for this user.")
        return

    banned = user_data.get("banned", False)
    status_text = f"ℹ️ User Info for {target_user_id}:\n🚫 Banned: {'Yes' if banned else 'No'}\n\n"

    for entry in user_data.get("limits", []):
        start_date = datetime.strptime(entry["start_date"], "%Y-%m-%d")
        expiry_date = start_date + timedelta(days=entry["period_days"])
        days_left = (expiry_date - datetime.now()).days

        status = "Expired" if days_left < 0 else "Active"
        days_left_display = "Expired" if days_left < 0 else f"{days_left} days"

        status_text += (
            f"🔹 Validity: {entry['valid_days']} days\n"
            f"🗓️ Start: {entry['start_date']}\n"
            f"📅 Expiry: {expiry_date.strftime('%Y-%m-%d')}\n"
            f"⏳ Days Left: {days_left_display}\n"
            f"🔑 Keys Used: {entry.get('key_used', 0)} / {entry.get('max_keys', 0)}\n"
            f"✅ Status: {status}\n\n"
        )

    await update.message.reply_text(status_text.strip())

async def ban_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    args = context.args

    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("You are not authorized to use this command.")
        return

    if len(args) != 1:
        await update.message.reply_text("Usage: /ban <user_id>")
        return

    target_user = args[0]
    limits = load_limits()
    users = limits.get("users", {})

    if target_user not in users:
        await update.message.reply_text(f"User {target_user} not found.")
        return

    users[target_user]["banned"] = True
    save_limits(limits)
    await update.message.reply_text(f"User {target_user} has been banned.")

async def unban_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    args = context.args

    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("You are not authorized to use this command.")
        return

    if len(args) != 1:
        await update.message.reply_text("Usage: /unban <user_id>")
        return

    target_user = args[0]
    limits = load_limits()
    users = limits.get("users", {})

    if target_user not in users:
        await update.message.reply_text(f"User {target_user} not found.")
        return

    users[target_user]["banned"] = False
    save_limits(limits)
    await update.message.reply_text(f"User {target_user} has been unbanned.")

async def list_users_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)

    # Check admin
    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    # Load user data
    users_data = load_limits()
    user_ids = users_data.get("users", {}).keys()
    user_list = "\n".join(user_ids)

    # Send message
    await update.message.reply_text(f"Registered Users id:\n{user_list}")

async def list_banned_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)

    # Check admin
    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    # Load user data
    users_data = load_limits()
    banned_user_ids = [
        uid for uid, info in users_data.get("users", {}).items()
        if isinstance(info, dict) and info.get("banned", False)
    ]

    if not banned_user_ids:
        await update.message.reply_text("No banned users found.")
        return

    banned_list = "\n".join(banned_user_ids)

    # Send message
    await update.message.reply_text(f"Banned Users:\n{banned_list}")

async def extend_all_keys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    args = context.args
    if len(args) != 1:
        await update.message.reply_text("Usage: /extendall <days>")
        return

    try:
        add_days = int(args[0])
    except ValueError:
        await update.message.reply_text("Please enter a valid number of days.")
        return

    keys_data = load_keys()
    if not keys_data:
        await update.message.reply_text("No keys found to update.")
        return

    updated_count = 0
    for key_entry in keys_data:
        expiry_str = key_entry.get("expirydate")
        if not expiry_str:
            continue

        # Parse date, format is dd-mm-yyyy
        expiry_date = datetime.strptime(expiry_str, "%d-%m-%Y")
        if expiry_date < datetime.now():
            continue  # skip expired keys

        # Add days
        new_expiry = expiry_date + timedelta(days=add_days)
        key_entry["expirydate"] = new_expiry.strftime("%d-%m-%Y")
        updated_count += 1

    save_keys(keys_data)
    await update.message.reply_text(f"✅ Extended expiry by {add_days} days for {updated_count} keys.")

async def mykeyinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if is_on_cooldown(user_id):
        await update.message.reply_text("⏳ Please wait a few seconds before using this command again.")
        return
    args = context.args

    if not args:
        await update.message.reply_text("Please provide a key. Example:\n`/mykeyinfo testkeyhtx`", parse_mode="Markdown")
        return

    key_input = args[0]
    keys = load_keys()
    now = datetime.now()

    key_info = next((k for k in keys if k.get("key") == key_input and k.get("added_by") == user_id), None)

    if not key_info:
        await update.message.reply_text("Key not found or you don't have access to it.")
        return

    expiry_str = key_info.get("expirydate", "N/A")
    validity = key_info.get("validity_days", "N/A")

    try:
        expiry_date = datetime.strptime(expiry_str, "%d-%m-%Y")
        days_left = (expiry_date - now).days
        if days_left < 0:
            left = "(expired)"
        elif days_left == 0:
            left = "(expires today)"
        else:
            left = f"({days_left} days left)"
    except:
        left = ""

    msg = (
        f"🔐 *Key Info:*\n"
        f"• Key: `{key_input}`\n"
        f"• Expiry: *{expiry_str}* {left}\n"
        f"• Validity: *{validity} days*"
    )

    await update.message.reply_text(msg, parse_mode="Markdown")

async def register(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)

    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("You are not authorized to register users.")
        return

    if len(context.args) < 3:
        await update.message.reply_text("Usage: /register <user_id> <name> <community>")
        return

    target_user_id = context.args[0]
    name = context.args[1]
    community = " ".join(context.args[2:])

    users = load_users()

    # Check if user is already registered
    for u in users:
        if u["user_id"] == target_user_id:
            await update.message.reply_text("User is already registered.")
            return

    new_user = {
        "user_id": target_user_id,
        "name": name,
        "community": community
    }

    users.append(new_user)
    save_users(users)

    msg = (
        "✅ *Registered user:*\n"
        f"        *Name*       : `{name}`\n"
        f"        *User ID*    : `{target_user_id}`\n"
        f"        *Community*  : `{community}`"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

async def find_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)

    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("You are not authorized to use this command.")
        return

    args = context.args
    if not args:
        await update.message.reply_text("Usage: /finduser <name|user_id|community>")
        return

    search_term = " ".join(args).lower()
    users = load_users()

    matches = [
        u for u in users if
        search_term in u.get("name", "").lower() or
        search_term in u.get("user_id", "") or
        search_term in u.get("community", "").lower()
    ]

    if not matches:
        await update.message.reply_text("No matching user found.")
        return

    msg = ""
    for i, u in enumerate(matches, 1):
        msg += (
            f"{i}. 👤 *User Info:*\n"
            f"• Name: `{u.get('name')}`\n"
            f"• User ID: `{u.get('user_id')}`\n"
            f"• Community: `{u.get('community')}`\n\n"
        )

    await update.message.reply_text(msg.strip(), parse_mode="Markdown")

async def list_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    users = load_users()
    if not users:
        await update.message.reply_text("No registered users found.")
        return

    msg = "*👥 Registered Users:*\n\n"
    for i, user in enumerate(users, start=1):
        msg += (
            f"{i}. 👤 *Name:* {user.get('name')}\n"
            f"   🆔 *User ID:* `{user.get('user_id')}`\n"
            f"   🌐 *Community:* {user.get('community')}\n\n"
        )

    await update.message.reply_text(msg, parse_mode="Markdown")

async def remove_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin_id = str(update.effective_user.id)
    if admin_id != str(ADMIN_USER_ID):
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Usage: /removeuser <user_id>")
        return

    target_user_id = context.args[0]
    users = load_users()

    updated_users = [u for u in users if u.get("user_id") != target_user_id]

    if len(updated_users) == len(users):
        await update.message.reply_text("⚠️ No user found with that ID.")
        return

    save_users(updated_users)
    await update.message.reply_text(f"✅ Removed user with ID: `{target_user_id}`", parse_mode="Markdown")

async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin_id = str(update.effective_user.id)
    if admin_id != str(ADMIN_USER_ID):
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    users = load_users()
    keys = load_keys()

    total_users = len(users)
    total_keys = len(keys)

    # Optional: Users per community
    community_count = {}
    for user in users:
        community = user.get("community", "Unknown")
        community_count[community] = community_count.get(community, 0) + 1

    msg = f"📊 *System Stats:*\n\n"
    msg += f"👤 Registered Users: *{total_users}*\n"
    msg += f"🔑 Total Keys: *{total_keys}*\n\n"

    msg += "🏘️ *Users by Community:*\n"
    for community, count in community_count.items():
        msg += f"• {community}: {count}\n"

    await update.message.reply_text(msg, parse_mode="Markdown")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    is_admin = user_id == str(ADMIN_USER_ID)

    msg = "🤖 *HTX Key Management Bot Help*\n\n"

    if is_admin:
        msg += (
            "👮‍♂️ *Admin Commands:*\n"
            "• /register `<name>` `<user_id>` `<community>` \\- Register a new user\n"
            "• /getkeys \\- View all keys\n"
            "• /userkeys `<user_id>` \\- View keys added by a user\n"
            "• /listusers \\- List all registered users\n"
            "• /viewuser `<query>` \\- Search users by ID, name, or community\n"
            "• /removeuser `<user_id>` \\- Remove a user\n"
            "• /stats \\- View bot usage statistics\n\n"
        )

    msg += (
        "👤 *User Commands:*\n"
        "• /mykeys \\- View your added keys\n"
        "• /mykeyinfo `<key>` \\- View info of a specific key you added"
    )

    await update.message.reply_text(msg, parse_mode="MarkdownV2")

async def set_version(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("You are not authorized to use this command.")
        return

    args = context.args
    if not args:
        await update.message.reply_text("Usage: /updateversion <version_number>")
        return

    try:
        new_version = int(args[0])
    except ValueError:
        await update.message.reply_text("Invalid version number. Please enter a numeric value.")
        return

    update_data = load_json_from_github("update.json") or {}
    update_data["latest_version"] = new_version

    if save_json_to_github("update.json", update_data, "Update latest version"):
        await update.message.reply_text(f"✅ Latest version updated to {new_version}")
    else:
        await update.message.reply_text("❌ Failed to update latest version.")

async def set_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if user_id != str(ADMIN_USER_ID):
        await update.message.reply_text("You are not authorized to use this command.")
        return

    if len(context.args) < 1:
        await update.message.reply_text("Usage: /seturl <download_url>")
        return

    url = context.args[0]
    data = load_update_info() or {}
    data["download_url"] = url

    if save_update_info(data):
        await update.message.reply_text("✅ Download URL updated.")
    else:
        await update.message.reply_text("❌ Failed to update download URL.")

def main():
    app = (ApplicationBuilder()
           .token(BOT_TOKEN)
           .build())
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("addkey", add_key))
    app.add_handler(CommandHandler("listkeys", listkeys))
    app.add_handler(CommandHandler("myid", myid))
    app.add_handler(CommandHandler("setlimit", set_limit))
    app.add_handler(CommandHandler("delkey", delkey))
    app.add_handler(CommandHandler("mykeys", my_keys))
    app.add_handler(CommandHandler("renewkey", renew_key))
    app.add_handler(CommandHandler("myinfo", myinfo))
    app.add_handler(CommandHandler("editkey", edit_key))
    app.add_handler(CommandHandler("addmaxkeys", add_max_keys))
    app.add_handler(CommandHandler("userinfo", user_info))
    app.add_handler(CommandHandler("ban", ban_user))
    app.add_handler(CommandHandler("unban", unban_user))
    app.add_handler(CommandHandler("listusersid", list_users_id))
    app.add_handler(CommandHandler("listbannedusers", list_banned_users))
    app.add_handler(CommandHandler("extendall", extend_all_keys))
    app.add_handler(CommandHandler("userkeys", userkeys))
    app.add_handler(CommandHandler("mykeyinfo", mykeyinfo))
    app.add_handler(CommandHandler("register", register))
    app.add_handler(CommandHandler("finduser", find_user))
    app.add_handler(CommandHandler("listusers", list_users))
    app.add_handler(CommandHandler("removeuser", remove_user))
    app.add_handler(CommandHandler("stats", stats))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("setversion", set_version))
    app.add_handler(CommandHandler("seturl", set_url))
    app.run_polling()

if __name__ == "__main__":
    main()
