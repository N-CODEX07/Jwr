import os
import binascii
import json
import logging
import warnings
from flask import Flask, jsonify, request
from flask_caching import Cache
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from colorama import init
from urllib3.exceptions import InsecureRequestWarning
import requests

import my_pb2
import output_pb2

# Environment variables (RECOMMENDED to use .env or OS envs)
AES_KEY = os.getenv("AES_KEY", "Yg&tc%DEuh6%Zc^8").encode()
AES_IV = os.getenv("AES_IV", "6oyZDr22E3ychjM%").encode()
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3")

# Suppress InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Logging
logging.basicConfig(level=logging.INFO)

# Init colorama
init(autoreset=True)

# Flask app setup
app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})


def get_token(password, uid):
    try:
        url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": CLIENT_SECRET,
            "client_id": "100067"
        }
        res = requests.post(url, headers=headers, data=data, timeout=10)
        if res.status_code == 200:
            token_json = res.json()
            if "access_token" in token_json and "open_id" in token_json:
                return token_json
        return None
    except Exception as e:
        logging.error("Failed to fetch token", exc_info=True)
        return None


def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)


def parse_response(content):
    response_dict = {}
    lines = content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict


@app.route('/token', methods=['POST'])
@cache.cached(timeout=25200, query_string=True)
def get_token_response():
    uid = request.form.get('uid')
    password = request.form.get('password')

    if not uid or not password:
        return jsonify({"error": "Both uid and password are required"}), 400

    token_data = get_token(password, uid)
    if not token_data:
        return jsonify({
            "uid": uid,
            "status": "invalid",
            "message": "Wrong UID or Password. Please check and try again.",
            "credit": "@YourStalkerbxby"
        }), 400

    game_data = my_pb2.GameData()
    # Sample data (keep or load dynamically if needed)
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth/lib/arm"
    game_data.field_76 = 1
    game_data.apk_info = "apk_hash|/data/app/com.dts.freefireth/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "base64_encryption_key=="
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    try:
        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
        edata = binascii.hexlify(encrypted_data).decode()

        url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; Android 9; ASUS_Z01QD)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }

        response = requests.post(url, data=bytes.fromhex(edata), headers=headers, verify=False)

        if response.status_code == 200:
            result_msg = output_pb2.Garena_420()
            try:
                result_msg.ParseFromString(response.content)
                response_dict = parse_response(str(result_msg))
                return jsonify({
                    "uid": uid,
                    "status": response_dict.get("status", "N/A"),
                    "token": response_dict.get("token", "N/A")
                }), 200
            except Exception as e:
                logging.error("Protobuf parsing failed", exc_info=True)
                return jsonify({
                    "uid": uid,
                    "error": f"Failed to deserialize the response: {str(e)}"
                }), 400
        else:
            return jsonify({
                "uid": uid,
                "error": f"Login request failed: HTTP {response.status_code} {response.reason}"
            }), 400
    except Exception as e:
        logging.error("Critical server error", exc_info=True)
        return jsonify({
            "uid": uid,
            "error": f"Internal server error: {str(e)}"
        }), 500


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
