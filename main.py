import os
import time
import hmac
import hashlib
import base64
import json
from datetime import datetime, timezone
import random

import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import gunicorn

# Carrega variáveis de ambiente
load_dotenv()

# --- Configurações Iniciais ---
CLIENT_ID = os.getenv("TUYA_CLIENT_ID")
CLIENT_SECRET = os.getenv("TUYA_CLIENT_SECRET")
DEVICE_ID = os.getenv("TUYA_DEVICE_ID")
API_BASE_URL = "https://openapi.tuyaus.com"

# Força o Python a mostrar os prints imediatamente nos logs
os.environ['PYTHONUNBUFFERED'] = '1'

app = Flask(__name__ )

class TuyaLockManager:
    def __init__(self, client_id, client_secret, device_id, api_base_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.device_id = device_id
        self.api_base_url = api_base_url
        self.token_info = {}

    def _get_headers(self, path, method, body=""):
        timestamp = str(int(time.time() * 1000))
        access_token = self.token_info.get("access_token", "")
        content_sha256 = hashlib.sha256(body.encode('utf-8')).hexdigest()
        string_to_sign = f"{self.client_id}{access_token}{timestamp}{method}\n{content_sha256}\n\n{path}"
        sign = hmac.new(self.client_secret.encode('utf-8'), msg=string_to_sign.encode('utf-8'), digestmod=hashlib.sha256).hexdigest().upper()
        return {"client_id": self.client_id, "sign": sign, "t": timestamp, "sign_method": "HMAC-SHA256", "access_token": access_token, "Content-Type": "application/json"}

    def _refresh_token(self):
        path = "/v1.0/token?grant_type=1"
        headers = self._get_headers(path, "GET")
        headers.pop("access_token")
        response = requests.get(f"{self.api_base_url}{path}", headers=headers)
        response.raise_for_status()
        data = response.json()
        if not data.get("success"): raise Exception(f"Falha ao obter token: {data.get('msg')}")
        self.token_info = data["result"]
        self.token_info['expire_time'] = int(time.time()) + self.token_info.get('expire', 7200)
        return True

    def _api_request(self, method, path, body=None):
        if not self.token_info or self.token_info.get("expire_time", 0) < int(time.time()) + 60: self._refresh_token()
        body_str = json.dumps(body) if body else ""
        headers = self._get_headers(path, method, body_str)
        url = f"{self.api_base_url}{path}"
        print(f"--- DEBUG URL SENDING: {method} {url}")
        response = requests.post(url, headers=headers, data=body_str) if method == "POST" else requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        print(f"--- DEBUG RAW RESPONSE FROM TUYA: {data}")
        if not data.get("success"):
            if data.get('code') == 1010:
                self._refresh_token()
                return self._api_request(method, path, body)
            raise Exception(f"Erro na API Tuya: {data.get('msg')} (código: {data.get('code')})")
        return data.get("result")

    def create_temporary_password(self, name, start_time_str, end_time_str):
        # Endpoint correto para modificar DPs (propriedades)
        path = f"/v2.0/cloud/thing/{self.device_id}/shadow/properties/issue"
        
        # Gerar uma senha aleatória de 6 dígitos
        password = str(random.randint(100000, 999999))
        # Gerar um ID de usuário aleatório entre 101 e 200 (faixa comum para temporários)
        user_id = random.randint(101, 200)

        # Formato do DP 11 que você encontrou!
        dp11_value = {
            "op": "add",
            "id": user_id,
            "code": password,
            "name": name,
            "validity": {
                "start_time": start_time_str.replace(" ", "T"), # Formato ISO 8601
                "end_time": end_time_str.replace(" ", "T")
            }
        }

        # O body final envia o DP 11 com seu valor em formato JSON (string)
        body_final = {
            "properties": {
                "11": json.dumps(dp11_value)
            }
        }
        
        print(f"--- DEBUG: Enviando para {path} com o body: {json.dumps(body_final)}")
        result = self._api_request("POST", path, body=body_final)
        
        if result.get("success"):
            return {"password": password, "user_id": user_id, "name": name, "start_time": start_time_str, "end_time": end_time_str}
        else:
            raise Exception(f"Falha ao emitir propriedade: {result}")

if not all([CLIENT_ID, CLIENT_SECRET, DEVICE_ID]): raise RuntimeError("As variáveis de ambiente não foram configuradas.")
lock_manager = TuyaLockManager(CLIENT_ID, CLIENT_SECRET, DEVICE_ID, API_BASE_URL)

@app.route("/v1/passwords/temporary", methods=["POST"])
def handle_create_password():
    print("--- ROTA /v1/passwords/temporary ACIONADA ---")
    data = request.get_json()
    if not data or "name" not in data or "start_time" not in data or "end_time" not in data:
        return jsonify({"error": "Campos obrigatórios ausentes."}), 400
    try:
        password_info = lock_manager.create_temporary_password(data["name"], data["start_time"], data["end_time"])
        print("--- SUCESSO: Senha criada.")
        return jsonify({"success": True, "data": password_info}), 201
    except Exception as e:
        print(f"--- ERRO NA EXECUÇÃO: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/health", methods=["GET"])
def health_check(): return jsonify({"status": "ok"}), 200

if __name__ == "__main__": app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)))
