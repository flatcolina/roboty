import os
import time
import hmac
import hashlib
import base64
import json
from datetime import datetime, timezone

import requests
from Crypto.Cipher import AES
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import gunicorn

# Carrega variáveis de ambiente (para desenvolvimento local, se houver .env)
load_dotenv()

# --- Configurações Iniciais ---
# Estas variáveis serão lidas do ambiente do Railway
CLIENT_ID = os.getenv("TUYA_CLIENT_ID")
CLIENT_SECRET = os.getenv("TUYA_CLIENT_SECRET")
DEVICE_ID = os.getenv("TUYA_DEVICE_ID")
# Região do seu Data Center (Western America)
API_BASE_URL = "https://openapi.tuyaus.com"

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
        
        sign = hmac.new(
            self.client_secret.encode('utf-8'),
            msg=string_to_sign.encode('utf-8'),
            digestmod=hashlib.sha256
        ).hexdigest().upper()

        return {
            "client_id": self.client_id,
            "sign": sign,
            "t": timestamp,
            "sign_method": "HMAC-SHA256",
            "access_token": access_token,
            "Content-Type": "application/json"
        }

    def _refresh_token(self):
        path = "/v1.0/token?grant_type=1"
        # Para a chamada de token, o access_token está vazio
        headers = self._get_headers(path, "GET")
        headers.pop("access_token")

        response = requests.get(f"{self.api_base_url}{path}", headers=headers)
        response.raise_for_status()
        
        data = response.json()
        if not data.get("success"):
            raise Exception(f"Falha ao obter token: {data.get('msg')}")
            
        self.token_info = data["result"]
        # O token da Tuya expira em 7200 segundos (2 horas)
        self.token_info['expire_time'] = int(time.time()) + self.token_info.get('expire', 7200)
        return True

    def _api_request(self, method, path, body=None):
        # Verifica se o token existe ou se está prestes a expirar
        if not self.token_info or self.token_info.get("expire_time", 0) < int(time.time()) + 60:
            self._refresh_token()

        body_str = json.dumps(body) if body else ""
        headers = self._get_headers(path, method, body_str)
        
        url = f"{self.api_base_url}{path}"
        print(f"--- DEBUG URL SENDING: {method} {url}") # Garanta que esta linha exista
        
        if method == "GET":
            response = requests.get(url, headers=headers)
        elif method == "POST":
            response = requests.post(url, headers=headers, data=body_str)
        else:
            raise ValueError(f"Método HTTP não suportado: {method}")

        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            # Se o token expirou, tenta renovar e refazer a chamada uma vez
            if data.get('code') == 1010:
                self._refresh_token()
                return self._api_request(method, path, body)
            raise Exception(f"Erro na API Tuya: {data.get('msg')} (código: {data.get('code')})")
            
        return data.get("result")

    def create_temporary_password(self, name, start_time_str, end_time_str):
        # 1. Obter o ticket
        path_ticket = f"/v1.0/devices/{self.device_id}/door-lock/password-ticket"
        ticket_response = self._api_request("POST", path_ticket, body={})
        
        ticket_id = ticket_response["ticket_id"]
        
        # 2. Criar a senha temporária
        start_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
        end_dt = datetime.strptime(end_time_str, "%Y-%m-%d %H:%M:%S")
        
        effective_time = int(start_dt.timestamp())
        invalid_time = int(end_dt.timestamp())

        password_payload = {
            "name": name,
            "password_type": "temporary",
            "effective_time": effective_time,
            "invalid_time": invalid_time,
            "ticket_id": ticket_id
        }
        
        path_password = f"/v1.0/devices/{self.device_id}/door-lock/temporary-password"
        
        result = self._api_request("POST", path_password, body=password_payload)
        
        return {
            "id": result["id"],
            "password": result["password"],
            "name": name,
            "effective_time": datetime.fromtimestamp(effective_time).isoformat(),
            "invalid_time": datetime.fromtimestamp(invalid_time).isoformat()
        }

# Verifica se as variáveis de ambiente essenciais foram carregadas
if not all([CLIENT_ID, CLIENT_SECRET, DEVICE_ID]):
    raise RuntimeError("As variáveis de ambiente TUYA_CLIENT_ID, TUYA_CLIENT_SECRET, e TUYA_DEVICE_ID não foram configuradas.")

lock_manager = TuyaLockManager(CLIENT_ID, CLIENT_SECRET, DEVICE_ID, API_BASE_URL)

@app.route("/v1/passwords/temporary", methods=["POST"])
@app.route("/v1/passwords/temporary", methods=["POST"])
def handle_create_password():
    app.logger.info("--- ROTA /v1/passwords/temporary ACIONADA ---") # LINHA NOVA
    data = request.get_json()
    if not data or "name" not in data or "start_time" not in data or "end_time" not in data:
        app.logger.error("--- ERRO: Payload inválido.") # LINHA NOVA
        return jsonify({"error": "Campos 'name', 'start_time' (YYYY-MM-DD HH:MM:SS) e 'end_time' (YYYY-MM-DD HH:MM:SS) são obrigatórios."}), 400

    try:
        name = data["name"]
        start_time = data["start_time"]
        end_time = data["end_time"]
        
        password_info = lock_manager.create_temporary_password(name, start_time, end_time)
        
        app.logger.info("--- SUCESSO: Senha criada.") # LINHA NOVA
        return jsonify({"success": True, "data": password_info}), 201
        
    except Exception as e:
        app.logger.error(f"--- ERRO NA EXECUÇÃO: {e}") # LINHA NOVA
        return jsonify({"success": False, "error": str(e)}), 500
        
       
        
    except Exception as e:
        # Log do erro para depuração no Railway
        print(f"Ocorreu um erro: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)
