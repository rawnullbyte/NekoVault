from utils.database import Database
import utils.ssl_gen
import utils.crypto
import asyncio
import websockets
import ssl
import json
import os
from pathlib import Path

db = Database()

CERT_FILE = "./cert/cert.pem"
KEY_FILE = "./cert/key.pem"

if not Path(CERT_FILE).exists() or not Path(KEY_FILE).exists():
    print("Generating self-signed certificate...")
    utils.ssl_gen.generate_cert(CERT_FILE, KEY_FILE)

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

class ClientSession():
    def __init__(self, websocket):
        self.websocket = websocket
        self.authenticated = False
        self.username = None

    async def run(self):
        print(f"New connection from {self.websocket.remote_address}")
        try:
            async for message in self.websocket:
                data = json.loads(message)
                await self.handle_command(data)
        except websockets.ConnectionClosed:
            print(f"User {self.username} disconnected.")
        except json.decoder.JSONDecodeError:
            print(f"Garbage received from {self.websocket.remote_address}, closing connection.")
            self.websocket.close()
    
    async def handle_command(self, data):
        # Check total size of the JSON string
        if len(json.dumps(data)) > 5120:
            await self.websocket.send(json.dumps({"response": "Total payload too large", "status": 400})); return

        # Check fields
        for key, value in data.items():
            if isinstance(value, str) and len(value) > 1024:
                await self.websocket.send(json.dumps({"response": f"Field '{key}' exceeds 1024 characters", "status": 400})); return
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, str) and len(sub_value) > 1024:
                        await self.websocket.send(json.dumps({"response": f"Sub-field '{sub_key}' too large", "status": 400})); return
                        
        action = data.get("action")
        if not action:
            await self.websocket.send(json.dumps({"error": "Missing action", "status": 400}))
            return

        if data.get("action") == "register":
            if self.authenticated == False and db.get(data.get("username")) is None:
                if not isinstance(data.get("username"), str) or not isinstance(data.get("password"), str):
                    await self.websocket.send(json.dumps({"response": "Invalid input types", "status": 400}))
                    return

                self.username = data.get("username")
                password = data.get("password")

                hashedPassword, salt = utils.crypto.hashPassword(password)
                db.put(self.username, {
                    "hPassword": hashedPassword,
                    "salt": salt,
                    "credentials": {}
                })
                self.authenticated = True
                await self.websocket.send(json.dumps({"response": "User registered successfully!", "status": 201}))

            else:
                await self.websocket.send(json.dumps({"response": "User already exists or already authenticated!", "status": 409}))
        elif data.get("action") == "login":
            if not self.authenticated:
                if not isinstance(data.get("username"), str) or not isinstance(data.get("password"), str):
                    await self.websocket.send(json.dumps({"response": "Invalid input types", "status": 400}))
                    return
                user = db.get(data.get("username"))
                if user is not None:
                    hashedPassword, salt = utils.crypto.hashPassword(data.get("password"), salt=user["salt"])
                    if hashedPassword == user["hPassword"]:
                        self.authenticated = True
                        self.username = data.get("username")
                        await self.websocket.send(json.dumps({"response": "Login successful!", "status": 200}))
                    else:
                        await self.websocket.send(json.dumps({"response": "Invalid password!", "status": 401}))
                else:
                    await self.websocket.send(json.dumps({"response": "User does not exist!", "status": 404}))
            else:
                await self.websocket.send(json.dumps({"response": "Already authenticated!", "status": 403}))
        elif data.get("action") == "getSalt":
            if self.authenticated:
                user = db.get(self.username)
                await self.websocket.send(json.dumps(
                       {
                            "response": "Salt fetched!",
                            "salt": user.get("salt", "").hex(),
                            "status": 200
                        }
                    )
                )
            else:
                await self.websocket.send(json.dumps({"response": "Not authenticated!", "status": 401}))
        elif data.get("action") == "getCredentials":
            if self.authenticated:
                user = db.get(self.username)
                await self.websocket.send(json.dumps(
                       {
                            "response": "Credentials fetched!",
                            "credentials": user.get("credentials", {}),
                            "status": 200
                        }
                    )
                )
            else:
                await self.websocket.send(json.dumps({"response": "Not authenticated!", "status": 401}))
        elif data.get("action") == "addCredential":
            if self.authenticated:
                if not data.get("credential", None): await self.websocket.send(json.dumps({"response": "Not enough data!", "status": 400})); return
                user = db.get(self.username)
                credentials = user.get("credentials", {})
                credential = data.get("credential", {})
                credID = os.urandom(8).hex()
                credentials[credID] = credential
                user["credentials"] = credentials
                db.put(self.username, user)
                await self.websocket.send(json.dumps({"response": "Credential added!", "status": 201}))
            else:
                await self.websocket.send(json.dumps({"response": "Not authenticated!", "status": 401}))
        elif data.get("action") == "updateCredential":
            if self.authenticated:
                if not data.get("credID", None) or not data.get("credential", None): await self.websocket.send(json.dumps({"response": "Not enough data!", "status": 400})); return
                user = db.get(self.username)
                credentials = user.get("credentials", {})

                if not credentials.get(data.get("credID")):
                    await self.websocket.send(json.dumps({"response": "Invalid credID!", "status": 404}))
                    return
                
                credential = data.get("credential")
                if not isinstance(credential, dict):
                    await self.websocket.send(json.dumps({"response": "Invalid credential!", "status": 400}))
                credential.pop(credID, None)
                credentials[data.get("credID")] = data.get("credential")
                await self.websocket.send(json.dumps({"response": "Credential updated!", "status": 200}))
            else:
                await self.websocket.send(json.dumps({"response": "Not authenticated!", "status": 401}))
        elif data.get("action") == "removeCredential":
            if self.authenticated:
                user = db.get(self.username)
                credentials = user.get("credentials", {})
                credentials.pop(data.get("credID"), None) # If not found - do nothing.
                user["credentials"] = credentials
                db.put(self.username, user)
                await self.websocket.send(json.dumps({"response": "Credential removed!", "status": 200}))
            else:
                await self.websocket.send(json.dumps({"response": "Not authenticated!", "status": 401}))

async def main():
    listenerIP = "0.0.0.0"
    port = 8765

    async def handler_wrapper(websocket):
        handler = ClientSession(websocket)
        await handler.run()

    server = await websockets.serve(
        handler_wrapper,
        listenerIP,
        port,
        ssl=ssl_context
    )
    print(f"NekoVault running at: wss://{listenerIP}:{port}")
    await server.wait_closed()

asyncio.run(main())