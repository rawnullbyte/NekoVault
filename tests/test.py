import asyncio
import sys
import websockets
import json
import ssl

URI = "wss://localhost:8765"

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE
failed = False


async def test_step(ws, payload, expected_status, description):
    print(f"Testing: {description}...", end=" ", flush=True)
    await ws.send(json.dumps(payload))
    
    response_raw = await ws.recv()
    res = json.loads(response_raw)
    
    if res.get("status") == expected_status:
        print("✅ PASS")
        return res
    else:
        print(f"❌ FAIL (Got {res.get('status')}, expected {expected_status})")
        print(f"   Response: {response_raw}")
        global failed
        failed = True
        return res

async def run():
    
    async with websockets.connect(URI, ssl=ssl_context) as ws:
        # Auth
        await test_step(ws, {"action": "register", "username": "neko_test", "password": "password123"}, 201, "Valid Registration")
        await test_step(ws, {"action": "login", "username": "neko_test", "password": "password123"}, 403, "Login while already authenticated")
        
        # Salt
        await test_step(ws, {"action": "getSalt"}, 200, "Get Salt")

        # Credentials
        await test_step(ws, {"action": "addCredential", "credential": {"site": "github.com"}}, 201, "Add Credential")
        
        creds_res = await test_step(ws, {"action": "getCredentials"}, 200, "Fetch Credentials")
        target_id = list(creds_res["credentials"].keys())[0]

        await test_step(ws, {"action": "updateCredential", "credID": target_id, "credential": {"site": "gitlab.com"}}, 200, "Update Credential")
        await test_step(ws, {"action": "removeCredential", "credID": target_id}, 200, "Remove Credential")

        # Bounds checks
        await test_step(ws, {"action": "register", "username": "a" * 1025, "password": "b"}, 400, "Username length limit")
        await test_step(ws, {"action": "addCredential", "credential": {"key": "v" * 1025}}, 400, "Sub-field length limit")

    async with websockets.connect(URI, ssl=ssl_context) as ws:
        await test_step(ws, {"action": "register", "username": 123, "password": "pw"}, 400, "Invalid Input Types (Int as Username)")
        await test_step(ws, {"action": "getSalt"}, 401, "Auth Required Check")
        await test_step(ws, {"action": "login", "username": "non_existent", "password": "pw"}, 404, "Non-existent user")
        
        print("Testing: Garbage Data/Connection Close...", end=" ", flush=True)
        await ws.send("!!NOT JSON!!")
        try:
            await ws.recv()
            print("❌ FAIL")
        except websockets.ConnectionClosed:
            print("✅ PASS")

if __name__ == "__main__":
    try:
        asyncio.run(run())
        if failed:
            sys.exit(1)
        else:
            sys.exit(0)
    except Exception as e:
        print(f"\nConnection Error: {e}\nIs the NekoVault server running?")
        sys.exit(1)