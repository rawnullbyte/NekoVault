import asyncio
import websockets
import json
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich_gradient import Text
from rich.live import Live
from rich.prompt import Prompt
from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings
from textual.app import App
from textual.widgets import DataTable
import utils.crypto
import ssl
import time
import sys

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

console = Console()

class NekoClient:
    def __init__(self, uri):
        self.uri = uri
        self.ws = None
        self.authenticated = False
        self.username = ""
        self.salt = None
        self.hashedMasterPassword = ""
        self.credentials = {}

        self.kb = KeyBindings()
        self.setup_bindings()

    def setup_bindings(self):
        @self.kb.add('c-r') # Ctrl + R
        async def _(event):
            credentialsResponse = await self.send_action("getCredentials")
            if credentialsResponse["status"] == 200:
                console.print(f"[bold green]Credentials received![/bold green]")
                self.credentials = await self.processCredentials(credentialsResponse["credentials"])
            else:
                console.print(f"[bold red]Error:[/bold red] {credentialsResponse["response"]}")
                await self.exit()

    async def connect(self):
        self.ws = await websockets.connect(self.uri, ssl=ssl_context)
        console.print("[bold green]Connected to NekoVault![/bold green]")
    
    async def exit(self):
        if self.ws:
            await self.ws.close()
        console.print("[yellow]Disconnected. Goodbye![/yellow]")
        sys.exit(0)

    async def clear(self):
        console.clear()
        console.print("")

    async def processCredentials(self, credentials):
        tempCredentials = {}
        for ka, va in credentials.items():
            tempCredentials[ka] = {}
            for kb, vb in va.items():
                tempCredentials[ka][kb] = utils.crypto.decrypt(vb, self.hashedMasterPassword)
        return tempCredentials

    async def retrieveCredentials(self):
        credentialsResponse = await self.send_action("getCredentials")
        if credentialsResponse["status"] == 200:
            console.print(f"[bold green]Credentials received![/bold green]")
            self.credentials = await self.processCredentials(credentialsResponse["credentials"])
        else:
            console.print(f"[bold red]Error:[/bold red] {credentialsResponse["response"]}")
            await self.exit()


    async def send_action(self, action, **kwargs):
        payload = {"action": action, **kwargs}
        await self.ws.send(json.dumps(payload))
        return json.loads(await self.ws.recv())

    async def loginMenu(self):
        while True:
            await self.clear()
            choice = await questionary.select(
                "Authorization:",
                choices=[
                    "Login",
                    "Register",
                    "Exit"
                ]
            ).ask_async()

            if choice == "Login":
                username = await questionary.text("Username:").ask_async()
                password = await questionary.password("Password:").ask_async()
                
                response = await self.send_action("login", username=username, password=password)

                if response["status"] == 200:
                    self.authenticated = True
                    self.username = username
                    console.print(f"[bold green]Success:[/bold green] {response["response"]}")
                    break
                else:
                    console.print(f"[bold red]Error:[/bold red] {response["response"]}")
                    await questionary.press_any_key_to_continue().ask_async()

            if choice == "Register":
                username = await questionary.text("Username:").ask_async()
                password = await questionary.password("Password:").ask_async()
                
                response = await self.send_action("register", username=username, password=password)
                if response["status"] == 200 or response["status"] == 201:
                    self.authenticated = True
                    self.username = username
                    console.print(f"[bold green]Success:[/bold green] {response["response"]}")
                    break
                else:
                    console.print(f"[bold red]Error:[/bold red] {response["response"]}")
                    await questionary.press_any_key_to_continue().ask_async()
            elif choice == "Exit":
                await self.exit()
                break
    
    async def postLogin(self):
        saltResponse = await self.send_action("getSalt")
        if saltResponse["status"] == 200:
            self.salt = bytes.fromhex(saltResponse["salt"])
            console.print(f"[bold green]Salt:[/bold green] {saltResponse["salt"]}")
        else:
            console.print(f"[bold red]Error:[/bold red] {saltResponse["response"]}")
            await self.exit()

        masterPassword = await questionary.password("Master password:").ask_async()
        self.hashedMasterPassword, _ = utils.crypto.hashPassword(masterPassword, self.salt)
        await self.retrieveCredentials()

    async def mainMenu(self):
        while True:
            await self.clear()
            console.print(
                Text(
                    "NekoVault Password Manager ฅ^•ﻌ•^ฅ",
                    colors = ["#ffb6c1", "#ff69b4", "#db7093", "#d291bc"],
                    style="bold",
                    justify="center"        
                )
            )

            choice = await questionary.select(
                "NekoVault:",
                choices=[
                    "View Credentials",
                    "Add Credential",
                    "Remove Credential",
                    "Exit"
                ]
            ).ask_async()

            if choice == "View Credentials":
                print(self.credentials)
                await questionary.press_any_key_to_continue().ask_async()
            elif choice == "Add Credential":
                addCredential = {}
                addCredential["title"] = utils.crypto.encrypt(await questionary.text("Title:").ask_async(), self.hashedMasterPassword)
                addCredential["username"] = utils.crypto.encrypt(await questionary.text("Username/Email:").ask_async(), self.hashedMasterPassword)
                addCredential["password"] = utils.crypto.encrypt(await questionary.password("Password:").ask_async(), self.hashedMasterPassword)
                addCredential["website"] = utils.crypto.encrypt(await questionary.text("Website:").ask_async(), self.hashedMasterPassword)

                addResponse = await self.send_action("addCredential", credential=addCredential)
                if addResponse["status"] == 201:
                    console.print(f"[bold green]Credential added![/bold green]")
                    await self.retrieveCredentials()
                    await questionary.press_any_key_to_continue().ask_async()
                else:
                    console.print(f"[bold red]Error:[/bold red] {addResponse["response"]}")
                    await self.exit()
            elif choice == "Remove Credential":
                removeResponse = await self.send_action(
                    "removeCredential",
                    credID=await questionary.text("CredID:").ask_async()
                )
                if removeResponse["status"] == 200:
                    console.print(f"[bold green]Credential removed![/bold green]")
                    await self.retrieveCredentials()
                    await questionary.press_any_key_to_continue().ask_async()
                else:
                    console.print(f"[bold red]Error:[/bold red] {removeResponse["response"]}")
                    await self.exit()

            elif choice == "Exit":
                await self.exit()
                break

async def start():
    client = NekoClient("wss://localhost:8765")
    await client.connect()
    await client.loginMenu()
    await client.postLogin()
    await client.mainMenu()

if __name__ == "__main__":
    try:
        asyncio.run(start())
    except KeyboardInterrupt:
        console.print("\n[yellow]Goodbye![/yellow]")