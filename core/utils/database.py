from rocksdict import Rdict

class Database:
    def __init__(self):
        self.db = Rdict("./data")

        """
        # Structure
        
        username: str {
            hPassword: str,
            salt: str,
            credentials: [
                {
                    credID: str,
                    field: list[str],
                    attachments: [
                        filename: str
                        mime: image/png
                        data: base64 file data
                    ]
                }   
            ]
        }
        """

    def put(self, key: str, value: str) -> None:
        self.db[key] = value

    def get(self, key: str) -> str:
        return self.db.get(key, None)

    def delete(self, key: str) -> None:
        if key in self.db:
            del self.db[key]

    def registerUser(self, username: str, hPassword: str, salt: str) -> None:
        self.db[username] = {
            "hPassword": hPassword,
            "salt": salt,
            "logins": []
        }

    def close(self) -> None:
        self.db.close()