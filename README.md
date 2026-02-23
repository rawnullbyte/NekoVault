# NekoVault
 
## About
I made this project for the [HackVault YSWS program](https://hackvault.hackclub.com/).
This is a simple and secure backend made for password related applications. For encryption I've decided to pick Argon2 for password hashing and AES-256 GCM for credentials encryption. All credentials are and should be decrypted on client side with a hash of the master key. To hash the master key use the salt retrieved using the getSalt command.

## Documentation

### Notes:
- JSON String (payload) must **not** exceed 5120 chars!
- JSON Fields (values) must **not** exceed 1024 chars!

### Authentication

<details>
    <summary>register</summary>

##### Notes: 
- Username and password should be sent raw without any encryption.

##### Payload:
```json
{
  "action": "register",
  "username": "your_name",
  "password": "your_password"
}
```

##### OK Response:
```json
{
  "response": "User registered successfully!",
  "status": 201
}
```

##### Error Response:
```json
{
  "response": "User already exists or already authenticated!",
  "status": 409
}
```
</details>



<details>
    <summary>login</summary>

##### Payload:

##### Notes: 
- Username and password should be sent raw without any encryption.

```json
{
  "action": "login",
  "username": "your_name",
  "password": "your_password"
}
```

##### OK Response:
```json
{
  "response": "Login successful!",
  "status": 200
}
```

##### Error Responses:
```json
{
  "response": "Invalid password!",
  "status": 401
}
```
```json
{
  "response": "User does not exist!",
  "status": 404
}
```
</details>

<!--------------------------------------------------------------------------->

### Data management

<details>
    <summary>getSalt</summary>

##### Notes: 
- Must be authenticated!

##### Payload:
```json
{
  "action": "getSalt"
}
```

##### Response:
```json
{
  "response": "Salt fetched!",
  "salt": "3638ff6739c6e63594eadc8f0a718a61",
  "status": 200
}
```

</details>



<details>
    <summary>getCredentials</summary>

##### Notes: 
- Must be authenticated!
- 12396f7ef6d33f4f is the credential ID (used for deleteing creds etc.)
- Values of credential keys must be decrypted on client side using a hash of the master password.

##### Payload:
```json
{
  "action": "getCredentials"
}
```

##### Response encrypted:
```json
{
  "response": "Credentials fetched!",
  "credentials": {
    "12396f7ef6d33f4f": {
      "title": "307ea2dd24a79c41dbfdfa09a597918d54054dea6c6d6eb52fd6bd17afc54335fb669a66",
      "username": "856dacd0d758a166ea64591f9fe6bdc120789c0ffb6fb6e83772feab559d2f183232d8bf",
      "password": "7fa406b9ca4312e7bb216fb55c05cfb1313910a17d466c4e5db3215a1e503be5388e2f0b",
      "website": "4a24c3c6bd7956c0f6ffd680c09b67bb0868943a31bd91131c1ea795fa78c0d4aab07967"
    }
  },
  "status": 200
}
```

##### Response decrypted:
```json
{
  "response": "Credentials fetched!",
  "credentials": {
    "12396f7ef6d33f4f": {
      "title": "a",
      "username": "b",
      "password": "c",
      "website": "d"
    }
  },
  "status": 200
}
```
</details>



<details>
    <summary>addCredential</summary>

##### Notes: 
- Must be authenticated!
- You can add any keys and values into the "credetial" value
- Values **must** be encrypted with a hash of the master password.

##### Decrypted payload:
```json
{
  "action": "addCredential",
  "credential": {
    "title": "a",
    "username": "b",
    "password": "c",
    "website": "d"
  }
}
```

##### Encrypted payload:
```json
{
  "action": "addCredential",
  "credential": {
    "title": "f33e8bac8282adaf9914bcbbdae580bacf075f8c2635f12215819446f531d5de588bc65956",
    "username": "e78a580a0eab184a63258f8a0f2b3a415f4bae4ac7f59806638acb7a8e9628bc8aa8e1907d",
    "password": "d641eab48619dd627a354a3da232911729e7682267156ed13fc6d946b7625e822e712f89",
    "website": "814292e612436c1580c48942497e28f1d1f0f1ff12433d48c5e24691df7c7e2cadc3470b"
  }
}
```

##### Response:
```json
{
  "response": "Credential added!",
  "status": 201
}
```
</details>



<details>
    <summary>updateCredential</summary>

##### Notes: 
- Must be authenticated!
- You can add any keys and values into the "credetial" value
- Values **must** be encrypted with a hash of the master password.

##### Decrypted payload:
```json
{
  "action": "updateCredential",
  "credID": "f3a1b2c3",
  "credential": {
    "title": "a2",
    "username": "b2",
    "password": "c2",
    "website": "d2"
  }
}
```

##### Encrypted payload:
```json
{
  "action": "updateCredential",
  "credID": "f3a1b2c3",
  "credential": {
    "title": "f33e8bac8282adaf9914bcbbdae580bacf075f8c2635f12215819446f531d5de588bc65956",
    "username": "e78a580a0eab184a63258f8a0f2b3a415f4bae4ac7f59806638acb7a8e9628bc8aa8e1907d",
    "password": "d641eab48619dd627a354a3da232911729e7682267156ed13fc6d946b7625e822e712f89",
    "website": "814292e612436c1580c48942497e28f1d1f0f1ff12433d48c5e24691df7c7e2cadc3470b"
  }
}
```

##### Response:
```json
{
  "response": "Credential updated!",
  "status": 200
}
```

##### Error Responses:
```json
{
  "response": "Invalid credID!",
  "status": 404
}
```
```json
{
  "response": "Invalid credential!",
  "status": 400
}
```
</details>



<details>
    <summary>removeCredential</summary>

##### Notes: 
- Must be authenticated!

##### Payload:
```json
{
  "action": "removeCredential",
  "credID": "f3a1b2c3"
}
```

##### Response:
```json
{
  "response": "Credential removed!",
  "status": 200
}
```
</details>

### Global error responses:

#### Payload Size:
```json
{
  "response": "Total payload too large",
  "status": 400
}
```

#### Field Size:
```json
{
  "response": "Field '...' exceeds 1024 characters",
  "status": 400
}
```
```json
{
  "response": "Sub-field '...' too large",
  "status": 400
}
```

#### Auth Required:
```json
{
  "response": "Not authenticated!",
  "status": 401
}
```

#### Invalid input type:
```json
{
  "response": "Invalid input types",
  "status": 400
}
```

#### Missing action:
```json
{
  "error": "Missing action",
  "status": 400
}
```

#### Not enough data:
```json
{
  "response": "Not enough data!",
  "status": 400
}
```


#### Already authenticated (trying to register/login when already logged in):
```json
{
  "response": "Already authenticated!",
  "status": 403
}
```

#### Malformed/Error occurs:
\*Connection gets closed\*
