# Burp XML to SQLite Converter

Converts a Burp Suite XML export generated with `Save items` into a SQLite database named `burp_history.sqlite3`.

The script parses HTTP requests from Burp Suite, applies optional scope filtering, removes duplicated requests, and stores the resulting records in SQLite. Each stored request receives a unique identifier. A second file named `endpoints_reference.json` is also generated, containing only the identifiers of the stored endpoints.

Cookies are parsed separately from the `Cookie` header. Request headers and parameters are stored inside the `entry_points` field.

## Export from Burp Suite

1. Open Burp Suite.
2. Go to `Proxy > HTTP history`.
3. Remove any active filters if you want to export all requests.
4. Select all entries with `Ctrl + A`.
5. Right-click the selected entries.
6. Click `Save items`.
7. Save the file as `burp_history.xml`.

## Usage

Run the script with Python 3:

```bash
python3 burp_xml_to_sqlite.py burp_history.xml
```

Run the script with an optional scope file:

```bash
python3 burp_xml_to_sqlite.py burp_history.xml --scope scope.txt
```

On Windows, you can run it with the Python launcher:

```powershell
py burp_xml_to_sqlite.py burp_history.xml
```

On Windows with an optional scope file:

```powershell
py burp_xml_to_sqlite.py burp_history.xml --scope scope.txt
```

The `scope.txt` file must contain one host per line:

```text
app.example.com
api.example.com
example.com
```

### `endpoints_reference.json`

JSON file containing only the identifiers of the stored endpoints.

Example:

```json
[
  "e3b2dfc2-3e7e-4cc4-bb6d-4d6c5fdf0ad7",
  "650a2056-ea1c-4d46-8660-c19845d5f81a",
  "1fc21bc5-6ed2-4c58-b59d-2d5fd0d5ed20"
]
```

## SQLite structure

The `http_requests` table contains the following fields:

```sql
CREATE TABLE http_requests (
    id TEXT PRIMARY KEY,
    unique_key TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    port TEXT,
    protocol TEXT,
    method TEXT,
    path TEXT,
    status TEXT,
    cookies TEXT NOT NULL,
    entry_points TEXT NOT NULL,
    record TEXT NOT NULL
);
```

## Stored record format

Each request is stored with a structure similar to this inside the `record` field:

```json
{
  "id": "e3b2dfc2-3e7e-4cc4-bb6d-4d6c5fdf0ad7",
  "url": "https://app.example.com/login?redirect=/dashboard",
  "port": "443",
  "protocol": "https",
  "method": "POST",
  "path": "/login",
  "status": "302",
  "cookies": [
    {
      "name": "session",
      "value": "abc123"
    },
    {
      "name": "lang",
      "value": "en"
    }
  ],
  "entry_points": {
    "headers": [
      {
        "name": "Host",
        "value": "app.example.com"
      },
      {
        "name": "User-Agent",
        "value": "Mozilla/5.0"
      },
      {
        "name": "Content-Type",
        "value": "application/x-www-form-urlencoded"
      }
    ],
    "parameters": [
      {
        "source": "query",
        "name": "redirect",
        "value": "/dashboard"
      },
      {
        "source": "body",
        "name": "username",
        "value": "admin"
      },
      {
        "source": "body",
        "name": "password",
        "value": "password123"
      }
    ]
  },
  "normalized_url": "https://app.example.com/login",
  "unique_key": "POST https://app.example.com/login"
}
```
