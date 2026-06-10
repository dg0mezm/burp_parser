# Burp XML to JSON Converter

Converts a Burp Suite XML export generated with `Save items` into a clean JSON file containing unique HTTP requests. The output removes unnecessary Burp fields, deduplicates requests by URL while ignoring the query string, and structures the detected entry points under `entry_points`, including request headers and parameters. Cookies are parsed separately from the `Cookie` header.

## Export from Burp Suite

1. Open Burp Suite.
2. Go to `Proxy > HTTP history`.
3. Remove any active filters if you want to export all requests.
4. Select all entries with `Ctrl + A`.
5. Right-click the selected entries.
6. Click `Save items`.
7. Save the file as `burp_history.xml`.

## Usage

Run the script with Python 3 by providing the Burp XML input file and the JSON output file:

```bash
python3 burp_xml_to_json.py burp_history.xml burp_history.json
```

Run the script with an optional scope file:

```bash
python3 burp_xml_to_json.py burp_history.xml burp_history.json --scope scope.txt
```

On Windows, you can run it with the Python launcher:

```powershell
py burp_xml_to_json.py burp_history.xml burp_history.json
```

On Windows with an optional scope file:

```powershell
py burp_xml_to_json.py burp_history.xml burp_history.json --scope scope.txt
```

The `scope.txt` file must contain one host per line:

```text
app.example.com
api.example.com
example.com
```

## Example `burp_history.json`

```json
[
  {
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
        },
        {
          "name": "Origin",
          "value": "https://app.example.com"
        },
        {
          "name": "Referer",
          "value": "https://app.example.com/login"
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
    }
  },
  {
    "url": "https://api.example.com/api/users/123",
    "port": "443",
    "protocol": "https",
    "method": "PUT",
    "path": "/api/users/123",
    "status": "200",
    "cookies": [
      {
        "name": "session",
        "value": "abc123"
      }
    ],
    "entry_points": {
      "headers": [
        {
          "name": "Host",
          "value": "api.example.com"
        },
        {
          "name": "User-Agent",
          "value": "Mozilla/5.0"
        },
        {
          "name": "Content-Type",
          "value": "application/json"
        },
        {
          "name": "Authorization",
          "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        }
      ],
      "parameters": [
        {
          "source": "json",
          "name": "name",
          "value": "John Doe"
        },
        {
          "source": "json",
          "name": "email",
          "value": "john@example.com"
        },
        {
          "source": "json",
          "name": "role",
          "value": "admin"
        }
      ]
    }
  }
]
```
