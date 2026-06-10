import argparse
import base64
import json
import re
import sqlite3
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit


def decode_burp_field(element):
    if element is None or element.text is None:
        return ""

    text = element.text

    if element.attrib.get("base64") == "true":
        return base64.b64decode(text).decode("utf-8", errors="replace")

    return text


def split_headers_body(raw_message):
    if "\r\n\r\n" in raw_message:
        return raw_message.split("\r\n\r\n", 1)

    if "\n\n" in raw_message:
        return raw_message.split("\n\n", 1)

    return raw_message, ""


def unfold_header_lines(lines):
    unfolded = []

    for line in lines:
        if line.startswith((" ", "\t")) and unfolded:
            unfolded[-1] += " " + line.strip()
        else:
            unfolded.append(line)

    return unfolded


def parse_raw_request(raw_request):
    header_block, body = split_headers_body(raw_request)
    lines = header_block.replace("\r\n", "\n").split("\n")

    first_line = lines[0].strip() if lines else ""
    header_lines = unfold_header_lines(lines[1:])

    all_headers = []

    for line in header_lines:
        if not line.strip():
            continue

        if ":" not in line:
            continue

        name, value = line.split(":", 1)

        all_headers.append({
            "name": name.strip(),
            "value": value.strip()
        })

    headers = [
        header
        for header in all_headers
        if header["name"].lower() != "cookie"
    ]

    return first_line, headers, all_headers, body


def get_header(headers, header_name):
    header_name = header_name.lower()

    for header in reversed(headers):
        if header["name"].lower() == header_name:
            return header["value"]

    return ""


def get_all_headers(headers, header_name):
    header_name = header_name.lower()

    return [
        header["value"]
        for header in headers
        if header["name"].lower() == header_name
    ]


def parse_request_target(first_line):
    parts = first_line.split()

    if len(parts) >= 2:
        return parts[1]

    return ""


def parse_method(first_line):
    parts = first_line.split()

    if len(parts) >= 1:
        return parts[0]

    return ""


def parse_cookies(headers):
    cookies = []

    for cookie_header in get_all_headers(headers, "cookie"):
        for cookie_part in cookie_header.split(";"):
            cookie_part = cookie_part.strip()

            if not cookie_part:
                continue

            if "=" in cookie_part:
                name, value = cookie_part.split("=", 1)
            else:
                name = cookie_part
                value = ""

            cookies.append({
                "name": name.strip(),
                "value": value.strip()
            })

    return cookies


def parse_query_parameters(url, request_target):
    parameters = []
    query = ""

    if url:
        query = urlsplit(url).query

    if not query and request_target:
        query = urlsplit(request_target).query

    for name, value in parse_qsl(query, keep_blank_values=True):
        parameters.append({
            "source": "query",
            "name": name,
            "value": value
        })

    return parameters


def parse_urlencoded_body(body):
    parameters = []

    for name, value in parse_qsl(body, keep_blank_values=True):
        parameters.append({
            "source": "body",
            "name": name,
            "value": value
        })

    return parameters


def flatten_json_value(value, prefix=""):
    parameters = []

    if isinstance(value, dict):
        for key, nested_value in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            parameters.extend(flatten_json_value(nested_value, name))

        return parameters

    if isinstance(value, list):
        for index, nested_value in enumerate(value):
            name = f"{prefix}[{index}]" if prefix else f"[{index}]"
            parameters.extend(flatten_json_value(nested_value, name))

        return parameters

    if prefix:
        parameters.append({
            "source": "json",
            "name": prefix,
            "value": value
        })

    return parameters


def parse_json_body(body):
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []

    return flatten_json_value(data)


def extract_boundary(content_type):
    match = re.search(r'boundary=("([^"]+)"|[^;]+)', content_type, re.IGNORECASE)

    if not match:
        return ""

    boundary = match.group(1).strip()

    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]

    return boundary


def parse_content_disposition_params(content_disposition):
    params = {}
    matches = re.finditer(r';\s*([^=;\s]+)=("([^"]*)"|[^;]*)', content_disposition)

    for match in matches:
        name = match.group(1).strip()
        raw_value = match.group(2).strip()

        if raw_value.startswith('"') and raw_value.endswith('"'):
            value = raw_value[1:-1]
        else:
            value = raw_value

        params[name] = value

    return params


def parse_multipart_body(body, content_type):
    parameters = []
    boundary = extract_boundary(content_type)

    if not boundary:
        return parameters

    boundary_marker = "--" + boundary
    parts = body.split(boundary_marker)

    for part in parts:
        part = part.strip("\r\n")

        if not part or part == "--":
            continue

        if part.endswith("--"):
            part = part[:-2].strip("\r\n")

        part_header_block, part_body = split_headers_body(part)
        part_lines = part_header_block.replace("\r\n", "\n").split("\n")

        part_headers = []

        for line in part_lines:
            if ":" not in line:
                continue

            name, value = line.split(":", 1)

            part_headers.append({
                "name": name.strip(),
                "value": value.strip()
            })

        content_disposition = get_header(part_headers, "content-disposition")

        if not content_disposition:
            continue

        disposition_params = parse_content_disposition_params(content_disposition)
        parameter_name = disposition_params.get("name")

        if not parameter_name:
            continue

        parameter = {
            "source": "multipart",
            "name": parameter_name,
            "value": part_body.rstrip("\r\n")
        }

        if "filename" in disposition_params:
            parameter["filename"] = disposition_params["filename"]
            parameter["value"] = ""

        parameters.append(parameter)

    return parameters


def parse_body_parameters(headers, body):
    if not body:
        return []

    content_type = get_header(headers, "content-type").lower()
    stripped_body = body.strip()

    if "application/x-www-form-urlencoded" in content_type:
        return parse_urlencoded_body(body)

    if "multipart/form-data" in content_type:
        return parse_multipart_body(body, content_type)

    if "json" in content_type:
        return parse_json_body(body)

    if stripped_body.startswith("{") or stripped_body.startswith("["):
        return parse_json_body(body)

    if "=" in stripped_body and "&" in stripped_body:
        return parse_urlencoded_body(body)

    return []


def parse_parameters(url, request_target, headers, body):
    parameters = []
    parameters.extend(parse_query_parameters(url, request_target))
    parameters.extend(parse_body_parameters(headers, body))

    return parameters


def parse_item(item):
    raw_request = decode_burp_field(item.find("request"))
    first_line, headers, all_headers, body = parse_raw_request(raw_request)
    request_target = parse_request_target(first_line)

    method = item.findtext("method", "") or parse_method(first_line)
    path = item.findtext("path", "") or request_target
    url = item.findtext("url", "")

    record = {
        "id": str(uuid.uuid4()),
        "url": url,
        "port": item.findtext("port", ""),
        "protocol": item.findtext("protocol", ""),
        "method": method,
        "path": path,
        "status": item.findtext("status", ""),
        "cookies": parse_cookies(all_headers),
        "entry_points": {
            "headers": headers,
            "parameters": parse_parameters(
                url,
                request_target,
                headers,
                body
            )
        }
    }

    record["normalized_url"] = normalize_url_without_query(record["url"])
    record["unique_key"] = build_unique_key(record)

    return record


def find_items(root):
    items = root.findall("item")

    if items:
        return items

    return root.findall(".//item")


def normalize_url_without_query(url):
    parsed_url = urlsplit(url)

    return urlunsplit((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        "",
        ""
    ))


def build_unique_key(record):
    method = record.get("method", "").upper()
    normalized_url = record.get("normalized_url", "")

    return f"{method} {normalized_url}"


def remove_duplicate_items(items):
    seen_items = set()
    unique_items = []

    for item in items:
        unique_key = item.get("unique_key", "")

        if unique_key in seen_items:
            continue

        seen_items.add(unique_key)
        unique_items.append(item)

    return unique_items


def normalize_host_value(host):
    host = host.strip().lower()

    if not host:
        return ""

    if "://" in host:
        parsed_host = urlsplit(host).netloc
        host = parsed_host if parsed_host else host

    host = host.split("/")[0]
    host = host.rstrip(".")

    if host.startswith("[") and "]" in host:
        return host

    if ":" in host:
        host = host.split(":", 1)[0]

    return host


def load_scope_hosts(scope_file):
    scope_hosts = set()

    with open(scope_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            normalized_host = normalize_host_value(line)

            if normalized_host:
                scope_hosts.add(normalized_host)

    return scope_hosts


def get_item_host(item):
    headers = item.get("entry_points", {}).get("headers", [])

    for header in headers:
        if header.get("name", "").lower() != "host":
            continue

        return normalize_host_value(header.get("value", ""))

    url = item.get("url", "")
    parsed_url = urlsplit(url)

    return normalize_host_value(parsed_url.netloc)


def filter_items_by_scope(items, scope_hosts):
    scoped_items = []
    discarded_items = []

    for item in items:
        host = get_item_host(item)

        if host in scope_hosts:
            scoped_items.append(item)
        else:
            discarded_items.append(item)

    return scoped_items, discarded_items


def filter_items_by_status(items, excluded_statuses):
    filtered_items = []
    discarded_items = []

    for item in items:
        status = str(item.get("status", "")).strip()

        if status in excluded_statuses:
            discarded_items.append(item)
        else:
            filtered_items.append(item)

    return filtered_items, discarded_items


def get_unique_host_headers(items):
    host_headers = []
    seen_hosts = set()

    for item in items:
        headers = item.get("entry_points", {}).get("headers", [])

        for header in headers:
            if header.get("name", "").lower() != "host":
                continue

            value = header.get("value", "").strip()

            if not value or value in seen_hosts:
                continue

            seen_hosts.add(value)
            host_headers.append(value)

    return host_headers


def create_database(database_file):
    database_path = Path(database_file)

    if database_path.exists():
        database_path.unlink()

    connection = sqlite3.connect(database_file)

    connection.execute("""
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
        )
    """)

    connection.execute("CREATE INDEX idx_http_requests_method ON http_requests(method)")
    connection.execute("CREATE INDEX idx_http_requests_path ON http_requests(path)")
    connection.execute("CREATE INDEX idx_http_requests_normalized_url ON http_requests(normalized_url)")

    connection.commit()

    return connection


def insert_items(connection, items):
    inserted_items = []

    for item in items:
        connection.execute(
            """
            INSERT INTO http_requests (
                id,
                unique_key,
                url,
                normalized_url,
                port,
                protocol,
                method,
                path,
                status,
                cookies,
                entry_points,
                record
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item["id"],
                item["unique_key"],
                item["url"],
                item["normalized_url"],
                item["port"],
                item["protocol"],
                item["method"],
                item["path"],
                item["status"],
                json.dumps(item["cookies"], ensure_ascii=False),
                json.dumps(item["entry_points"], ensure_ascii=False),
                json.dumps(item, ensure_ascii=False)
            )
        )

        inserted_items.append(item)

    connection.commit()

    return inserted_items


def write_endpoints_reference(reference_file, items):
    endpoint_ids = [
        item["id"]
        for item in items
    ]

    with open(reference_file, "w", encoding="utf-8") as f:
        json.dump(endpoint_ids, f, ensure_ascii=False, indent=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_xml")
    parser.add_argument("--scope", required=False, help="Optional file with in-scope hosts, one per line")
    parser.add_argument("--database", default="burp_history.sqlite3")
    parser.add_argument("--reference", default="endpoints_reference.json")
    args = parser.parse_args()

    tree = ET.parse(args.input_xml)
    root = tree.getroot()

    items = [parse_item(item) for item in find_items(root)]
    total_items = len(items)

    if args.scope:
        scope_hosts = load_scope_hosts(args.scope)
        items, discarded_items = filter_items_by_scope(items, scope_hosts)
        discarded_by_scope = len(discarded_items)
    else:
        scope_hosts = set()
        discarded_by_scope = 0

    items, discarded_status_items = filter_items_by_status(items, {"404"})
    discarded_by_status = len(discarded_status_items)

    items = remove_duplicate_items(items)
    host_headers = get_unique_host_headers(items)

    connection = create_database(args.database)

    try:
        inserted_items = insert_items(connection, items)
    finally:
        connection.close()

    write_endpoints_reference(args.reference, inserted_items)

    print(f"Se han procesado {total_items} peticiones desde el XML")

    if args.scope:
        print(f"Se han descartado {discarded_by_scope} peticiones fuera de scope")
        print(f"Scope cargado desde {args.scope}: {len(scope_hosts)} hosts")

    print(f"Se han descartado {discarded_by_status} peticiones con status 404")
    print(f"Se han guardado {len(inserted_items)} peticiones únicas en {args.database}")
    print(f"Se han generado {len(inserted_items)} referencias en {args.reference}")

    if host_headers:
        print("Host headers encontrados:")

        for host in host_headers:
            print(f"- {host}")
    else:
        print("No se han encontrado headers Host")


if __name__ == "__main__":
    main()