# 🔐 kuncen: Token Generator & Validator CLI

> Stateless, secure, and minimal binary for time-based token validation  
> CLI ringan dan aman untuk validasi token berbasis waktu

---

## 🇮🇩 Tentang

`kuncen` adalah aplikasi terminal (CLI) untuk membuat dan memverifikasi token berbasis waktu. Dirancang khusus untuk REST API, IoT, atau sistem mikro tanpa menyimpan token di server dan tanpa koneksi ke database.

- ⏱️ Token valid dalam waktu terbatas (default: 3 menit)
- 🔐 SALT terenkripsi secara internal
- 🛡️ Validasi dilakukan oleh executable, tidak bisa dipalsukan eksternal
- 🌐 Mendukung domain lock dan UTC

Tinggal pasang tetap bebas digunakan sesuai lisensi.

---

## About

`kuncen` is a secure, standalone CLI tool to generate and validate time-based tokens. Designed for REST APIs, IoT, or embedded systems where no server-side storage is possible.

- ⏱️ Token expires automatically (default: 3 minutes)
- 🔐 Encrypted internal salt
- 🛡️ Executable performs validation securely
- 🌐 Domain lock and UTC support

Binary is freely usable under license terms.

---

## ⚙️ Cara Pakai / How to Use

Download dan izinkan eksekusi:

   ```bash
   chmod +x kuncen
   ```

### 🔑 Buat token / Generate token

#### 🔑 Terminal / CLI

```bash
./kuncen -b -t 5 -k mau_gratisan
Respon: ```69```
```

### ✅ Validasi token / Validate token
```bash
./kuncen -v <your-token> -t 5 -k mau_gratisan
./kuncen -v 69 -t 5 -k mau_gratisan
```
Respon: ```1```
```bash
./kuncen -v 69 -t 5 -k gak_mau_gratisan
```
Respon: ```0```

## Usecase


#### 🧪 Contoh Request dari Client

#### bash
```bash
TOKEN=$(./kuncen -b -t 5 -k mau_gratisan)

curl -X POST https://domainku.com/api/data \
     -H "Content-Type: application/json" \
     -H "X-Token: $TOKEN" \
     -d '{"user":"Pekok", "nilai":4}'
```

#### python3

```python3
import subprocess
import requests

token_proc = subprocess.run(
    ["./kuncen", "-b", "-t", "5", "-k", "mau_gratisan"],
    capture_output=True,
    text=True
)
TOKEN = token_proc.stdout.strip()

# Kirim request ke REST API
response = requests.post(
    "https://domainku.com/api/data",
    headers={
        "Content-Type": "application/json",
        "X-Token": TOKEN
    },
    json={"user": "Pekok", "nilai": 4}
)

# Tampilkan respons
print("Status:", response.status_code)
print("Respon:", response.text)

```

#### 🔑 PHP / Laravel (server-side)

## 🧰 Contoh Middleware Laravel

**File:** `app/Http/Middleware/VerifyTokenKuncen.php`

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\Process\Process;

class VerifyTokenKuncen
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->header('X-Token') ?? $request->query('token');
        if (!$token) {
            return response()->json(['error' => 'Missing token'], 403);
        }

        $domain = parse_url(config('app.url'), PHP_URL_HOST);
        $binary = base_path('storage/app/kuncen');

        $process = new Process([$binary, '-v', $token, '-k', $domain]);
        $process->run();
        //respon MUST 1
        if (!$process->isSuccessful() || $process->getOutput() !== 1) {
            return response()->json(['error' => 'Invalid token'], 403);
        }

        return $next($request);
    }
}
```

## 🛠️ Registrasi Middleware

**File:** `app/Http/Kernel.php`

```php
protected $routeMiddleware = [
    // ...
    'verify.token' => \App\Http\Middleware\VerifyTokenKuncen::class,
];
```

## 🧪 Contoh Route API

**File:** `routes/api.php`

```php
use Illuminate\Support\Facades\Route;

Route::middleware(['verify.token'])->group(function () {
    Route::post('/data', function (\Illuminate\Http\Request $request) {
        return response()->json(['message' => 'Data diterima']);
    });
});
```

#### 🔑 PHP / CodeIgniter 4

**File:** `app/Filters/VerifyTokenKuncen.php`

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\Process\Process;

class VerifyTokenKuncen
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->header('X-Token') ?? $request->query('token');
        if (!$token) {
            return response()->json(['error' => 'Missing token'], 403);
        }

        $domain = parse_url(config('app.url'), PHP_URL_HOST);
        $binary = base_path('writable/kuncen');

        $process = new Process([$binary, '-v', $token, '-k', $domain]);
        $process->run();
        //respon MUST 1
        if (!$process->isSuccessful() || $process->getOutput() !== 1) {
            return response()->json(['error' => 'Invalid token'], 403);
        }

        return $next($request);
    }
}
```

## 🛠️ Registrasi Middleware

**File:** `app/Config/Filters.php`

```php
public $aliases = [
    'verify.token' => \App\Filters\VerifyTokenKuncen::class,
];
```

## 🧪 Contoh Route API

**File:** `app/Config/Routes.php`

```php
$routes->group('api', ['filter' => 'verify.token'], function($routes) {
    $routes->post('data', 'ApiController::submitData');
});
```
---

#### 🐍 Python3 / Flask

```python
# File: middleware/verify_token_kuncen.py
import subprocess
from flask import request, jsonify

def verify_token_kuncen(domain: str = "localhost", binary_path="./kuncen"):
    def decorator(f):
        def wrapper(*args, **kwargs):
            token = request.headers.get("X-Token") or request.args.get("token")
            if not token:
                return jsonify({"error": "Missing token"}), 403

            try:
                result = subprocess.run(
                    [binary_path, "-v", token, "-k", domain],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=2
                )
                if result.stdout.decode().strip() != "1":
                    return jsonify({"error": "Invalid token"}), 403
            except Exception as e:
                return jsonify({"error": f"Token check failed: {str(e)}"}), 500

            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator
```

---

```python
# File: app.py
from flask import Flask, request, jsonify
from middleware.verify_token_kuncen import verify_token_kuncen

app = Flask(__name__)

@app.route("/api/data", methods=["POST"])
@verify_token_kuncen(domain="mydomain.com", binary_path="./kuncen")
def submit_data():
    data = request.json
    return jsonify({"message": "Data diterima", "data": data})
```

---

#### ▶️ Jalankan Flask

```bash
FLASK_APP=app.py flask run --port=69
```

---


## ⚠️ Catatan Keamanan / Security Notes

- Tidak menggunakan database, token bersifat stateless dan otomatis kadaluarsa
- SALT tidak bisa dibaca karena telah terenkripsi
- Gunakan di jaringan lokal atau HTTPS untuk keamanan maksimal

---

## 📦 Distribusi

Hanya file binary `kuncen` yang dibagikan.  
> Kompatibel dengan Linux x86_64 statis (glibc).

---


## ✍️ Pembuat / Author

**Sri Sutyoko Hermawan**  
📧 sri.sutyoko@gmail.com  
🔗 [GitHub](https://github.com/undix)

