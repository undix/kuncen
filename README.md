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


### 🧪 Contoh Request dari Client / Sample client-side

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

### 🧪 Contoh Validasi Server / Sample server-side

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

 🛠️ Registrasi Middleware

**File:** `app/Config/Filters.php`

```php
public $aliases = [
    'verify.token' => \App\Filters\VerifyTokenKuncen::class,
];
```

 🧪 Contoh Route API

**File:** `app/Config/Routes.php`

```php
$routes->group('api', ['filter' => 'verify.token'], function($routes) {
    $routes->post('data', 'ApiController::submitData');
});
```
---

#### 🐍 Go / Gin

```golang
package middleware

import (
	"fmt"
	"os/exec"
	"strings"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Middleware untuk verifikasi token menggunakan executable "kuncen"
func VerifyTokenKuncen(domain string, binaryPath string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Ambil token dari header atau query parameter
		token := c.GetHeader("X-Token")
		if token == "" {
			token = c.Query("token")
		}
		if token == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Missing token"})
			c.Abort()
			return
		}

		// Eksekusi binary untuk verifikasi token
		cmd := exec.Command(binaryPath, "-v", token, "-k", domain)
		out, err := cmd.Output()

		// Jika gagal, kirim respon error
		if err != nil || strings.TrimSpace(string(out)) != "1" {
			fmt.Println("Token verification error:", err)
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Jika sukses, lanjut ke handler
		c.Next()
	}
}

```

---

```golang
// File: main.go
package main

import (
	"github.com/gin-gonic/gin"
	"yourmodule/middleware" // Ganti dengan nama modul atau path middleware kamu
)

func main() {
	r := gin.Default()

	// Middleware untuk verifikasi token "kuncen"
	// Ganti domain dan path binary sesuai kebutuhan
	r.Use(middleware.VerifyTokenKuncen("mydomain.com", "./kuncen"))

	// Endpoint utama
	r.POST("/api/data", func(c *gin.Context) {
		var payload map[string]interface{}
		if err := c.BindJSON(&payload); err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		c.JSON(200, gin.H{
			"message": "Data diterima",
			"data":    payload,
		})
	})

	r.Run(":69")
}

```

---

#### ▶️ Jalankan Go/Gin

```bash
go mod init yourmodule
go get github.com/gin-gonic/gin
go run main.go
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

#### 🔑 PHP / Laravel

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


## ⚠️ Catatan Keamanan / Security Notes

- ✅ Tidak menggunakan database, token bersifat stateless dan otomatis kadaluarsa  
  ✅ No database required — tokens are stateless and expire automatically  
- 🔒 SALT tidak bisa dibaca karena telah terenkripsi  
  🔒 SALT is encrypted internally and not accessible from outside  
- 🌐 Gunakan di jaringan lokal atau HTTPS untuk keamanan maksimal  
  🌐 Use in local network or HTTPS for maximum security  

---

## 📦 Distribusi / Distribution

Hanya file binary `kuncen` yang dibagikan.  
Only the `kuncen` binary is distributed.

> ✅ Kompatibel dengan Linux x86_64 statis (glibc)  
> ✅ Compatible with Linux x86_64 static build (glibc)


---


## ✍️ Pembuat / Author

**Sri Sutyoko Hermawan**  
📧 sri.sutyoko@gmail.com  
🔗 [GitHub](https://github.com/undix)

