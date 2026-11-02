# Wazuh PHP2Shell Detection Rules

Kumpulan **custom decoders, rules, auditd policies, dan SCA policies** untuk Wazuh guna mendeteksi
eksploitasi **PHP2Shell (CVE-2026-109618 / CVE-2026-109619)** pada server web berbasis PHP
(Apache/`mod_php`, Nginx + PHP-FPM, maupun PHP di dalam container Docker).

## Identitas Project

| Item | Keterangan |
| --- | --- |
| Nama | Wazuh PHP2Shell Detection Rules |
| Jenis | Custom content Wazuh (decoders + rules + auditd + SCA) |
| Target | Wazuh Manager >= 4.9 dan Wazuh Agent Linux |
| Cakupan serangan | Reconnaissance, arming probe (log poisoning / session file), OOM/crash signal, ModSecurity, post-exploitation (reverse shell, download payload), FIM webshell |
| MITRE ATT&CK | T1190, T1595.002, T1592.004, T1499, T1505.003, T1059.004, T1005 |
| Referensi CVE | GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp |
| Compliance | NIST SP 800-53, PCI DSS v4.0, TSC |

### Struktur Repository

```
wazuh_php2shell/
├── auditd/
│   └── php2shell.rules                    # Audit execve oleh user web (www-data)
├── decoders/
│   ├── 0170-nginx_decoders.xml            # Decoder nginx error log + ModSecurity
│   ├── 0375-web-accesslog_decoders.xml     # Decoder access log (dengan & tanpa params)
│   └── php-fpm_decoders.xml                # Decoder log PHP-FPM warning
├── rules/
│   ├── 100-modsec_custom_rules.xml         # Rule ModSecurity (id 100000-100008)
│   └── 111-php2shell_rules.xml             # Rule utama PHP2Shell (id 111000-111141)
├── sca/
│   ├── sca_php2shell_php_runtime.yml       # Hardening runtime PHP
│   ├── sca_php2shell_web_server.yml        # Hardening web server & host
│   └── sca_php2shell_docker_runtime.yml    # Variant untuk container Docker
├── yara/
│   ├── yara.sh                             # Script active response YARA (agent)
│   └── php2shell_yara.xml                  # Decoder & rule integrasi YARA
└── log_samples/                            # Contoh log untuk pengujian
```

### Ringkasan Rule

| Rule ID | Level | Deteksi |
| --- | --- | --- |
| 111000-111004 | 3-10 | Recon: scanner UA, akses `phpinfo`, parameter `qXXXXXXX` (transport 9bie), HTTP 500, path sesi di parameter |
| 111105 | 10 | Log poisoning (path menunjuk `access.log`/`error.log`) |
| 111020-111029 | 7-12 | Error PHP: body melebihi `post_max_size`, multipart flood, session rusak, heap corruption, OOM |
| 111040-111041 | 7 | ModSecurity menolak body multipart/JSON |
| 111050-111051 | 12 | Segfault PHP worker, OOM killer |
| 111052-111053 | 12 | Post-exploit: download payload & reverse shell via auditd |
| 111054-111055 | 8-10 | FIM: file PHP baru/berubah di `/var/www` |
| 111060-111062 | 0 | Pemicu scan YARA (level 0, tanpa alert) |
| 108000-108001, 111070-111072 | 8-15 | Hasil scan YARA: signature malware/webshell |
| 111100-111141 | 10-15 | Korelasi multiple event per source IP / host |
| 100000-100008 | 0-14 | Normalisasi event ModSecurity (Nginx) |

## Prasyarat

- Wazuh Manager dan Wazuh Agent sudah terpasang dan saling terhubung.
- Akses root (atau `sudo`) pada manager dan agent.
- Web server log tersedia: access log Apache/Nginx, error log, dan log PHP-FPM.
- (Opsional) ModSecurity + OWASP CRS aktif pada Nginx/Apache.
- (Opsional) Docker CLI bagi agent yang memantau container (SCA Docker).

## Instalasi

### 1. Backup Konfigurasi

```bash
sudo mkdir -p /root/wazuh-backup
sudo cp /var/ossec/etc/ossec.conf /root/wazuh-backup/
```

### 2. Deploy Decoders (Wazuh Manager)

```bash
sudo cp decoders/*.xml /var/ossec/etc/decoders/
sudo chown wazuh:wazuh /var/ossec/etc/decoders/*.xml
sudo chmod 660 /var/ossec/etc/decoders/*.xml
```

### 3. Deploy Rules (Wazuh Manager)

```bash
sudo cp rules/*.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/*.xml
sudo chmod 660 /var/ossec/etc/rules/*.xml
```

> Rule `100-modsec_custom_rules.xml` bergantung pada decoder `nginx-errorlog-modsec`, pastikan file
> decoder ikut di-deploy.

### 4. Nonaktifkan Decoder Bawaan yang Digantikan

Tambahkan blok berikut di `<decoders>` pada `/var/ossec/etc/ossec.conf` agar decoder bawaan
`0170-nginx_decoders.xml` dan `0375-web-accesslog_decoders.xml` tidak bentrok:

```xml
<decoder_exclude>0170-nginx_decoders.xml</decoder_exclude>
<decoder_exclude>0375-web-accesslog_decoders.xml</decoder_exclude>
```

### 5. Deploy Auditd Rules (Wazuh Agent / Server Web)

```bash
sudo cp auditd/php2shell.rules /etc/audit/rules.d/
```

Sesuaikan UID user web pada file tersebut bila berbeda (`euid=33` = `www-data` pada Debian/Ubuntu,
`euid=48` = `apache` pada RHEL family). Cek dengan `id -u www-data`.

```bash
sudo augenrules --load
sudo systemctl enable --now auditd
sudo auditctl -l | grep php2shell_exec
```

### 6. Konfigurasi Log Collection pada Agent

Tambahkan `localfile` di `/var/ossec/etc/ossec.conf` agent:

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/nginx/access.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/error.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/php*-fpm.log</location>
</localfile>

<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

Aktifkan juga FIM untuk web root (diperlukan rule 111054/111055):

```xml
<syscheck>
  <directories check_all="yes" report_changes="yes">/var/www</directories>
</syscheck>
```

### 7. Deploy SCA Policy (Wazuh Agent)

```bash
sudo cp sca/*.yml /var/ossec/etc/shared/default/
sudo chown wazuh:wazuh /var/ossec/etc/shared/default/*.yml
sudo chmod 660 /var/ossec/etc/shared/default/*.yml
```

Pastikan agent berada pada group `default` dan blok `<sca>` aktif pada `agent.conf`/`ossec.conf`:

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
</sca>
```

Untuk container, gunakan `sca_php2shell_docker_runtime.yml` dan pastikan agent dapat mengakses Docker socket.

### 8. Validasi dan Restart

```bash
sudo /var/ossec/bin/wazuh-logtest
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

Pada agent:

```bash
sudo systemctl restart wazuh-agent
```

## Pengujian

Uji decoder & rule dengan sample log yang disediakan:

```bash
sudo /var/ossec/bin/wazuh-logtest -q < log_samples/apache.log
sudo /var/ossec/bin/wazuh-logtest -q < log_samples/nginx.log
sudo /var/ossec/bin/wazuh-logtest -q < log_samples/auditd.log
```

Hasil yang diharapkan muncul misalnya `PHP2Shell: scanner user agent seen on the web server` (rule 111000).

## Active Response: `firewall-drop`

Rule PHP2Shell yang terpicu secara otomatis memicu **active response** `firewall-drop`, sehingga IP
penyerang diblokir pada firewall host selama durasi tertentu.

### Group Pemicu

| Group Rule | Contoh Rule | Efek |
| --- | --- | --- |
| `php2shell_recon` | 111000, 111001, 111002, 111003, 111100 | IP scanner yang melakukan reconnaissance diblokir |
| `php2shell_http` | 111002, 111003, 111004, 111105 | IP pengirim request berbahaya (LFI, log poisoning) diblokir |
| `modsecurity` | 111040, 111041, 100002, 100004, 100005 | IP yang ditolak ModSecurity / Nginx diblokir |

> `firewall-drop` membutuhkan `srcip`, sehingga hanya rule dengan source IP yang dapat memicu.
> Rule berbasis kernel/auditd (`php2shell_crash_signal`, `php2shell_post_exploit`) tidak dapat
> memicu `firewall-drop` karena tidak membawa IP sumber.

### Prasyarat pada Agent

- Paket `iptables` tersedia (atau `nftables` jika konfigurasi Wazuh disesuaikan).
- Script active response bawaan `firewall-drop` ada di `/var/ossec/active-response/bin/firewall-drop`.
- Agent berjalan sebagai root agar dapat menulis rule iptables.

### Konfigurasi Agent (`/var/ossec/etc/ossec.conf`)

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_group>php2shell_recon|php2shell_http|modsecurity</rules_group>
  <timeout>1800</timeout>
</active-response>
```

Keterangan:

| Field | Nilai | Keterangan |
| --- | --- | --- |
| `command` | `firewall-drop` | Nama command active response |
| `location` | `local` | Blokir pada host agent yang menerima event |
| `rules_group` | `php2shell_recon\|php2shell_http\|modsecurity` | Group dipisah `\|` (OR) |
| `timeout` | `1800` | Durasi blokir dalam detik (30 menit) |

### Konfigurasi Alternatif: per Rule ID

Jika ingin hanya rule tertentu yang memblokir, gunakan `<rules_id>`:

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>111000,111002,111004,111105,100004</rules_id>
  <timeout>1800</timeout>
</active-response>
```

### Konfigurasi Terpusat dari Manager (`agent.conf`)

Agar berlaku untuk semua agent dalam group, letakkan pada `/var/ossec/etc/shared/<group>/agent.conf`:

```xml
<agent_config>
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_group>php2shell_recon|php2shell_http|modsecurity</rules_group>
    <timeout>1800</timeout>
  </active-response>
</agent_config>
```

### Verifikasi

```bash
# pada agent: pastikan rule iptables terbentuk setelah simulasi rule
sudo iptables -L -n | grep DROP

# pada manager: pastikan active response tercatat
sudo tail -f /var/ossec/logs/active-responses.log
```

Setelah `timeout` habis, `firewall-drop` menghapus blokir secara otomatis.

### Catatan Keamanan

- **Whitelist IP internal** (load balancer, monitoring, reverse proxy) di
  `/var/ossec/etc/lists/` atau dengan rule level `0` untuk menghindari self-block.
- Blokir pada `location local` hanya melindungi host tersebut. Untuk memblokir di satu titik masuk,
  gunakan `location server` pada manager dengan skenario `firewall-drop` terpusat.
- `modsecurity` mencakup rule level rendah (100002 level 5, 100006 level 6); pastikan threshold
  tidak memblokir pengguna sah akibat false positive (atur `rules_id` bila perlu).

## Menyesuaikan Path Web Root

Sebagian rule dan SCA policy **menghardcode** path web root umum (`/var/www`, `/srv/www`,
`/usr/share/nginx/html`, `/usr/local/www`, `/opt/lampp/htdocs`). Jika instalasi Anda memakai path
lain (mis. `/data/www`, `/home/site/public_html`, `/app/public`, atau web root di dalam container),
lakukan penyesuaian berikut.

### Tabel Lokasi yang Harus Diubah

| File | Baris | Isi Saat Ini | Yang Perlu Diubah |
| --- | --- | --- | --- |
| `rules/111-php2shell_rules.xml` | 257 | `^/var/www/.+\.(?:php...)$` (rule 111054, FIM file baru) | Ganti `^/var/www/` dengan prefix web root Anda, mis. `^(?:/var/www\|/data/www)/` |
| `rules/111-php2shell_rules.xml` | 268 | `^/var/www/.+\.(?:php...)$` (rule 111055, FIM file diubah) | Sama seperti di atas |
| `rules/111-php2shell_rules.xml` | 50 | Regex 111004 mendeteksi path sesi di `/tmp` atau `/var/lib/php` | Tambahkan prefix direktori sesi Anda (`/run/php`, `/data/sessions`, dst.) |
| `sca/sca_php2shell_web_server.yml` | 53 | `find /var/www /srv/www ...` (check 42102) | Tambahkan path web root Anda |
| `sca/sca_php2shell_web_server.yml` | 77 | `find /var/lib/php/sessions ... /tmp` (check 42104) | Tambahkan direktori sesi (lihat `php -i \| grep session.save_path`) |
| `sca/sca_php2shell_web_server.yml` | 107-111 | `d:/var/www`, `d:/srv/www`, ... (check 42106) | Tambahkan baris `d:<path>` untuk web root Anda |
| `sca/sca_php2shell_php_runtime.yml` | 135 | Regex `(^|;)/(var/www\|usr/share/nginx\|srv/www\|opt/lampp/htdocs)` (check 42009) | Tambahkan alternasi path web root Anda |
| `sca/sca_php2shell_docker_runtime.yml` | 182 | Regex yang sama dengan 42009 | Tambahkan alternasi path web root di dalam container |

### Contoh Penyesuaian

**Rule FIM** (default 2 path):

```xml
<field name="file" type="pcre2">(?i)^(?:/var/www|/data/www|/home/site/public_html)/.+\.(?:php[0-9]?|phtml|phar|pht|phps)$</field>
```

**SCA check 42102** (tambahkan path):

```yaml
c:find /var/www /srv/www /usr/share/nginx/html /usr/local/www /opt/lampp/htdocs /data/www -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.php5" -o -name "*.pht" \) -perm -0002 -print -quit 2>/dev/null -> r:.
```

**SCA check 42106** (tambahkan satu baris per web root):

```yaml
- 'd:/data/www -> (^\.htaccess$|^\.user\.ini$) -> r:session\.upload_progress\.enabled\s*[= ]\s*(On|1|true)|auto_prepend_file\s*[= ]'
```

**FIM `<syscheck>` pada agent** juga harus menunjuk path yang sama:

```xml
<syscheck>
  <directories check_all="yes" report_changes="yes">/data/www</directories>
</syscheck>
```

### Cara Menemukan Web Root Sebenarnya

```bash
# Nginx
grep -r "root " /etc/nginx/sites-enabled/ /etc/nginx/conf.d/

# Apache
grep -r "DocumentRoot" /etc/apache2/sites-enabled/ /etc/httpd/conf.d/

# Docker
docker inspect -f '{{.Name}} {{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}' $(docker ps -q)

# Session path aktual
php -i | grep session.save_path
```

### Hal Lain yang Perlu Diperhatikan

- **`log_samples/`** memakai `/var/www/html` sebagai contoh; tidak perlu diubah kecuali untuk pengujian.
- **Nonaktifkan `syscheck` ignore** untuk direktori deploy/release baru, agar rule 111054 tidak
  menghasilkan alert berlebih saat deployment.
- **Path dengan karakter regex** (spasi, titik) harus di-escape atau diberi `\Q...\E` pada pola PCRE2.
- **Container**: agent host biasanya hanya melihat path host (mis. `/srv/docker/app/html`), bukan
  path di dalam container; gunakan `sca_php2shell_docker_runtime.yml` untuk membaca setting runtime.
- Jika web root berada di luar `/var/www`, rule FIM harus diperbarui **dan** tetap konsisten dengan
  `<directories>` pada `ossec.conf`; jika tidak, rule tidak akan pernah terpicu.

## Integrasi YARA

YARA dipakai untuk memverifikasi apakah file PHP baru/berubah di web root merupakan webshell atau
malware. Alurnya mengikuti
[Panduan Wazuh: Detecting malware using YARA integration](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-malware-yara-integration.html):

```
FIM (rule 111054/111055) ──► Active Response `yara_linux` (yara.sh)
                                      │  yara -w -r <rules> <file>
                                      ▼
                         /var/ossec/logs/active-responses.log
                                      │
                        decoder yara_decoder (manager)
                                      ▼
                     rule 108001 ─► 111070 (webshell di web root) / 111071
```

### File Terkait

| File | Tujuan |
| --- | --- |
| `yara/yara.sh` | Script active response (instal ke agent), varian PHP2Shell dari `yara.sh` Wazuh |
| `yara/php2shell_yara.xml` | Decoder `yara_decoder` + rule 111060-111072 dan contoh blok `<command>` |

### Langkah 1: Instal YARA pada Endpoint (Agent)

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y make gcc autoconf libtool libssl-dev pkg-config jq curl
sudo curl -LO https://github.com/VirusTotal/yara/archive/v4.5.5.tar.gz
sudo tar -xvzf v4.5.5.tar.gz -C /usr/local/bin/ && rm -f v4.5.5.tar.gz
cd /usr/local/bin/yara-4.5.5/
sudo ./bootstrap.sh && sudo ./configure && sudo make && sudo make install && sudo make check
```

Jika muncul `libyara.so.<n>: cannot open shared object file`:

```bash
echo "/usr/local/lib" | sudo tee -a /etc/ld.so.conf && sudo ldconfig
```

RHEL: ganti paket dengan `yum install -y make automake gcc autoconf libtool openssl-devel pkg-config jq`
dan aktifkan `epel-release`.

### Langkah 2: Unduh Ruleset YARA

```bash
sudo mkdir -p /tmp/yara/rules
sudo curl 'https://valhalla.nextron-systems.com/api/v1/get' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'demo=demo&apikey=1111111111111111111111111111111111111111111111111111111111111111&format=text' \
  -o /tmp/yara/rules/yara_rules.yar
```

> `apikey` demo bersifat publik dan rate-limited. Untuk produksi gunakan ruleset milik sendiri,
> misalnya aturan webshell PHP (`php2shell`, `webshell`, `c99`, `r57`, `b374k`) di direktori
> `/tmp/yara/rules/` lalu arahkan `-yara_rules` ke file/direktori tersebut.
>
> Simpan ruleset di luar `/tmp` pada produksi, mis. `/var/ossec/etc/yara/rules.yar`, karena `/tmp`
> bisa dibersihkan oleh `systemd-tmpfiles`.

### Langkah 3: Pasang Script Active Response pada Agent

```bash
sudo cp yara/yara.sh /var/ossec/active-response/bin/yara.sh
sudo chown root:wazuh /var/ossec/active-response/bin/yara.sh
sudo chmod 750 /var/ossec/active-response/bin/yara.sh
```

### Langkah 4: Aktifkan FIM pada Web Root (Agent)

`/var/ossec/etc/ossec.conf`:

```xml
<syscheck>
  <directories realtime="yes" report_changes="yes">/var/www</directories>
  <directories realtime="yes">/tmp/yara/malware</directories>
</syscheck>
```

`/tmp/yara/malware` adalah direktori uji dari dokumentasi Wazuh. Sesuaikan `/var/www` dengan
web root Anda (lihat bagian [Menyesuaikan Path Web Root](#menyesuaikan-path-web-root)).

### Langkah 5: Deploy Decoder dan Rule YARA (Manager)

Decoder `yara_decoder` dan rule `108000`/`108001` berada di `yara/php2shell_yara.xml`. Pisahkan
sesuai jenisnya, atau salin ke file lokal manager:

```bash
# decoder -> /var/ossec/etc/decoders/php2shell_yara_decoders.xml
# rules   -> /var/ossec/etc/rules/112-php2shell_yara_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/decoders/php2shell_yara_decoders.xml \
                       /var/ossec/etc/rules/112-php2shell_yara_rules.xml
sudo chmod 660 /var/ossec/etc/decoders/php2shell_yara_decoders.xml \
               /var/ossec/etc/rules/112-php2shell_yara_rules.xml
```

Rule kunci:

| Rule ID | Level | Fungsi |
| --- | --- | --- |
| 111060 | 0 | FIM file PHP baru di web root, memicu scan (tanpa alert) |
| 111061 | 0 | FIM file PHP diubah di web root, memicu scan (tanpa alert) |
| 111062 | 0 | Event direktori uji `/tmp/yara/malware`, memicu scan |
| 108000 | 0 | Grouping decoder YARA |
| 108001 | 12 | YARA positif match (bawaan dokumentasi) |
| 111070 | 14 | YARA positif match pada file di web root (indikasi webshell) |
| 111071 | 8 | YARA positif match di luar web root |
| 111072 | 15 | Korelasi 3+ match malware dalam 10 menit |

> Rule 111060/111061 level `0` hanya memicu active response tanpa menghasilkan alert, karena
> alert FIM sudah ditangani rule 111054/111055 (level 10/8). Jika ingin tanpa alert ganda, aktifkan
> hanya salah satu pasangan pada `<rules_id>` active response.

### Langkah 6: Konfigurasi Active Response (Manager)

Tambahkan di dalam `<ossec_config>` pada `/var/ossec/etc/ossec.conf` manager:

```xml
<command>
  <name>yara_linux</name>
  <executable>yara.sh</executable>
  <extra_args>-yara_path /usr/local/bin -yara_rules /tmp/yara/rules/yara_rules.yar</extra_args>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>yara_linux</command>
  <location>local</location>
  <rules_id>111054,111055,111060,111061,111062</rules_id>
</active-response>
```

Untuk men-deploy ke banyak agent, letakkan blok `<active-response>` yang sama dalam
`/var/ossec/etc/shared/<group>/agent.conf` di dalam `<agent_config>`.

Restart service:

```bash
sudo systemctl restart wazuh-manager
# pada agent
sudo systemctl restart wazuh-agent
```

## Troubleshooting

| Gejala | Solusi |
| --- | --- |
| Rule tidak terpicu | Cek decoder dengan `wazuh-logtest`, pastikan `decoder_exclude` sudah di-set pada manager |
| Rule URL/params tidak match | Decoder access log baru mengisi `field params`; gunakan `<field name="params">` bukan `<url>` |
| Rule auditd tidak terpicu | Pastikan `auditd` aktif, key `php2shell_exec` ter-load, dan log audit dikumpulkan agent |
| FIM tidak melapor | Pastikan `/var/www` ada di `<syscheck><directories>` |
| SCA tidak muncul | Cek status di dashboard, pastikan policy berada di folder `shared` group agent |
| Active response tidak memblokir | Cek `iptables` tersedia, agent berjalan sebagai root, dan `rules_group` tertulis benar |
| YARA tidak memindai | Cek `jq` terpasang, `yara.sh` executable (`750 root:wazuh`), path `-yara_path`/`-yara_rules` benar, dan agent menerima konfigurasi active response terbaru |
| `yara: error while loading shared libraries` | Tambahkan `/usr/local/lib` ke `/etc/ld.so.conf` lalu jalankan `ldconfig` |

## Lisensi

Dirilis di bawah [MIT License](LICENSE). Copyright (c) 2026 Ridwan Na'im.
