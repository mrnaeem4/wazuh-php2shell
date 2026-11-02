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

## Troubleshooting

| Gejala | Solusi |
| --- | --- |
| Rule tidak terpicu | Cek decoder dengan `wazuh-logtest`, pastikan `decoder_exclude` sudah di-set pada manager |
| Rule URL/params tidak match | Decoder access log baru mengisi `field params`; gunakan `<field name="params">` bukan `<url>` |
| Rule auditd tidak terpicu | Pastikan `auditd` aktif, key `php2shell_exec` ter-load, dan log audit dikumpulkan agent |
| FIM tidak melapor | Pastikan `/var/www` ada di `<syscheck><directories>` |
| SCA tidak muncul | Cek status di dashboard, pastikan policy berada di folder `shared` group agent |

## Lisensi

Dirilis di bawah [MIT License](LICENSE). Copyright (c) 2026 Ridwan Na'im.
