# Spesifikasi RustCtrl

Status: dokumen awal sebagai bahan pengembangan spec fitur dan tiket melalui skill Matt Pocock. Aturan sumber kebutuhan berikutnya ada di `docs/agents/issue-tracker.md`. Integrasi perangkat belum dinyatakan lulus uji.

## 1. Tujuan dan kapasitas

RustCtrl membantu tim IT memantau serta mengendalikan komputer Windows dan Android TV dari satu dashboard desktop. Staf memilih perangkat berdasarkan nama dan lokasi, tanpa mencari IP melalui Winbox atau mendatangi perangkat satu per satu.

Lingkungan awal:

- Sekitar 100 komputer Windows dan 20 Android TV.
- Sekitar 10 staf IT, masing-masing dengan akun dan password sendiri.
- Satu jaringan kantor dengan beberapa VLAN.
- Maksimal 10 sesi remote bersamaan pada perangkat berbeda.
- Satu perangkat hanya boleh memiliki satu operator pengendali pada satu waktu.
- Login, monitoring, remote, dan tugas pengelolaan tetap berfungsi saat koneksi internet putus, selama jaringan internal dan server tersedia.
- Remote bersifat unattended: tidak membutuhkan persetujuan pengguna di perangkat tujuan pada setiap sesi setelah provisioning selesai.

Seluruh modul pada dokumen ini masuk versi pertama, termasuk debloat TV, deployment aplikasi, eksekusi script, aksi massal, telemetry, dan pengaturan aplikasi antrian pada monitor kedua.

## 2. Platform dan stack

| Komponen | Platform dan ketentuan |
| --- | --- |
| Controller | Aplikasi desktop Rust dengan Zed GPUI untuk Windows dan Linux, termasuk AlmaLinux pada komputer staf. |
| Server pusat | Service Rust headless pada Linux. Menyimpan akun, inventaris, tugas, sesi, dan audit secara terpusat. |
| Windows agent | Service Rust untuk komputer Windows, dengan helper terpisah untuk sesi desktop interaktif. |
| Android TV | Koneksi melalui ADB dan scrcpy, tanpa pemasangan agent RustCtrl permanen. |
| Concurrency | Tokio untuk pekerjaan jaringan, pemantauan perangkat, pengiriman tugas, dan pemulihan koneksi. |
| Penyimpanan | Database persisten pada server pusat. Baseline versi pertama adalah SQLite dengan transaksi dan WAL pada satu instance server. |

Target awal komputer Windows adalah Windows 10/11. Windows Server tetap termasuk cakupan agent pada konfigurasi yang menyediakan desktop interaktif dan telah divalidasi. Versi serta edisi Windows yang benar-benar dipakai kantor harus masuk matriks pengujian; kompatibilitas tidak disimpulkan hanya dari tersedianya API Win32.

Versi AlmaLinux di kantor belum diketahui. Rilis controller harus menyebutkan versi OS, arsitektur CPU, sesi X11/Wayland, glibc, serta GPU dan driver yang telah diuji. Controller Linux memerlukan lingkungan grafis yang sesuai dengan revisi GPUI terpilih. Server pusat tidak membutuhkan desktop atau GPU untuk menjalankan GPUI.

GPUI masih berkembang. Kunci versi atau commit GPUI, toolchain Rust, crate, ADB, dan scrcpy yang dipakai pada build rilis. Jangan mengikuti branch terbaru secara otomatis pada instalasi produksi.

Sumber platform: [GPUI README](https://github.com/zed-industries/zed/blob/main/crates/gpui/README.md), [Zed Linux](https://zed.dev/docs/linux). Ketentuan binary Zed tidak otomatis menjadi ketentuan binary RustCtrl; paket RustCtrl harus diuji sendiri.

### 2.1. Kebijakan keselamatan Rust dan ukuran agent

- Logika aplikasi, domain, dan jaringan memakai safe Rust.
- `unsafe` diperbolehkan secara terbatas untuk FFI dan integrasi native yang memang membutuhkannya.
- Letakkan pemanggilan tersebut dalam modul kecil, sediakan safe wrapper, dan dokumentasikan lifetime, kepemilikan resource, thread, serta prasyarat keselamatannya.
- Jangan mengklaim seluruh dependensi atau binary bebas `unsafe`.
- Ukuran agent di bawah 10 MB adalah target optimasi, bukan syarat yang mengalahkan fungsi, keamanan, atau kestabilan. Laporkan ukuran binary, helper, dan paket instalasi secara terpisah.

Binding resmi [`SendInput`](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/UI/Input/KeyboardAndMouse/fn.SendInput.html) merupakan salah satu alasan perlunya batas FFI tersebut.

## 3. Arsitektur sistem

```text
Controller desktop Windows / AlmaLinux
                  |
          login, API, remote
                  |
        RustCtrl Server di Linux
        |                     |
  koneksi agent          ADB + scrcpy
        |                     |
 Windows service          Android TV
        |
 helper desktop interaktif
```

### 3.1. Tanggung jawab server pusat

Server merupakan sumber data utama untuk akun, hak akses, identitas perangkat, status, tugas, kepemilikan sesi remote, dan riwayat aktivitas.

- Semua controller memakai akun dan inventaris yang sama.
- Pemeriksaan hak akses dilakukan server, bukan hanya dengan menyembunyikan tombol pada controller.
- Server mengoordinasikan satu pemilik sesi remote per perangkat secara atomik, termasuk ketika dua staf mengajukan sesi pada waktu yang hampir sama.
- Server menyediakan jalur pengendalian dan relay media internal. Tidak ada ketergantungan pada layanan relay, autentikasi, STUN, atau TURN publik.
- Untuk Android TV, service penghubung ADB berjalan dalam lingkungan yang dikelola server. Kunci otorisasi ADB tidak dibagikan kepada setiap operator.
- Controller tidak harus memiliki izin jaringan langsung ke semua endpoint. Server atau komponen penghubungnya harus dapat menjangkau VLAN target.
- Data penting tidak hanya berada dalam cache controller atau `Arc<RwLock<HashMap<...>>>`. Cache tersebut boleh dipakai untuk state runtime, sedangkan identitas, tugas, akun, dan audit harus persisten.

### 3.2. Jalur komunikasi

- Control plane controller/server dan Windows agent/server memakai gRPC melalui TLS, dengan default port server `9876/TCP` yang dapat dikonfigurasi. Agent Windows membuka koneksi keluar ke server dan mempertahankan kanal untuk heartbeat serta perintah yang diotorisasi.
- Baseline media plane adalah WebRTC dengan media terenkripsi dan relay internal. Implementasi codec, transport, serta bridge video scrcpy harus dibuktikan melalui uji integrasi sebelum dinyatakan siap.
- Server mengikat setiap kanal media dan input pada sesi yang telah diotorisasi. Kanal input berhenti ketika hak sesi berakhir.
- ADB TCP klasik bukan pengganti kanal TLS. Batasi akses ADB pada jalur server yang disetujui melalui routing dan firewall. Gunakan otorisasi atau pairing yang tersedia pada perangkat.
- Alamat server dan port dikonfigurasi saat deployment. Sertakan daftar port control plane, media, dan ADB yang benar-benar digunakan pada panduan instalasi; jangan mengasumsikan semua VLAN dapat saling terhubung.

Jika server tidak tersedia, controller menampilkan gangguan server, bukan mengubah seluruh perangkat menjadi offline. Sesi yang tidak lagi memiliki otorisasi valid harus dihentikan. Setelah server pulih, agent menyambung ulang, inventaris dimuat kembali, dan tugas yang sempat berjalan direkonsiliasi tanpa otomatis mengeksekusi ulang aksi yang hasilnya belum diketahui.

## 4. Akun, hak akses, dan audit

Setiap staf memakai username dan password pribadi. Autentikasi disediakan server internal dan tidak memerlukan layanan internet. Password disimpan sebagai hash dengan algoritma khusus password, bukan plaintext. Sesi pengguna dapat dicabut saat akun dinonaktifkan atau password direset.

| Kemampuan | Operator | Admin |
| --- | --- | --- |
| Melihat seluruh perangkat dan status | Ya | Ya |
| Remote seluruh perangkat | Ya | Ya |
| Mengelola akun dan reset password | Tidak | Ya |
| Mendaftarkan, menamai, mengelompokkan, dan menghapus perangkat | Tidak | Ya |
| Mengatur jaringan, provisioning, dan kebijakan agent | Tidak | Ya |
| Debloat, launcher, instalasi APK/paket, dan eksekusi script | Tidak | Ya |
| Restart/shutdown dan aksi massal | Tidak | Ya |
| Mengatur profil aplikasi antrian dan monitor kedua | Tidak | Ya |
| Melihat riwayat audit terpusat | Tidak | Ya |

Kewenangan di atas mengatur fitur RustCtrl. Pengguna yang melakukan remote tetap dibatasi oleh akun dan izin OS yang dipakai pada endpoint; akses desktop bukan mekanisme pembatasan perubahan di dalam OS.

Audit mencakup login, perubahan akun/perangkat, pembukaan dan penutupan sesi remote, serta seluruh tugas pengelolaan. Minimal simpan aktor, perangkat, tindakan, waktu server, hasil, dan ID sesi atau tugas. Untuk remote, simpan waktu mulai, selesai, dan alasan berakhir. Untuk tugas massal, simpan hasil setiap perangkat.

Jangan menyimpan password Windows, token, atau keystroke remote dalam audit. Output script perlu pembatasan akses dan penyaringan rahasia. Perekaman video layar bukan bagian kebutuhan versi pertama. Retensi, kapasitas log, serta jadwal backup harus dikonfigurasi dan dicatat pada deployment kantor.

## 5. Inventaris, discovery, dan monitoring

### 5.1. Identitas dan provisioning

Identitas perangkat tetap sama saat IP berubah. Gunakan ID pendaftaran agent untuk Windows dan identitas inventaris yang dipasangkan dengan identitas ADB untuk TV. IP, MAC, dan nama host adalah atribut inventaris, bukan satu-satunya identitas. MAC perangkat lintas VLAN tidak selalu tersedia dan tidak boleh menjadi syarat remote.

Provisioning Windows:

1. Admin memasang service dan helper dengan hak OS yang diperlukan.
2. Masukkan alamat server serta kode pendaftaran sekali pakai.
3. Server memvalidasi kode dan menerbitkan identitas atau kredensial perangkat yang dapat dicabut.
4. Admin memberi nama, lokasi, serta grup VLAN.
5. Service berjalan otomatis setelah boot dan menyambung ulang ketika jaringan pulih.

Provisioning TV:

1. Inventarisasi model, versi Android, firmware, dan opsi debugging.
2. Aktifkan debugging serta otorisasi ADB atau pairing yang didukung. Akses fisik saat pemasangan awal diperbolehkan.
3. Daftarkan identitas, alamat atau metode penemuan ulang, nama, lokasi, dan grup VLAN.
4. Verifikasi capture, kontrol input, serta akses ulang setelah reboot tanpa interaksi lokal.

Penghapusan perangkat mencabut akses RustCtrl dan kredensial terkait. Penghapusan dari inventaris tidak boleh diam-diam dianggap sudah mematikan debugging atau menghapus konfigurasi pada TV.

### 5.2. Discovery lintas VLAN

- Admin dapat memasukkan IP tertentu dan daftar CIDR yang disetujui.
- Pemindaian berjalan asynchronous dengan batas concurrency dan timeout yang dapat dikonfigurasi.
- Port ADB TCP klasik `5555` merupakan salah satu kandidat, bukan asumsi universal. Wireless debugging dapat memakai pairing dan port berbeda.
- Windows agent terdaftar ditemukan dari registry dan koneksinya ke server. Port `9876/TCP` berada pada server pusat; instalasi agent tidak memerlukan listener inbound di setiap PC.
- Perangkat hasil scan berstatus kandidat sampai admin mendaftarkannya. Port terbuka tidak memberi kewenangan untuk menjalankan perintah.
- Koneksi lintas VLAN memerlukan routing serta firewall yang mengizinkan. TCP langsung tidak otomatis menembus firewall dan tidak disebut tunneling jika tidak ada tunnel yang benar-benar dibangun.

### 5.3. Status dan telemetry

Daftar perangkat menampilkan nama, lokasi, jenis OS, grup VLAN, status, waktu terakhir terhubung, dan tombol remote. Detail perangkat memuat IP terakhir, versi OS/agent, CPU, RAM, disk, uptime, proses aktif, serta tugas terakhir sesuai kemampuan endpoint.

Status dibedakan menjadi online, offline, reconnecting, belum terdaftar, dan perlu provisioning/otorisasi. Agent online belum tentu berarti capture atau input siap; tampilkan kemampuan remote dan alasan kegagalan secara terpisah.

Heartbeat, batas kedaluwarsa status, interval telemetry, dan backoff reconnect dapat dikonfigurasi. Controller memuat perubahan tanpa memblokir UI. Perangkat offline tetap berada dalam inventaris. Beban server atau keterlambatan telemetry tidak boleh ditampilkan sebagai nilai metrik yang masih dianggap terbaru.

## 6. Remote interaktif

### 6.1. Siklus sesi dan eksklusivitas

1. Staf memilih perangkat dan meminta sesi.
2. Server memeriksa akun, status perangkat, kemampuan remote, serta kepemilikan sesi.
3. Jika perangkat sedang dipakai, tampilkan staf pemilik sesi. Permintaan kedua ditolak; tidak ada pengambilalihan otomatis.
4. Server membentuk sesi media dan input yang terikat pada pengguna serta perangkat tersebut.
5. Pengguna menutup sesi atau sistem menghentikannya ketika koneksi atau otorisasi tidak lagi valid.
6. Server melepas kepemilikan dan menutup audit sesi.

Gunakan lease dengan heartbeat agar controller yang crash tidak mengunci perangkat selamanya. Sebelum pemilik baru diizinkan mengendalikan perangkat, pastikan jalur input pemilik lama sudah tidak valid. Batas 10 sesi berlaku untuk gabungan Windows dan TV, bukan 10 sesi untuk masing-masing jenis.

### 6.2. Android TV: ADB dan scrcpy

- Gunakan adapter ADB untuk shell, inspeksi paket, provisioning, dan instalasi APK.
- `adb_client` merupakan kandidat library. Validasi cakupan protokol dan pairing yang diperlukan; binary ADB yang dipin dapat dibundel untuk operasi yang belum didukung adapter.
- Gunakan komponen server dan protokol scrcpy untuk capture serta kontrol. Pin versi client/server yang cocok; jangan menganggap protokol internal scrcpy sebagai API lintas versi yang stabil.
- Video ditampilkan dalam panel remote GPUI. Integrasi tidak dinyatakan selesai hanya karena jendela scrcpy eksternal dapat dibuka.
- Pemetaan input mencakup mouse/tap, swipe jika didukung, keyboard, D-pad, Select/Enter, Home, dan Back. Sesuaikan koordinat dengan resolusi dan rotasi aktual.
- Tidak ada agent RustCtrl permanen pada TV. Namun scrcpy tetap menempatkan serta menjalankan komponen server sementara melalui ADB selama sesi.
- Jalur ADB/scrcpy berbeda dari aplikasi MediaProjection biasa dan dapat melakukan capture tanpa dialog persetujuan layar per sesi. Prasyaratnya tetap debugging serta otorisasi yang valid.

**Akses setelah reboot adalah kebutuhan wajib, bukan jaminan semua Android TV sudah mendukungnya.** Jangan mengklaim `setprop persist.adb.tcp.port 5555` selalu tersedia atau dapat ditulis oleh shell biasa. Persistence dapat membutuhkan hak root atau dukungan firmware/vendor. Root dan perubahan firmware bukan prasyarat yang diasumsikan atau dijalankan otomatis oleh produk.

Model TV baru dinyatakan didukung setelah lulus uji reboot, koneksi ADB, capture, dan kontrol tanpa sentuhan lokal. Jika tidak lulus, catat sebagai kebutuhan yang belum terpenuhi; jangan diam-diam menggantinya dengan remote yang memerlukan persetujuan setiap sesi.

Sumber: [arsitektur scrcpy](https://github.com/Genymobile/scrcpy/blob/master/doc/develop.md), [ADB](https://developer.android.com/tools/adb), [persistence menurut maintainer](https://github.com/Genymobile/scrcpy/issues/4101).

### 6.3. Windows: service, helper, capture, dan input

- Service menangani identitas, konektivitas, tugas, dan lifecycle helper. Capture serta input menggunakan proses/helper pada sesi desktop yang tepat.
- Jangan menganggap service pada session 0 otomatis dapat mengakses desktop pengguna.
- Capture memakai DXGI Desktop Duplication atau integrasi native yang memenuhi kebutuhan yang sama. Tangani pergantian resolusi, monitor, desktop, dan hilangnya resource capture dengan inisialisasi ulang.
- Encode video dengan latensi rendah dan kirim melalui media plane internal. Hardware acceleration dapat digunakan, tetapi kebutuhan serta fallback harus diuji pada perangkat kantor.
- Input mouse dan keyboard memakai API native dengan otorisasi sesi. `SendInput` biasa tidak otomatis dapat mengendalikan aplikasi elevated atau secure desktop.
- Dukungan wajib mencakup desktop biasa, kondisi terkunci, layar login setelah reboot, serta dialog UAC. Helper, hak proses, dan jalur desktop yang diperlukan harus dibuktikan dalam uji teknis.
- Jika dibutuhkan, Ctrl+Alt+Del memakai mekanisme OS yang diizinkan, bukan sekadar mengirim kombinasi tombol biasa. Jangan menonaktifkan UAC untuk memenuhi pengujian.
- Untuk komputer multi-monitor, operator dapat memilih layar yang dikendalikan dan koordinat input harus mengikuti layar aktif.
- Password login Windows dimasukkan operator melalui sesi yang terlindungi; RustCtrl tidak perlu menyimpan kredensial Windows tersebut.

Sumber: [interactive services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services), [SendInput dan UIPI](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput), [Desktop Duplication](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput), [SendSAS](https://learn.microsoft.com/en-us/windows/win32/api/sas/nf-sas-sendsas).

### 6.4. Batas transfer data

Remote tidak menyediakan file manager atau transfer file bebas seperti aplikasi remote desktop umum. Pengiriman APK, installer, script, serta komponen scrcpy tetap diperbolehkan sebagai bagian tugas pengelolaan yang diotorisasi, bukan fitur transfer file umum bagi operator.

## 7. Pengelolaan perangkat dan tugas massal

### 7.1. Android TV

- Inspeksi dan daftar paket terpasang.
- Instalasi atau pembaruan APK yang dipilih admin.
- Debloat melalui operasi seperti `pm uninstall --user 0`, dengan profil paket per model/firmware dan hasil per paket.
- Kustomisasi launcher sesuai kemampuan perangkat.
- Provisioning ADB dan pemeriksaan persistence yang didukung perangkat.
- Restart/shutdown sesuai kemampuan endpoint.

Profil debloat harus menyebutkan paket dan perubahan yang dilakukan. Jangan mengasumsikan daftar paket aman dipakai pada semua merek. Bedakan uninstall untuk user 0 dari penghapusan permanen paket sistem; kemampuan pemulihan harus dilaporkan sesuai perangkat yang diuji.

### 7.2. Windows

- Mengumpulkan CPU, RAM, disk, uptime, dan proses aktif.
- Menjalankan PowerShell, Batch, atau CMD dengan konteks eksekusi yang eksplisit, timeout, exit code, serta stdout/stderr.
- Menjalankan silent installer `.exe` dan `.msi` dengan argumen yang dikonfigurasi per paket. Jangan mengasumsikan seluruh installer memakai argumen silent yang sama.
- Mengirim pembaruan aplikasi dan paket maintenance.
- Menjalankan restart/shutdown serta profil pengelolaan monitor kedua.

Paket dan script disediakan dari penyimpanan internal. Catat hash/versi artefak agar admin mengetahui payload yang dijalankan. Aktivasi paket yang memerlukan internet atau lisensi pihak ketiga tetap merupakan prasyarat paket tersebut; aplikasi RustCtrl sendiri tidak bergantung pada internet untuk mengatur tugas.

### 7.3. Konfirmasi, hasil, dan kegagalan

Sebelum eksekusi, admin melihat jenis tindakan, parameter penting, serta daftar dan jumlah perangkat sasaran. Tindakan baru dijalankan setelah konfirmasi tersebut.

- Setiap tugas memiliki ID, aktor, payload/versi, target, waktu, dan hasil per perangkat.
- Status per target membedakan pending, running, succeeded, failed, skipped-offline, timed-out, cancelled jika belum berjalan, dan unknown jika hasil tidak dapat dipastikan.
- Perangkat offline saat dispatch dilewati. Tugas tidak disimpan untuk otomatis dieksekusi ketika perangkat kembali online.
- Keberhasilan di sebagian perangkat tidak dibatalkan hanya karena target lain gagal. Tidak ada janji rollback atomik lintas perangkat.
- Admin dapat mengulang hanya target yang dipilih setelah melihat hasil sebelumnya. Perangkat yang sudah berhasil tidak otomatis dijalankan ulang.
- Transport retry menggunakan ID eksekusi untuk mencegah aksi ganda. Koneksi terputus setelah dispatch tidak membuktikan tugas gagal; rekonsiliasi hasil sebelum menyarankan pengulangan.
- Pembatalan menghentikan dispatch yang belum dimulai. Proses installer atau perintah yang sedang berjalan tidak selalu dapat dibatalkan atau dipulihkan dengan aman.
- Tampilkan exit code, waktu, serta ringkasan error yang dapat ditindaklanjuti tanpa membocorkan rahasia.

## 8. Pengaturan aplikasi antrian dan monitor kedua

Modul ini merupakan fitur versi pertama untuk endpoint Windows.

- Enumerasi monitor melalui API Win32 seperti `EnumDisplayMonitors` dan `GetMonitorInfoW`.
- Admin membuat profil per perangkat atau kelompok: executable, argumen, konteks pengguna, cara mengenali jendela melalui PID/judul, layar tujuan, dan mode tampilan.
- Pilih monitor berdasarkan identitas yang tersedia dan posisi layar; jangan hanya menganggap indeks Display 2 selalu menunjuk perangkat fisik yang sama.
- Pantau proses dan jendela, pindahkan jendela ke monitor tujuan, lalu terapkan mode tampilan sesuai profil.
- `SetWindowPos` dan maximize bukan jaminan fullscreen eksklusif. Jika aplikasi membutuhkan mode eksklusif, gunakan kemampuan aplikasi itu dan buktikan melalui uji. Borderless/fullscreen biasa harus dibedakan dari mode eksklusif.
- Jika monitor tujuan terlepas atau tidak tersedia, pulihkan jendela ke monitor utama agar aplikasi tetap dapat diakses. Ketika monitor kembali, evaluasi ulang profil tanpa loop perpindahan jendela.
- Jika aplikasi crash, luncurkan ulang sesuai profil dan pulihkan posisinya. Gunakan batas frekuensi restart agar aplikasi yang terus gagal tidak membentuk loop tanpa batas.
- Admin dapat mengaktifkan atau menonaktifkan pengawasan profil secara eksplisit sebelum maintenance atau penghentian aplikasi.
- Aplikasi desktop dijalankan pada sesi pengguna yang sesuai, bukan sebagai jendela service pada session 0.

Executable dan perilaku aplikasi antrian kantor belum diberikan. Fitur dinyatakan diterima setelah diuji pada aplikasi yang benar-benar digunakan, termasuk cara launch, fullscreen, crash recovery, dan pelepasan monitor.

## 9. Antarmuka controller GPUI

- Sidebar mengelompokkan perangkat berdasarkan Windows/Android TV, lokasi, grup VLAN, serta status.
- Daftar atau grid status memiliki pencarian, filter, waktu terakhir terhubung, dan aksi remote.
- Dashboard tidak harus menampilkan pratinjau layar seluruh perangkat. Video dibuka ketika sesi remote dimulai.
- Halaman detail menampilkan inventaris, telemetry, kesiapan remote, serta tugas terakhir.
- Panel remote menampilkan video, kontrol layar/monitor, status sesi, pemilik sesi, dan tindakan mengakhiri koneksi.
- Toolbar admin mencakup debloat, instalasi APK, push script, deployment paket, restart/shutdown, dan profil aplikasi antrian.
- Halaman tugas menampilkan progres serta hasil per perangkat, bukan hanya satu status agregat.
- Log dan terminal output menggunakan virtual scrolling serta pembatasan buffer supaya UI tidak macet saat output paralel bertambah.
- Pekerjaan jaringan, scan, decode video, dan tugas perangkat tidak memblokir thread UI. State UI disampaikan melalui mekanisme GPUI yang sesuai.
- Kesalahan dibedakan antara server tidak tersedia, endpoint offline, ADB belum diotorisasi, capture gagal, input tidak tersedia, dan perangkat sedang dipakai staf lain.

## 10. Struktur workspace

```text
rustctrl/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── SPEC.md
├── README.md
├── assets/
│   ├── binaries/                 # ADB/scrcpy yang dipin dan metadata lisensi
│   └── icons/
├── crates/
│   ├── rustctrl_core/            # Tipe domain, status, error, konfigurasi
│   ├── rustctrl_protocol/        # API, autentikasi kanal, kontrak event/media
│   ├── rustctrl_server/          # Akun, registry, database, sesi, audit, API
│   ├── rustctrl_network/         # Scan, routing config, koneksi dan reconnect
│   ├── rustctrl_tasks/           # Dispatch, deduplikasi, hasil per perangkat
│   ├── rustctrl_android/         # Adapter ADB, paket, provisioning, scrcpy
│   ├── rustctrl_media/           # Encode/decode, relay dan integrasi video
│   ├── rustctrl_agent/           # Windows Service, telemetry, executor
│   ├── rustctrl_windows_native/  # FFI, desktop helper, input, display manager
│   └── rustctrl_controller/      # GPUI, dashboard, task view, remote panel
├── packaging/                    # Windows, AlmaLinux, dan service Linux
└── docs/
    ├── deployment.md             # Port, VLAN, sertifikat, instalasi offline
    └── compatibility.md          # OS, TV, GPU/driver dan hasil uji
```

Struktur tersebut merupakan rancangan modul, bukan klaim bahwa crate sudah tersedia. Server dan agent tidak bergantung pada GPUI. Controller lintas platform tidak boleh menarik modul Win32 tanpa batas kompilasi yang sesuai.

## 11. Kriteria penerimaan versi pertama

| Area | Bukti yang harus tersedia |
| --- | --- |
| Kapasitas | Sekitar 120 endpoint terdaftar; heartbeat, telemetry, pencarian, dan UI tetap berjalan saat 10 sesi remote gabungan Windows/TV aktif. |
| Identitas | Perubahan IP dan restart controller/server tidak menggandakan perangkat atau menghapus inventaris. |
| Lintas VLAN | Remote dan tugas berhasil pada setiap VLAN yang didukung dengan aturan routing/firewall terdokumentasi. |
| Offline internet | Login, monitoring, remote, dan tugas dari paket internal berhasil ketika akses internet diputus. |
| Akun dan hak akses | Operator tidak dapat menjalankan aksi admin melalui UI maupun API; akun yang dinonaktifkan tidak dapat membuka sesi baru. |
| Eksklusivitas | Dua permintaan bersamaan untuk satu perangkat hanya menghasilkan satu pemilik; controller crash akhirnya melepas lease tanpa membiarkan dua jalur input aktif. |
| Windows unattended | Setelah reboot, operator dapat mengakses login, lock/unlock, desktop, dan UAC tanpa persetujuan lokal; perubahan display tidak mematikan remote secara permanen. |
| Android TV unattended | Untuk setiap model/firmware yang didukung, setelah reboot operator dapat melihat layar dan memakai D-pad/Home/Back tanpa menyentuh TV. |
| Controller Windows dan AlmaLinux | Build/paket terpasang pada lingkungan staf yang tercatat; dashboard, render video, input, dan reconnect lulus uji. |
| Tugas massal | Campuran target sukses, gagal, dan offline menghasilkan status yang benar; retry terpilih tidak mengulang target sukses atau menjalankan tugas lama saat perangkat online. |
| Pengelolaan TV | Inspeksi paket, instalasi APK, debloat, dan launcher lulus pada profil model yang didukung, dengan hasil per perubahan. |
| Pengelolaan Windows | Telemetry, script, installer, update, dan restart/shutdown memberi hasil yang dapat ditelusuri pada endpoint target. |
| Monitor kedua | Aplikasi antrian aktual diluncurkan, ditempatkan, dipulihkan setelah crash, dan tetap dapat diakses ketika monitor dilepas. |
| Audit dan pemulihan | Aktor, perangkat, sesi, dan hasil tugas bertahan setelah restart server; backup dapat dipulihkan; rahasia tidak masuk log. |

Uji kapasitas harus mencatat hardware server/controller, jaringan, resolusi, codec, FPS, latency, CPU/RAM, bandwidth, serta durasi uji. Belum ada angka FPS atau latency yang disepakati; tetapkan baseline terukur pada uji awal, kemudian jadikan hasil yang disetujui sebagai batas performa rilis. Jangan menuliskan angka benchmark seolah sudah dibuktikan.

## 12. Data lapangan dan pembuktian teknis yang masih dibutuhkan

Seluruh fitur tetap masuk versi pertama. Data dan pengujian berikut menentukan apakah implementasinya benar-benar memenuhi spec.

1. Inventaris merek/model, versi Android, firmware, dan metode ADB pada sekitar 20 TV. Tahun pembelian 2020 ke atas tidak cukup untuk menyimpulkan kompatibilitas.
2. Versi AlmaLinux, arsitektur CPU, X11/Wayland, GPU/driver, serta baseline paket yang digunakan staf.
3. Versi/edisi Windows endpoint dan ketersediaan Windows Server dengan desktop interaktif.
4. Identitas serta cara menjalankan aplikasi antrian, kebutuhan fullscreen, dan konfigurasi monitor nyata.
5. Uji bridge scrcpy ke panel GPUI, media relay internal, capture/input Windows pada login dan UAC, serta pemulihan koneksi.
6. Daftar VLAN/CIDR, routing, port yang diizinkan, dan perubahan alamat perangkat. Nama VLAN saja tidak menjamin konektivitas.
7. Hardware server, retensi audit, jadwal backup, kapasitas penyimpanan paket, dan hasil uji performa.

Kegagalan uji wajib dicatat sebagai gap yang harus diselesaikan. Persetujuan terhadap rancangan tidak menjadi pengganti hasil pengujian. Ketergantungan dan binary yang dibundel harus memiliki versi serta lisensi yang tercatat, dan paket instalasi harus menyediakan kebutuhan runtime untuk operasi offline.
