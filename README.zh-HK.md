# ESP32 AdBlocker（ESP32-S3 N16R8）

[English](README.md) | **繁體中文**

一塊 ESP32-S3 N16R8 開發板，就能做到類似 Pi-hole 的全網絡廣告攔截。只要把路由器的 DNS
指向它，網絡上所有裝置的廣告和追蹤器都會被攔截：手機、電視、遊戲機，以及任何無法自行安裝
廣告攔截器的裝置。

放行的查詢會以 **DNS-over-TLS** 加密，上游伺服器的回覆原封不動地傳回：所有記錄類型、所有
地址、CNAME 鏈和真實的 TTL。它會透過 [ntfy](https://ntfy.sh) 向你的手機回報狀態、接收指令，
並每晚自動重新啟動。

```
$ dig @192.168.0.254 doubleclick.net +short
0.0.0.0
$ dig @192.168.0.254 x.y.doubleclick.net +short
0.0.0.0
$ dig @192.168.0.254 example.com +short
172.66.147.243
104.20.23.154
```

## 功能

| | |
|---|---|
| **攔截** | 最多合併 4 份攔截清單（HOSTS、Adblock `\|\|domain^` 或純域名格式），約 250,000 個域名；預設的 Hagezi Pro 清單有 210,000 個。子域名會隨上層域名一併攔截，能識破以 CNAME 隱藏的追蹤器，你自訂的攔截／放行清單優先於所有清單 |
| **解析** | 以 DNS-over-TLS 連接 Cloudflare（或 Quad9／Google），不可用時改用一般 DNS。完整轉發所有記錄類型，768 筆遵守 TTL 的快取，最多 64 個查詢同時進行，支援 TCP 上的 DNS、IPv4 及 IPv6 |
| **區域網絡** | 區域名稱（`printer`、`nas.lan`、私人地址的反向查詢）交由路由器處理；另有「本地 DNS」頁面，可加入你自己的「IP 名稱」記錄 |
| **防繞過** | 利用 Firefox DNS-over-HTTPS 和 iCloud 私密轉送的檢測域名，自動令這兩項功能停用 |
| **可視化** | 網頁儀表板（24 小時圖表、最常攔截／放行的域名、最活躍裝置）、可篩選的查詢記錄（每行一鍵攔截／放行）、即時狀態頁 |
| **手機控制** | 開機後透過 ntfy 發送 IP 和狀態，並支援以密語保護的指令：`status`、`top`、`check`、`block`、`unblock`、`reload`、`reboot` 等 |
| **自我維護** | 按你設定的時間和時區每日重新啟動；每日重新下載攔截清單，重新啟動後一秒內從快閃記憶體還原；下載失敗每 5 分鐘重試 |
| **狀態燈** | 板載 WS2812 一眼看出設定中、攔截中、下載中、沒有互聯網或故障 |
| **韌體不含任何密碼** | WiFi、ntfy 和密碼都在網頁設定入口輸入，並儲存於 NVS，所以同一個韌體檔案人人可用 |

## 與 Pi-hole 比較

一般家庭用 Pi-hole 做的事，它大致都能做到；比不上的是規模。

| | 樹莓派上的 Pi-hole | 這塊開發板 |
|---|---|---|
| 成本／耗電 | 一部樹莓派加 SD 卡，約 3 W | 約 10 美元的開發板，不足 1 W，無需 SD 卡 |
| 攔截清單容量 | 數以百萬計的域名 | 約 250,000 個 |
| 正規表示式規則 | 有 | 沒有：只有完整域名及子域名 |
| 查詢記錄 | 長期資料庫 | 最近 6,000 個查詢，重新啟動即清空；每小時統計保留一星期 |
| DHCP 伺服器、DNSSEC 驗證 | 有 | 沒有（DHCP 由路由器負責；Cloudflare 會做驗證） |
| 加密上游 | 需額外安裝（cloudflared／unbound） | 內建 |
| 手機通知及指令 | 需額外安裝 | 內建 |

## 硬件

- **ESP32-S3 N16R8**：16 MB 快閃記憶體、8 MB 八線 PSRAM。必須有 PSRAM，攔截清單、快取和
  查詢記錄都放在裡面。已在 ESP32-S3-DevKitC-1 類型的開發板上測試。
- **2.4 GHz WiFi。** ESP32 沒有 5 GHz 無線電。
- **固定 IP 地址**：設定靜態 IP，或在路由器做 DHCP 保留。所有裝置都會把 DNS 查詢發給它，
  地址不能改變。

## 快速開始

### 1. 燒錄

從[最新發佈版本](https://github.com/Garionhk/ESP32---AdBlocker-N16R8/releases/latest)下載：

| 檔案 | 適用情況 |
|---|---|
| `adblocker-v1.0.1-esp32s3-n16r8.bin` | 首次安裝，經開發板的 **UART** 接口或 USB 轉序列埠轉接器（CP2102、CH343、FTDI）連接 |
| `adblocker-v1.0.1-esp32s3-n16r8-usbcdc.bin` | 首次安裝，經開發板的**原生 USB** 接口連接 |
| `…-app.bin`／`…-usbcdc-app.bin` | 更新已在運行的開發板，保留設定及攔截清單 |

兩個版本的分別只在序列埠記錄從哪個接口輸出，攔截功能完全一樣。

```bash
pip install esptool
```

首次安裝（寫入整個快閃記憶體）：

```bash
esptool --port /dev/cu.usbserial-XXXX --baud 921600 write-flash 0x0 adblocker-v1.0.1-esp32s3-n16r8.bin
```

更新（只寫入應用程式）：

```bash
esptool --port /dev/cu.usbserial-XXXX --baud 921600 write-flash 0x10000 adblocker-v1.0.1-esp32s3-n16r8-app.bin
```

如要自行編譯，請參閱[編譯](#編譯)。

### 2. 設定

1. 用手機連接 WiFi 網絡 **`AdBlocker-Setup-XXXX`**。**請先關閉流動數據**，否則手機可能在
   頁面載入前，就因這個網絡沒有互聯網而自行斷開。
2. 設定頁會自動彈出；如沒有，請開啟 **http://192.168.4.1**。
3. 填寫 WiFi、ntfy 主題和兩個密碼，然後按 **Save & restart**。

| 部分 | 欄位 |
|---|---|
| WiFi | 網絡（從即時掃描中選取）及密碼 |
| 地址 | 靜態 IP、閘道、子網路遮罩。三項留空即使用 DHCP |
| 上游 DNS | 一般伺服器（預設 `1.1.1.1`／`1.0.0.1`）、DNS-over-TLS 及其伺服器、區域名稱交給路由器、IPv6 |
| 攔截清單 | 最多 4 個網址、每日更新時間、子域名攔截、停用 Firefox／iCloud 繞過功能 |
| 每日重新啟動 | 開／關、時間、時區 |
| 狀態燈 | GPIO（0 = 不使用）、WS2812 或單色、亮度 |
| ntfy | 伺服器、連接埠、TLS、主題，以及可選的登入資料或權杖 |
| 密碼 | ntfy 指令密語，以及網頁管理密碼（用戶名 `admin`） |

### 3. 開機回報

你的 ntfy 主題會收到：

```
AdBlocker online
ESP32 AdBlocker v1.0.0
ip 192.168.0.254 (static)
gw 192.168.0.1
upstream DNS-over-TLS, connected to one.one.one.one; fallback 1.1.1.1 / 1.0.0.1
wifi home (-57 dBm)
settings http://192.168.0.254
blocklist 53,172 domains, downloaded 1h 10m ago (from flash)
blocking on
queries 243, blocked 109 (44%), cached 19
up 5m, last reset: power on
time 2026-10-25 17:27 PDT
next reboot 04:00 PDT, list refresh 03:00
ntfy connected
heap 109 KB, psram 136 KB free
```

使用 DHCP 地址時，訊息還會列出 MAC 地址，方便你在路由器設定保留。首次開機時，攔截清單會在
背景下載（預設的 Hagezi Pro 清單約需 20 秒），完成後會再收到一則訊息。

### 4. 把網絡指向它

在路由器的 DHCP 設定中，把 **DNS 伺服器**設為開發板的 IP，而且**只設這一個**。如果另加
`8.8.8.8` 之類的第二個伺服器，裝置就能繞過攔截。裝置重新連線後便會使用新設定。

更改設定前，可先在電腦上測試：

```bash
dig @192.168.0.254 doubleclick.net
```

回覆 `0.0.0.0` 即表示攔截正常運作。

**任何 DNS 攔截器都會被以下情況繞過：**
- **Chrome 的「使用安全 DNS」**：請關閉，或設為「使用你目前的服務供應商」。Firefox 的同類
  功能及 iCloud 私密轉送會自動被停用。
- **路由器提供的 IPv6 DNS**：開發板也會在 IPv6 上回應，但必須路由器容許你把它設為 IPv6 DNS
  伺服器才有用。如不容許，請在路由器關閉 IPv6 DNS。
- **VPN。**

## 使用方法

### 網頁

用瀏覽器開啟開發板的 IP，以 `admin` 登入。

| 頁面 | 內容 |
|---|---|
| **Status（狀態）** | 狀態報告；查詢、攔截、放行、重新下載、開／關、重新啟動 |
| **Dashboard（儀表板）** | 總數、24 小時圖表、最常攔截、最常放行、最活躍裝置 |
| **Query log（查詢記錄）** | 最近 6,000 個查詢：時間、裝置、類型、名稱、結果、延遲。可按名稱、裝置或只顯示已攔截篩選；每行都可一鍵攔截或放行 |
| **Local DNS（本地 DNS）** | 你自己的「IP 名稱」記錄，包括反向查詢 |
| **Settings（設定）** | 設定表單的所有項目 |

查詢記錄和排行榜存放在記憶體中，每次重新啟動（包括每日重新啟動）後都會清空。圖表所用的
每小時統計存放在 RTC 記憶體，每日重新啟動後仍會保留，但斷電後會消失。

### ntfy 指令

發送到你的主題，每個指令前面都要加上指令密語，例如 `sekret status`。

| 指令 | 別名 | 作用 |
|---|---|---|
| `help` | `?` | 列出所有指令 |
| `status` | `stat` | 上面那份狀態報告 |
| `stats` | | 統計數字及最近 10 個被攔截的名稱 |
| `top` | | 最常被攔截的名稱及最活躍的裝置 |
| `check <域名>` | | 是否被攔截，以及由哪一項攔截（`via doubleclick.net`） |
| `block <域名>` | | 加入你的自訂清單（域名必須能解析，以防打錯字） |
| `unblock <域名>` | `allow` | 放行，即使上層域名已被攔截 |
| `on`／`off` | | 暫停攔截，直至發送 `on` 或下次重新啟動 |
| `reload` | `refresh` | 立即重新下載攔截清單 |
| `clearcustom` | | 清除你所有自訂的攔截及放行 |
| `reboot` | `restart` | 立即重新啟動 |
| `factoryreset` | | 清除設定並重新啟動進入設定模式（保留攔截清單） |

沒有正確密語的訊息完全不會得到回覆，而任何回覆都不會重複密語。請使用又長又隨機的主題名稱：
在公開的 ntfy.sh 上，主題名稱是阻止陌生人的唯一屏障。

### 狀態燈

ESP32-S3-DevKitC-1 v1.0 的板載 WS2812 在 **GPIO 48**，v1.1 則在 **GPIO 38**；可在設定頁
更改（0 = 不使用）。單色 LED 亦可使用。

| 顏色 | 閃動方式 | 意思 |
|---|---|---|
| 黃色 | 慢閃 | 設定模式，或 WiFi 斷線 |
| 綠色 | 長亮 | 正常攔截中 |
| 藍色 | 中速閃動 | 正在下載攔截清單（這幾秒不會攔截） |
| 紫色 | 快速閃動 | 上次下載連不上互聯網，每 5 分鐘重試 |
| 青色 | 極慢閃動 | 上次下載失敗，仍以舊清單攔截 |
| 紅色 | 快閃 | 完全沒有攔截清單，不會攔截任何東西 |

## 運作原理

### 名稱比對

- **子域名隨上層域名攔截**（預設開啟）：清單上有 `doubleclick.net`，`ads.doubleclick.net`
  也會被攔截。開頭的 `www.` 一律忽略。關閉此功能即改為 hosts 檔式的完全比對。
- **最具體的一項優先。** `unblock cdn.example.com` 會放行這個名稱，即使 `example.com` 仍被
  攔截。
- **檢查 CNAME。** 放行的名稱如果原來是被攔截名稱的別名，也會一併攔截，記錄中會顯示
  `blocked (CNAME)`。
- **區域名稱交給路由器處理**（`printer`、`*.lan`、`*.home`、`*.home.arpa`、`*.internal`、
  私人地址的反向查詢），絕不會送到公共解析器。來自路由器本身的查詢不會被送回路由器，所以
  不會形成迴圈。
- **`.local`** 絕不轉發（屬於 mDNS），**`localhost`** 永遠是 `127.0.0.1`。

### 上游

放行的查詢會先嘗試 DNS-over-TLS。如果它不可用，或 0.9 秒內沒有回應，就改用一般伺服器，所以
DNS 始終可用，只是這些查詢沒有加密。狀態報告會清楚顯示目前使用哪一條路徑。

- 因為 Cloudflare 會在連線閒置約 10 秒後中斷，開發板每 7 秒發送一個極小的查詢來保持 TLS
  連線。
- 每日約 20 秒的攔截清單下載期間，DoT 會暫時讓路：晶片的內部記憶體同時只容得下幾條 TLS 連線。
- UDP 容納不下的回覆會標記為截斷，用戶端隨即改用 TCP 重試。

### 攔截清單

每份清單可以是 HOSTS（`0.0.0.0 ads.example.com`）、Adblock（`||ads.example.com^`）或
每行一個域名的格式。帶選項、路徑、萬用字元或 `@@` 例外的 Adblock 規則會被略過，因為 DNS 無法
執行這些規則。

| 清單 | 大小 | 網址 |
|---|---|---|
| **Hagezi Multi PRO**（預設） | 210,000 個，3.8 MB | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt` |
| Hagezi Multi NORMAL（較寬鬆） | 較小 | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt` |
| StevenBlack 綜合版（較保守） | 53,000 個，1.3 MB | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` |
| StevenBlack + 假新聞 + 賭博 | 較大 | `https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts` |

開發板約有 4.9 MB 空間存放域名，以一般 18 個字元計約可容納 250,000 個。合併後超出容量的清單會被
截短，下載訊息會顯示 `TRUNCATED`。

**由 v1.0.0 升級？** 新預設只適用於全新安裝及恢復原廠設定。已設定好的開發板會保留原本儲存的網址，
請在設定頁自行更改。

- **每日在更新時間下載清單**（預設 03:00）；如開機時已儲存的副本超過 24 小時，也會即時下載。
- **伺服器回應後才會取代現有清單**，所以沒有互聯網時的下載嘗試不會影響任何東西。下載中途
  失敗會從快閃記憶體還原舊清單。
- **下載後排序期間不會攔截**，Hagezi Pro 約需 20 秒。

### 每日重新啟動

預設在當地時間 04:00 啟用，支援任何 POSIX TZ 時區字串。

- **短暫中斷：** 重新啟動期間 DNS 會停止數秒；裝置會自動重試，通常不會察覺。
- **記錄原因：** 計劃中的重新啟動後，`last reset` 會顯示 `daily reboot`；其他情況則顯示硬件
  原因（`crash (panic)`、`brownout`、`power on`）。
- **不會中斷下載：** 正在下載時不會重新啟動。
- **需要時鐘：** 必須先從 NTP 取得時間，才能按時重新啟動。
- **避開 01:00–03:00：** 夏令時間轉換會跳過或重複這段時間。

## 日後更改設定

| 情況 | 做法 |
|---|---|
| 開發板已上線 | 用瀏覽器開啟它的 IP，以 `admin` 登入 |
| WiFi 斷線 | 它會開啟 `AdBlocker-Setup-XXXX`（http://192.168.4.1，需管理員登入），並每 10 秒重試連接你的路由器 |
| 搬屋，或忘記管理密碼 | 按一下 **EN** 後放手，然後**按住 BOOT** 2 秒：設定入口會開啟，無需登入 |
| 遠端 | 透過 ntfy 發送 `<密語> factoryreset` |

如果連不上 WiFi，序列埠記錄（115200 baud）會列出範圍內所有 2.4 GHz 網絡，並標明你的網絡是否
在其中，從而分辨是打錯名稱、只有 5 GHz 的網絡，還是密碼錯誤。

## 編譯

使用 [arduino-cli](https://arduino.github.io/arduino-cli/)，配合 ESP32 核心 3.1.1 或以上版本
（已用 3.3.10 測試）及 ArduinoJson：

```bash
arduino-cli core install esp32:esp32
```

```bash
arduino-cli lib install ArduinoJson
```

```bash
arduino-cli compile --fqbn "esp32:esp32:esp32s3:FlashSize=16M,PSRAM=opi,PartitionScheme=custom" --export-binaries ESP32-AdBlocker
```

如開發板經原生 USB 接口連接，請在 FQBN 加上 `,CDCOnBoot=cdc`。
`PartitionScheme=custom` 會使用專案自帶的 [`partitions.csv`](ESP32-AdBlocker/partitions.csv)：
4 MB 應用程式空間，以及 12 MB 的 LittleFS，用來儲存攔截清單副本、你的自訂清單及本地記錄。
[flash.md](flash.md)（英文）說明如何編譯可分享的韌體及燒錄。

### 測試

純邏輯部分有 265 項無需開發板的本機測試，涵蓋 DNS 封包處理（壓縮、指標迴圈、溢出、TTL 遞減、
CNAME）、攔截清單解析、設定的儲存及驗證、跨越兩次夏令時間轉換的重新啟動時間、狀態燈、本地
DNS 解析，以及包括密語檢查在內的所有 ntfy 指令。

```bash
./test/run.sh
```

### 原始碼結構

| 檔案 | 作用 |
|---|---|
| `ESP32-AdBlocker.ino` | 開機流程；設定／後備／上線三種狀態 |
| `sinkhole.cpp` | DNS 伺服器：判斷、回覆或轉發；UDP 及 TCP，IPv4 及 IPv6 |
| `dnsmsg.h` | DNS 封包格式：解析、逐一處理記錄、建立回覆、分類名稱 |
| `dnscache.cpp` | PSRAM 中的回覆快取 |
| `dot.cpp` | 迴環介面上的 DNS-over-TLS 代理 |
| `blocklist.cpp`、`blparse.h` | PSRAM 攔截清單、下載、快閃記憶體副本、你的攔截／放行清單 |
| `querylog.cpp` | 查詢記錄、每小時統計、排行榜 |
| `localdns.cpp`、`localrec.h` | 本地 DNS 記錄 |
| `webconfig.cpp` | 設定入口及網頁 |
| `ntfy.cpp`、`commands.cpp` | ntfy 串流、發送訊息、處理指令 |
| `scheduler.cpp`、`schedule.h` | 每日重新啟動、每日更新、重新啟動原因 |
| `led.cpp`、`ledstate.h` | 狀態燈 |
| `settings.cpp`、`config.h` | NVS 中的設定；可調參數 |

## 鳴謝及授權

攔截清單引擎及最初的 DNS 回應程式來自
[s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker)（s60sc 及 dateno1），採用
AGPL-3.0 授權，因此本專案同樣以 **[AGPL-3.0](LICENSE)** 發佈。如果你把修改後的版本作為網絡
服務運行，必須向其用戶提供原始碼。

預設攔截清單：[Hagezi DNS blocklists](https://github.com/hagezi/dns-blocklists)。亦支援
[StevenBlack/hosts](https://github.com/StevenBlack/hosts)。
