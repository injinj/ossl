# SSL (Source Sink Library) 4.x sink wire protocol — notes from captures, 2026-09-23

Server: ADS 3.x (`/usr/ads/bin/ads`, ads1..6.www, port 8101, `*ads*allowSSLConnections : True`;
ads1 has `*ads*sslMsgPacking : False`, others True).  Client: `/usr/ads/demo/example` (SSL 4.5 sink
demo), `-E ssl40 | ssl45 | ssl40be | sslauto` (sslauto → SSL40BE against this ADS).
Captures `*.bin` here = `proxy.py` records: `<c tag><f64 t><u32 len><bytes>` per read.  Scripts:
`runcap2.sh <name> <ads> <ver> svc:item[,svc:item]` (env WAIT REQTYPE USER_NAME), `ctl.py file.bin`
prints every non-update message in time order, `frames.py`, `dump.py`, `parse.py`.
Client reads `./ipcroute` from cwd (ignores IPCROUTE); port name via getservbyname (`rmds_sink 8101/tcp`).

## 1. Connect record (identical in all dialects)
```
C→S 12 B: 00 00 00 12  00 00 00 04  00 0c  00 00
S→C 13 B: 00 0d  02 05  00 00 00 00  04  0c e4  00 00      (0x0ce4 = 3300; 04 = ipc version?)
```
Not yet decoded further; constant across ssl40/45/40BE, users, ADS instances.

## 2. Frame (identical in all dialects)
```
u16 frame_len | 04 00 06 | u8 flags (00 client, 02 server) | { u16 msg_len | msg }*
```
msg_len includes its own 2 bytes.  Packing (several msgs per frame) happens **only with 40BE**
and only when `*ads*sslMsgPacking : True` (up to 18 updates/frame seen); ssl40/ssl45 = 1 msg/frame.

## 3. Full-header message (ssl40, ssl45, and the login/login-ack of 40BE)
```
0c | fixed_len | proto (00 01 = 4.0, 00 04 = 4.5) | ver (04 ssl40, 05 ssl45, 06 ssl40be) | type
   | u32 session  (client sends 0; server sends its per-connection id, echoed in every server msg)
then fixed_len bytes of FIXED fields: tag + fixed-width value
then VARIABLE fields to end of msg: tag | u16 len | value
```
Fixed and variable tags are separate namespaces (0d is u8 in fixed, position string in variable).

Fixed-field widths seen:
| tag | width | meaning (best guess) | values seen |
|---|---|---|---|
| 04 | u32 | client request id, echoed in image | 1 |
| 08 | u16 | ? | ffff |
| 0a | u8  | request type (ssl45 open) | 02 streaming, 00 snapshot |
| 0b | u16 | ? (open) | 0001 |
| 0c | u32 | ? (open) | 1 |
| 0d | u8  | ? (login, login-ack 40) | 00 |
| 0f | u16 | client-side value, differs per run | 2537, 27b7 (server echoes 25b7 in 45 ack) |
| 14 | 3 B | ? (image) | 00 02 00 |
| 15 | u16 | ? (image, update) | 0002 |
| 16 | u16 | ? (image, update) | 0000 |
| 17 | u32 | per-item message counter (image 1, updates 2,3,…; 0x127 in a 318 re-image) | |
| 1a | u32 | ? (45 login-ack) | 0x0BEBC200 = 200,000,000 |
| 1c | u32 | group id (per service; 0 for snapshot) | 1, 2, 0 |
| 1d | u16 | **ping interval seconds** | 0x14 = 20 (pings observed every 20 s) |
| 1e | u8  | ? (login-ack) | fe (40), 19 (45) |
| 29 | u32 | ? (45) | 0 |
| 2a | u8  | ? (45) | 01 |
| 2b | u32 | client request sequence (45): open 1, close 2, open 3…; server echoes 0 | |
| 2d | u32 | ? (45) client 0x0a, server 0x3fffffff (a limit/window) | |

Variable-field tags: 01 service name, 02 item name, 06 status text (RWF state text passed
through, e.g. "Item Refresh Completed", "NOT_FOUND"), 07 data (Marketfeed), 08 empty (open),
09 user name, 0c application id ("256"), 0d position ("127.0.0.1/net"), 0e instance ("chex.1" /
"ads1"), 10 server name ("ads1.ads1.ads", 40 ack), 12 "ads", 13 host ("chex" / "ads1", 45).

Message types (byte 5 of header):
| | ssl40 | ssl45 |
|---|---|---|
| C login | 0d (fixed 0b: 08 ffff, 0f pid?, 0d 00, 1d 0014) | 06 (fixed 17: + 2a 01, 29 0, 2d 0a) |
| S login ack | 0f (fixed 04: 0d 00, 1e fe; var 10 name) | 08 (fixed 1e: 1a, 1d, 2a, 29, 2b, 2d, 1e, 0f; var 13 0e 12) |
| C directory req | 18 (empty) | (none seen — 45 server pushes directory after login) |
| S directory | 19 (var 07 = `06 04 ADH5 02 01 04 ADH1 02 01 …` one msg) | 0d, one per service (fixed 0f: 14 01?, 2b 0, 1a, 15 0002; var 01 name) |
| C open | 12 (fixed 0d: 04 1, 0b 0001, 0c 1; var 01 02 08) | 0a (fixed 14: 0a type, 04, 0b, 0c, 2b seq; var 01 02 08) |
| S image | 23 (fixed 14: 14 15 16 04 1c; var 01 02 04"" 05"" 06 text 07 MF) | 0f (fixed 1e: 14 15 16 1c 17 04 2b; same var) |
| S update | 24 (fixed 0b: 15 16 17; var 01 02 07 MF) | 10 (same) |
| C close | 10 (var 01 02) | 09 (fixed 05: 2b seq; var 01 02) |
| S close/open ack | — | 1c (fixed 05: 2b 0) sent right after each image |
| S ping | (not captured) | 0b (empty) every 20 s |
| C ping | | 0c (empty), sent in reply to server ping |

## 4. 40BE compact messages (everything after login/login-ack)
```
u8 flags | u8 type | u8 class (05 = control/update, 06 = open/image) | positional fields
```
| msg | bytes |
|---|---|
| S login text | `00 0d 05 fe | u16len "ads1.ads1.ads"` (fe = tag 1e value) |
| C dir req | `00 0f 05 00 00 00 01` |
| S dir entry | `00 0b 05 | u16 svc_id | 00 01 00 00 00 01 | u8len name | 00 02` — ids assigned in this order per session |
| S dir end | `00 0e 05 00 00 00 01` |
| C open | `02 13 06 03 | u16 svc | 00 00 00 01 (req id) | 02 (type: stream) | u8len name | 00 01 00 00 00 01` |
| S image | `02 02 06 09 | u16 svc | 00 00 00 00 | u16 group | 00 02 | 00 00 | u8len name | 00 00 00 01 (req id) | u16len text | u16 mflen | MF` |
| S update | `00 01 05 | u16 svc | u8len name | u16 mflen | MF` |
| C close | `00 14 05 | u16 svc | u8len name` |
| S ping | `00 05 05 00 00 00 00` every 20 s |
| C ping | `00 12 05 00 00 00 00` |
Service by u16 id from the directory, item by name in every message (the u32 "req id" is 1 for
every open — not a handle).  Update = 177 B vs 203 B in ssl40/45 for the same MF body.

## 5. Payload
Marketfeed, u16 length prefixed: image `<FS>340<US>XX<GS>RIC<US>RTL<US>1<RS>fid<US>val…<FS>`,
update `<FS>316<US>XX<GS>RIC<US><RS>…<FS>`, periodic verify `318` delivered as an image message.
Not-found: normal image msg, status text "NOT_FOUND", body `<FS>340<US>XX<GS>NAME<US>0<US>1<RS>3857<US>0<RS>1008<US>NOT_FOUND<FS>`.
Values are ADS-formatted (`+64 4/8`, `20 JUN 1995`, 16-char padded strings, enum numbers).

## 5b. Source down / up (adh3 stopped 35 s while watching ADH3/INTC.O; captures down_be, down_45, down_45b)
ADS log: "Source ADH3 has shut down" → 0.1 s later the sink gets a **group status**, no per-item message:
- 40BE: `00 08 05 | u16 svc | 01 (state: down/stale) | 00 | u32 group | u16len "GA23: Service has gone down. Will recall when service becomes available."`
        then `00 09 05 | u16 svc | u32 group | u32 new_group (0)`  — group merge, like RSSL group status merge
- ssl45: type 16, fixed `14 01 02 00 | 1c group | 2b 0`, var `01 svc | 06 text`  (tag 14 = 3-byte status triple; image has 00 02 00)
         then type 17, fixed `1c group | 1f new_group (0) | 2b 0`, var `01 svc`
Updates stop.  **Recovery differs**: 40BE — ~10 s after "Service ADH3 has started" the ADS re-images the item
(the feed's 318 verify, sent as an image msg) and updates resume; no explicit "recalled" message.
ssl45 — nothing: no re-image, no updates, no directory/service-up message for 78 s after the service was back
(reproduced twice).  Either 4.5 semantics put the recall on the client (SSL_SNK_MO_WATCHLIST / re-open on service up)
and `example` doesn't do it, or the ADS drops 4.5 items on group-merge-to-0.  Needs an RFA 7 SSLED client to settle.
Group ids are per ADS instance (ADH3 = group 3 on ads1, group 2 on ads2).

## 6. Open questions
connect record fields; tags 08 0b 0c 14 15 16 1a 29 2a 2d; what `08 ""` in open carries (DACS
lock?); status/stale/group-status messages (need a source going down); inserts (SSL_MT_INSERT);
compression (`*ads*compressionType : 1`); 2.2-mount-version clients; source-side (`sslSrcMount`).

## 7. Dictionaries recovered from `~/rai/RaiCore/src/feed/reut/ssl.h` (SSL 4.5 API header, 1994 ©) and
##    `/usr/reuters-ssl/lib/libssl.a` (32-bit, 2007, `ipctrace.o` = the library's own message tracer) — 2026-09-23 19:15
Method: `ar x libssl.a ipctrace.o rdbeparser.o …`; `.data` pointer tables → name arrays; `write_fix_data` /
`write_var_data` switch jump tables → tag→format-string (script `ipctrace_tables.py`, needs objdump).  Same
tables found in the 2016 `example` binary (`.data` 0x67c308 = 4.5 types, 0x67c6e8 = sink 4.0 types).

### Header (confirmed by the tracer's own printf: "msg_length hdr_length fixed_length / header flags /
### prot_type / prot_version / msg_type / user_id")
```
u16 msg_length | u8 hdr_length (=12, counts the u16) | u8 fixed_length | u16 prot_type | u8 prot_version | u8 msg_type | u32 user_id
```
prot_type: 1 SINK_DIST, 2 SRC_DIST, 3 RRBP, 4 "SSLLIB" (the 4.5 protocol).  prot_version (IPC_PV_*): 1 3.0.0,
2 3.0.1, 3 3.2, 4 = 4.0, 5 = 4.5; 6 = 4.0 BE (not in the 2007 tables).  user_id = server-assigned per session.

### msg_type tables (1-based)
Sink 4.0 (prot_type 1): 01 GBL_STATUS 02 GBL_UPDATE 03 PG_IMAGE 04 PG_UPDATE 05 PG_STATUS 06 RENAME 07 REC_IMAGE
08 REC_UPDATE 09 REC_STATUS 0a INSERT_REQ 0b INSERT_ACK 0c ACCESS_LOCK **0d MOUNT_REQ 0e MOUNT_NAK 0f MOUNT_ACK
10 CLOSE_REQ** 11 CLOSE_NAK **12 OPEN_REQ** 13 OPEN_NAK 14 MUX_CLI_DISMOUNT 15 MUX_CLI_FORCE_CLOSE 16 PING_REQ 17 PING
**18 SRC_TBL_REQ 19 SRC_TBL** 1a PRIORITY_REQ 1b PRIORITY_NAK 1c INSERT_NAK 1d CLIENT_START 1e CLIENT_EXIT 1f SERVICE_UP
20 SERVICE_DOWN **21 GROUP_STATUS** 22 CHANGE_GROUP **23 ITEM_IMAGE 24 ITEM_UPDATE** 25 ITEM_STATUS 26 BROADCAST
**27 GROUP_MERGE** 28 CHANNEL_STATUS 29 ITEM_UPDATE(2) 2a APPENDIX_A_REQ 2b APPENDIX_A 2c APPENDIX_A_NAK (2016 adds dictionary download)
SSL 4.5 (prot_type 4): 01 BROADCAST 02 RENAME 03 INSERT_REQ 04 INSERT_NAK 05 INSERT_ACK **06 MOUNT_REQ** 07 MOUNT_NAK
**08 MOUNT_ACK 09 CLOSE_REQ 0a IMAGE_REQ 0b PING 0c PING_ACK 0d SERVICE_STATUS** 0e PRIORITY_REQ **0f ITEM_IMAGE
10 ITEM_UPDATE** 11 ITEM_STATUS 12 MUX_CLI_DISMOUNT 13 MUX_CLI_FORCE_CLOSE 14 MUX_CLI_START 15 MUX_CLI_EXIT
**16 GROUP_STATUS 17 GROUP_MERGE** 18 CHANGE_GROUP 19 CHANNEL_STATUS 1a HALT_UPDATES 1b LOAD_REQ **1c CONFIRM_DELIVERY**
1d CRITERIA_ACK 1e CRITERIA_CLOSE 1f CRITERIA_NAK 20 CRITERIA_OPEN 21 CRITERIA_ADD_ITEMS 22 CRITERIA_DELETE_ITEMS
23 SET_MAX_UNCONFIRMED 24 DISMOUNT 25 RECONNECT_ACK 26 RECONNECT_NAK 27 RECONNECT_REQ **28 UNSOLICITED_IMAGE**
29 PERMISSION_DATA 2a SRC_IMAGE_REQ_THROTTLE 2b SRC_SERVER_MODE 2c CRITERIA_INFO 2d ITEM_UPDATE(2) 2e CONFIG_REQ
2f CONFIG_ACK 30 CONFIG_NAK 31 ACCESS_LOCK.   (bold = seen on the wire; every observed 4.0/4.5 type matches)
Source dist (prot_type 2, 1-based): 01 GBL_STATUS 02 GBL_UPDATE 03 IMAGE 04 PG_UPDATE 05 PG_STATUS 06 REC_IMAGE 07 REC_UPDATE
08 REC_STATUS 09 INSERT_REQ 0a INSERT_ACK 0b ACCESS_LOCK_REQ 0c ACCESS_LOCK_NAK 0d MOUNT_REQ 0e MOUNT_NAK 0f MOUNT_ACK
10 CLOSE_REQ 11 CLOSE_NAK 12 CLOSE_ACK 13 OPEN_REQ 14 OPEN_NAK 15 OPEN_ACK 16 IMAGE_NAK 17 UPDATE_NAK 18 STATUS_NAK
19 WRITE_ACK 1a REQ_IMAGE 1b IMAGE_NAK 1c DB_CLOSE 1d RENAME_REQ 1e RENAME_NAK 1f LOAD_REQ 20 SPG_REQ 21 SPG_NAK 22 READY_REQ
23 PING_REQ 24 PING_ACK 25 INSERT_NAK 26 CACHE_LOCK_REQ 27 CACHE_LOCK_NAK 28 PRIORITY 29 SEND_IMAGE_REQ 2a SEND_IMAGE_NAK
2b ITEM_IMAGE 2c ITEM_STATUS 2d ITEM_UPDATE 2e OPEN_LIMIT 2f BROADCAST 30 HALT_UPDATES 31 STANDBY 32 ACTIVE 33 GROUP_STATUS
34 CHANGE_GROUP 35 GROUP_MERGE 36 CHANNEL_STATUS.
40BE compact (empirical, own numbering, not in the 2007 lib): 01 ITEM_UPDATE 02 ITEM_IMAGE 05 PING 08 GROUP_STATUS
09 CHANGE_GROUP/MERGE 0b SERVICE_STATUS 0d MOUNT_ACK-text 0e SRC_TBL end 0f SRC_TBL_REQ 12 PING_ACK 13 IMAGE_REQ 14 CLOSE_REQ.
BE layout per `ipc_trace_be`/`rdbeparser.o` (`ssl_unpack_bitmap`): `u8 hdr_len | u8 msg_type | bitmap of present elements
(05 / 06 09 / 06 03 …) | elements in canonical order, fixed widths, no tags`.

### Fixed-element tags (`write_fix_data`), width from observation
02 status_code(u8, T2_STS_IC table: NONE PREEMPTED NO_RESOURCES NO_PERMISSION NON_UPDATING_ITEM FAILOVER_START
FAILOVER_COMPLETE TOO_MANY_ITEMS SRC_UNKNOWN NOT_OPEN) · 04 item_id(u32 = ClientItemTag) · 05 insert_id · 06 db_req_id
· 07 user_req_id · 08 req_num_items(u16; login ffff) · 0a open_req_type(u8: 0 SNAPSHOT 2 NORMAL 3 HOST) · 0b priority_class(u16)
· 0c priority_count(u32) · 0d mux_tag(u8) · 0e cache_size · 0f mount_flags(u16; client 2537/27b7, server 25b7) · 10 load
· 11 map · 12 spg_operator · 13 user id · 14 status_state(u8: 0 OK 1 STALE 2 CLOSED 3 CLOSED_RECOVER 4 NO_CHANGE; for
SERVICE_STATUS 0 DOWN 1 UP) · 15 data_type_format(u16: 1 ANSI_PAGE 2 MARKETFEED_RECORD 4 QFORM 5 TIBMSG)
· 16 data_type_descriptor(u16) · 17 sequence_number(u32) · 18 cache_size(v4) · 19 flags · 1a open_limit(u32; ADS 200 000 000
= *ads*aggregateItemLimit) · 1b Triarch configuration flags · 1c group(u32) · 1d ping interval(u16, 20) · 1e tri cnf max
item name(u8) · 1f group2(u32, merge target) · 20 filter id · 21 protocol · 22 open req flags · 23 mes req id · 24 table size
· 25 number of items · 26 criteria id · 27 criteria open option · 28 names list flag · 29 session key(u32) · 2a session
quality(u8: 1 NORMAL 2 RECOVERABLE 3 PERSISTENT) · 2b conf seq num(u32) · 2c dismount type · 2d max unconfirmed(u32; client 10,
server 3fffffff) · 2e last seq recv · 2f criteria name type · 30 criteria data info · 31 service_id.
### Variable-element tags (`write_var_data`, `tag | u16 len | bytes`)
01 source_name 02 item_name 03 new_name 04 next_name 05 prev_name 06 text 07 data 08 attributes 09 user_name
0a access_lock 0b spg list 0c app_key 0d position 0e instance id 0f tag 10 distributor name 11 criteria name 12 app name 13 hostname.
### Status codes / error tables also recovered (see `ipctrace_tables.py` output): GROUP/ITEM state info codes, SSL error
codes (NO_SESSION … NO_RESPONSE), insert NAK codes, NAK reason codes (UNIMPL_FUNC ILL_NAME NO_SUCH_ITEM … RECALL GOODBYE ACCESS_DENIED).

### Message-level source files in the lib: src/cssl/{fmtchain,fmtbechain,rdparser,rdbeparser,msg_open,msgclose,snk_open,
snkclose,snk_ping,src_ping,send_msg,conf_message,flush_buff,ipctrace}.c, src/ipc/sipcsrvr.c, src/ssl/{edapi,eddispch,edsndev,edutils}.c.
Connection versions in lib: `_conn_version_451`, `_conn_version_46`; `initSipc46Server` — the 12/13-byte connect record is
sipc 4.6.  The lib is a complete reference implementation of the sink *and* source *and* RRBP sides (32-bit, GCC 3.2.3, RHEL 3).

## 8. RFA 7.5.0.L1 SSLED client (the real legacy consumer) — 2026-09-23 21:35
Package `~/rfa7.5.0.L1.linux.rrg/` (Legacy/Examples, Libs/RHEL6_32_GCC444 incl. `libssl48.so`, `libRFA_SSLED_Adapter.so.7`,
Docs: RFA_ConfigGuide.pdf, Legacy/Docs/MFdata.pdf = Marketfeed spec, RFA_DevelopersGuide-Legacy.pdf).  32-bit only.
Built `Legacy/Examples/RFASTTicker` on chex (Fedora 43, GCC 15):
`make LIB_DIR=../../../Libs/RHEL6_32_GCC444 OUTPUT_DIR=./RHEL6_32_GCC444 CFLAGS="-m32 -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS -DLinux -D_GLIBCXX_USE_CXX11_ABI=0 -std=gnu++98 -fpermissive -w" SYSTEM_LIBS="-lpthread -ldl -lrt"`
after `ln -s libX.so.7 libX.so` in the Libs dir; runtime needs `libnsl.i686` (dnf pulled glibc 2.42-13→16 with it).
Runner `/tmp/ssltest/rfa/run.sh -s SVC -i ITEM` (LD_LIBRARY_PATH to Libs), config `rfa_ExampleRFA.cfg`: Connection_SSLED
serverList/userName + `\Control\Entitlements\dacs_*Enabled = False` (else "Entitlements Denied", no subscribe).
Findings (captures rfa_basic, rfa_down):
- RFA 7.5 SSLED **always negotiates 40BE** (login `0c 0b 00 01 06`, mount_flags 0x25a7; no config knob for 4.0/4.5 —
  `sslauto` only).  Wire byte-identical to `example -E sslauto`: same login TLVs (appId 256, position 127.0.0.1/net,
  instance chex.1), SRC_TBL_REQ, IMAGE_REQ `02 13 06 03 …`, CLOSE `00 14 05 …`, PING_ACK `00 12 05`.
- Reports the 318 verify as **UnsolicitedImage**, status text "A23: Service has gone down…" as a Status event.
- **Source down/up with RFA**: same as `example`: GROUP_STATUS + CHANGE_GROUP→0, then ADS auto-recalls with a 318
  image ~10 s after the service restarts, updates resume.  The "ssl45 no-recall" observation is moot for RFA clients.
- On shutdown RFA sent **CLOSE_REQ 4× for the same item** — a server must treat duplicate closes as idempotent.
- It opened the item 20 ms after SRC_TBL end (waits for the directory), pings every 20 s in reply to server pings.
=> Bridge target order: 40BE first (RFA 7.x, SFC, ADS-POP), 4.5/4.0 full-header only for raw SSL SDK apps that force them.
