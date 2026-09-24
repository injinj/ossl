# ossl — Open SSL (Reuters Source Sink Library) protocol

An open implementation of the SSL 4.x sink protocol that Triarch / RMDS /
RTDS distributes Marketfeed on (the ADS `rmds_ssl_sink` port, 8101), spoken by
the SSL SDK, RFA 7.x SSLED, SFC and ADS-POP consumers.  LSEG has announced the
removal of Marketfeed and SSL from RTDS (PCN206364: legacy APIs unsupported from
28 Feb 2026, protocol removal from RTDS from Q4 2028); this project keeps those
consumers running by fronting an OMM (RSSL) infrastructure with an SSL
distributor.

Status: **protocol documented, client working; server in progress.**

* `docs/PROTOCOL.md` — the wire protocol as derived from captures against
  ADS 3.x with the RFA 7.5 / SSL 4.5 demo clients and the element names the
  SSL library's own tracer prints: connect record, frame, full header
  (SSL 4.0 / 4.5), compact 4.0 BE messages, element dictionaries, message
  sequences (mount, directory, open, image, update, group status, pings).
* `include/ossl/ipc.h`, `src/ipc.cpp` — frame and message parse / build,
  element tables, message type names.
* `ossl_client` — an SSL 4.5 sink client: mounts, prints the service
  directory, opens items, decodes the Marketfeed with raimd.

      ossl_client -d ads1.www -c /path/to/RDMFieldDictionary_dir ADH1.INTC.O

The Marketfeed side lives in raimd: `MktfdMsg` (decode) and
`MktfdMsgWriter` (encode, including RWF field list -> Marketfeed through the
field iterator), so an RSSL refresh/update can be re-encoded as an SSL image /
update without an intermediate model.

Depends on raikv, raimd, libdecnumber and omm (the OMM upstream), built the
same way (`make`, siblings in `../`).

The repository directory is `openssl`; the package, library and include
directory are `ossl` / `libossl` / `include/ossl` to stay clear of the
OpenSSL crypto library's `openssl` package and `<openssl/*.h>` headers.
