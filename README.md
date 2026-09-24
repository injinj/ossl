# ossl — Open SSL (Reuters Source Sink Library) protocol

An open implementation of the SSL 4.x sink protocol that Triarch / RMDS /
RTDS distributes Marketfeed on (the ADS `rmds_ssl_sink` port, 8101), spoken by
the SSL SDK, RFA 7.x SSLED, SFC and ADS-POP consumers.  LSEG has announced the
removal of Marketfeed and SSL from RTDS (PCN206364: legacy APIs unsupported from
28 Feb 2026, protocol removal from RTDS from Q4 2028); this project keeps those
consumers running by fronting an OMM (RSSL) infrastructure with an SSL
distributor.

Status: **protocol documented; client and server working against ADS 3.x and RFA 7.x.**

* `docs/PROTOCOL.md` — the wire protocol as derived from captures against
  ADS 3.x with the RFA 7.5 / SSL 4.5 demo clients and the element names the
  SSL library's own tracer prints: connect record, frame, full header
  (SSL 4.0 / 4.5), compact 4.0 BE messages, element dictionaries, message
  sequences (mount, directory, open, image, update, group status, pings).
* `include/ossl/ipc.h`, `src/ipc.cpp` — frame and message parse / build,
  element tables, message type names.
* `ossl_server` — the SSL sink distributor: SSL 4.0 / 4.5 / 4.0 BE
  consumers mount on the sink port, items are subscribed from an OMM
  upstream (an ADS RSSL port or an omm_server) through omm's EvOmmClient
  and the raikv route table, RWF field lists are re-encoded as Marketfeed.
  Tested with the RFA 7.5 SSLED adapter (BE), the SSL 4.5 demo (`-E ssl40`,
  `ssl45`, `sslauto`) and ossl_client, fed from ADS 3.x and omm_server.

      ossl_server -o 8101 -p ads1.www:14002 -c /path/to/RDMFieldDictionary_dir

* `ossl_client` — an SSL 4.5 sink client: mounts, prints the service
  directory, opens items, decodes the Marketfeed with raimd.

      ossl_client -d ads1.www -c /path/to/RDMFieldDictionary_dir ADH1.INTC.O

The Marketfeed side lives in raimd: `MktfdMsg` (decode) and
`MktfdMsgWriter` (encode, including RWF field list -> Marketfeed through the
field iterator), so an RSSL refresh/update can be re-encoded as an SSL image /
update without an intermediate model.

Depends on raikv, raimd, libdecnumber and omm (the OMM upstream), built the
same way (`make`, siblings in `../`).

Named `ossl` (repository, package, `libossl`, `include/ossl`) rather than
"openssl" to stay clear of the OpenSSL crypto library's package and
`<openssl/*.h>` headers.
