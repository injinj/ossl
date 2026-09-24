#ifndef __rai_ossl__ipc_h__
#define __rai_ossl__ipc_h__

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Open SSL: the Reuters/Triarch "Source Sink Library" sink protocol as
 * spoken by an ADS on port 8101 (rmds_ssl_sink) to SSL 4.x consumers
 * (SSL SDK, RFA 7.x SSLED adapter, SFC, ADS-POP).  Everything here was
 * derived from captures against ADS 3.x with the RFA 7.5 / SSL 4.5 demo
 * clients and the field names the SSL library's own tracer prints; see
 * docs/PROTOCOL.md for the byte layouts and the observed sequences.
 *
 * Layers:
 *
 *  1. connect record   12 B client / 13 B server, once per tcp connection
 *  2. frame            u16 len | 04 00 06 | u8 flags | { u16 len | msg }*
 *  3. message          full header (protocol 4.0 / 4.5):
 *                        u16 msg_len | u8 hdr_len(12) | u8 fixed_len
 *                        | u16 prot_type | u8 prot_ver | u8 msg_type
 *                        | u32 user_id | fixed elements | variable elements
 *                      compact header (4.0 "BE", bandwidth enhancement):
 *                        u8 hdr_len | u8 msg_type | element bitmap
 *                        | elements in canonical order, no tags
 *  4. payload          Marketfeed (raimd MktfdMsg / MktfdMsgWriter)
 */

namespace rai {
namespace ossl {

/* ---- 1. connect record ------------------------------------------------ */
static const uint8_t SSL_CONNECT_REQ[ 12 ] =
  { 0x00,0x00,0x00,0x12, 0x00,0x00,0x00,0x04, 0x00,0x0c, 0x00,0x00 };
static const uint8_t SSL_CONNECT_ACK[ 13 ] =
  { 0x00,0x0d, 0x02,0x05, 0x00,0x00,0x00,0x00, 0x04, 0x0c,0xe4, 0x00,0x00 };
static const size_t  SSL_CONNECT_REQ_LEN = 12,
                     SSL_CONNECT_ACK_LEN = 13,
                     SSL_MAX_FRAME       = 0x0ce4; /* 3300, in the ack */

/* ---- 2. frame --------------------------------------------------------- */
static const uint8_t SSL_FRAME_MAGIC[ 3 ] = { 0x04, 0x00, 0x06 };
static const uint8_t SSL_FRAME_FROM_CLIENT = 0x00,
                     SSL_FRAME_FROM_SERVER = 0x02;
static const size_t  SSL_FRAME_HDR = 6;    /* len(2) magic(3) flags(1) */

/* ---- 3. message header ------------------------------------------------ */
enum SslProtType {   /* u16 in the header, which msg_type table applies */
  PT_SINK_DIST = 1,  /* SSL 4.0 sink protocol */
  PT_SRC_DIST  = 2,  /* SSL 4.0 source protocol */
  PT_RRBP      = 3,  /* reliable broadcast messaging */
  PT_SSLLIB    = 4   /* SSL 4.5 protocol */
};
enum SslProtVer {    /* u8 IPC_PV_* */
  PV_SSL_3_0   = 1,
  PV_SSL_3_0_1 = 2,
  PV_SSL_3_2   = 3,
  PV_SSL_4     = 4,  /* full header, PT_SINK_DIST types */
  PV_SSL_45    = 5,  /* full header, PT_SSLLIB types */
  PV_SSL_40BE  = 6   /* login/ack with full header, then compact msgs */
};
static const uint8_t SSL_HDR_LEN = 12; /* counts the u16 msg_len */

/* msg_type, SSL 4.0 sink protocol (PT_SINK_DIST, 1-based) */
enum SslSinkMsgType {
  SNK_GBL_STATUS    = 0x01, SNK_GBL_UPDATE     = 0x02, SNK_PG_IMAGE     = 0x03,
  SNK_PG_UPDATE     = 0x04, SNK_PG_STATUS      = 0x05, SNK_RENAME       = 0x06,
  SNK_REC_IMAGE     = 0x07, SNK_REC_UPDATE     = 0x08, SNK_REC_STATUS   = 0x09,
  SNK_INSERT_REQ    = 0x0a, SNK_INSERT_ACK     = 0x0b, SNK_ACCESS_LOCK  = 0x0c,
  SNK_MOUNT_REQ     = 0x0d, SNK_MOUNT_NAK      = 0x0e, SNK_MOUNT_ACK    = 0x0f,
  SNK_CLOSE_REQ     = 0x10, SNK_CLOSE_NAK      = 0x11, SNK_OPEN_REQ     = 0x12,
  SNK_OPEN_NAK      = 0x13, SNK_MUX_CLI_DISMOUNT = 0x14, SNK_MUX_CLI_FORCE_CLOSE = 0x15,
  SNK_PING_REQ      = 0x16, SNK_PING           = 0x17, SNK_SRC_TBL_REQ  = 0x18,
  SNK_SRC_TBL       = 0x19, SNK_PRIORITY_REQ   = 0x1a, SNK_PRIORITY_NAK = 0x1b,
  SNK_INSERT_NAK    = 0x1c, SNK_CLIENT_START   = 0x1d, SNK_CLIENT_EXIT  = 0x1e,
  SNK_SERVICE_UP    = 0x1f, SNK_SERVICE_DOWN   = 0x20, SNK_GROUP_STATUS = 0x21,
  SNK_CHANGE_GROUP  = 0x22, SNK_ITEM_IMAGE     = 0x23, SNK_ITEM_UPDATE  = 0x24,
  SNK_ITEM_STATUS   = 0x25, SNK_BROADCAST      = 0x26, SNK_GROUP_MERGE  = 0x27,
  SNK_CHANNEL_STATUS = 0x28, SNK_ITEM_UPDATE2  = 0x29, SNK_APPENDIX_A_REQ = 0x2a,
  SNK_APPENDIX_A    = 0x2b, SNK_APPENDIX_A_NAK = 0x2c
};
/* msg_type, SSL 4.5 protocol (PT_SSLLIB, 1-based) */
enum Ssl45MsgType {
  S45_BROADCAST     = 0x01, S45_RENAME         = 0x02, S45_INSERT_REQ   = 0x03,
  S45_INSERT_NAK    = 0x04, S45_INSERT_ACK     = 0x05, S45_MOUNT_REQ    = 0x06,
  S45_MOUNT_NAK     = 0x07, S45_MOUNT_ACK      = 0x08, S45_CLOSE_REQ    = 0x09,
  S45_IMAGE_REQ     = 0x0a, S45_PING           = 0x0b, S45_PING_ACK     = 0x0c,
  S45_SERVICE_STATUS = 0x0d, S45_PRIORITY_REQ  = 0x0e, S45_ITEM_IMAGE   = 0x0f,
  S45_ITEM_UPDATE   = 0x10, S45_ITEM_STATUS    = 0x11, S45_MUX_CLI_DISMOUNT = 0x12,
  S45_MUX_CLI_FORCE_CLOSE = 0x13, S45_MUX_CLI_START = 0x14, S45_MUX_CLI_EXIT = 0x15,
  S45_GROUP_STATUS  = 0x16, S45_GROUP_MERGE    = 0x17, S45_CHANGE_GROUP = 0x18,
  S45_CHANNEL_STATUS = 0x19, S45_HALT_UPDATES  = 0x1a, S45_LOAD_REQ     = 0x1b,
  S45_CONFIRM_DELIVERY = 0x1c, S45_CRITERIA_ACK = 0x1d, S45_CRITERIA_CLOSE = 0x1e,
  S45_CRITERIA_NAK  = 0x1f, S45_CRITERIA_OPEN  = 0x20, S45_CRITERIA_ADD_ITEMS = 0x21,
  S45_CRITERIA_DELETE_ITEMS = 0x22, S45_SET_MAX_UNCONFIRMED = 0x23, S45_DISMOUNT = 0x24,
  S45_RECONNECT_ACK = 0x25, S45_RECONNECT_NAK  = 0x26, S45_RECONNECT_REQ = 0x27,
  S45_UNSOLICITED_IMAGE = 0x28, S45_PERMISSION_DATA = 0x29, S45_SRC_IMAGE_REQ_THROTTLE = 0x2a,
  S45_SRC_SERVER_MODE = 0x2b, S45_CRITERIA_INFO = 0x2c, S45_ITEM_UPDATE2 = 0x2d,
  S45_CONFIG_REQ    = 0x2e, S45_CONFIG_ACK     = 0x2f, S45_CONFIG_NAK   = 0x30,
  S45_ACCESS_LOCK   = 0x31
};
/* msg_type, 4.0 BE compact messages (observed, own numbering) */
enum SslBeMsgType {
  BE_ITEM_UPDATE    = 0x01, BE_ITEM_IMAGE      = 0x02, BE_PING          = 0x05,
  BE_GROUP_STATUS   = 0x08, BE_CHANGE_GROUP    = 0x09, BE_SERVICE_STATUS = 0x0b,
  BE_MOUNT_ACK_TEXT = 0x0d, BE_SRC_TBL_END     = 0x0e, BE_SRC_TBL_REQ   = 0x0f,
  BE_PING_ACK       = 0x12, BE_IMAGE_REQ       = 0x13, BE_CLOSE_REQ     = 0x14
};

/* fixed-width elements: tag + value, in the fixed_len block */
enum SslFixedTag {
  FX_STATUS_CODE      = 0x02, /* u8  SslStatusCode */
  FX_ITEM_ID          = 0x04, /* u32 client item tag, echoed in the image */
  FX_INSERT_ID        = 0x05, /* u32 */
  FX_DB_REQ_ID        = 0x06, /* u32 */
  FX_USER_REQ_ID      = 0x07, /* u32 */
  FX_REQ_NUM_ITEMS    = 0x08, /* u16 (login: ffff) */
  FX_OPEN_REQ_TYPE    = 0x0a, /* u8  SslReqType */
  FX_PRIORITY_CLASS   = 0x0b, /* u16 */
  FX_PRIORITY_COUNT   = 0x0c, /* u32 */
  FX_MUX_TAG          = 0x0d, /* u8 */
  FX_CACHE_SIZE       = 0x0e, /* u32 */
  FX_MOUNT_FLAGS      = 0x0f, /* u16 */
  FX_LOAD             = 0x10, /* u32 */
  FX_MAP              = 0x11, /* u8 */
  FX_SPG_OPERATOR     = 0x12, /* u8 */
  FX_USER_ID          = 0x13, /* u32 */
  FX_STATUS_STATE     = 0x14, /* u8  SslItemState / SslServiceState */
  FX_DATA_TYPE_FORMAT = 0x15, /* u16 SslDataFormat */
  FX_DATA_TYPE_DESC   = 0x16, /* u16 */
  FX_SEQUENCE_NUMBER  = 0x17, /* u32 per item message counter */
  FX_CACHE_SIZE_V4    = 0x18, /* u32 */
  FX_FLAGS            = 0x19, /* u16 */
  FX_OPEN_LIMIT       = 0x1a, /* u32 */
  FX_TRIARCH_CFG_FLAGS= 0x1b, /* u32 */
  FX_GROUP            = 0x1c, /* u32 */
  FX_PING_INTERVAL    = 0x1d, /* u16 seconds */
  FX_MAX_ITEM_NAME    = 0x1e, /* u8 */
  FX_GROUP2           = 0x1f, /* u32 merge target */
  FX_FILTER_ID        = 0x20, /* u32 */
  FX_PROTOCOL         = 0x21, /* u16 */
  FX_OPEN_REQ_FLAGS   = 0x22, /* u16 */
  FX_MES_REQ_ID       = 0x23, /* u32 */
  FX_TABLE_SIZE       = 0x24, /* u32 */
  FX_NUMBER_OF_ITEMS  = 0x25, /* u32 */
  FX_CRITERIA_ID      = 0x26, /* u32 */
  FX_CRITERIA_OPEN_OPT= 0x27, /* u16 */
  FX_NAMES_LIST_FLAG  = 0x28, /* u8 */
  FX_SESSION_KEY      = 0x29, /* u32 */
  FX_SESSION_QUALITY  = 0x2a, /* u8  SslSessionQuality */
  FX_CONF_SEQ_NUM     = 0x2b, /* u32 confirm delivery sequence */
  FX_DISMOUNT_TYPE    = 0x2c, /* u8 */
  FX_MAX_UNCONFIRMED  = 0x2d, /* u32 */
  FX_LAST_SEQ_RECV    = 0x2e, /* u32 */
  FX_CRITERIA_NAME_TP = 0x2f, /* u8 */
  FX_CRITERIA_DATA    = 0x30, /* u32 */
  FX_SERVICE_ID       = 0x31  /* u16 */
};
/* width in bytes of each fixed element value, 0 = unknown tag */
uint8_t ssl_fixed_width( uint8_t tag ) noexcept;
const char *ssl_fixed_name( uint8_t tag ) noexcept;

/* variable elements: tag | u16 len | bytes, after the fixed block */
enum SslVarTag {
  VR_SOURCE_NAME  = 0x01, VR_ITEM_NAME     = 0x02, VR_NEW_NAME      = 0x03,
  VR_NEXT_NAME    = 0x04, VR_PREV_NAME     = 0x05, VR_TEXT          = 0x06,
  VR_DATA         = 0x07, VR_ATTRIBUTES    = 0x08, VR_USER_NAME     = 0x09,
  VR_ACCESS_LOCK  = 0x0a, VR_SPG_LIST      = 0x0b, VR_APP_KEY       = 0x0c,
  VR_POSITION     = 0x0d, VR_INSTANCE_ID   = 0x0e, VR_TAG           = 0x0f,
  VR_DISTRIBUTOR_NAME = 0x10, VR_CRITERIA_NAME = 0x11, VR_APP_NAME  = 0x12,
  VR_HOSTNAME     = 0x13
};
const char *ssl_var_name( uint8_t tag ) noexcept;
const char *ssl_msg_type_name( uint16_t prot_type,  uint8_t ver,
                               uint8_t msg_type ) noexcept;

enum SslReqType      { RT_SNAPSHOT = 0, RT_NORMAL = 2, RT_HOST = 3 };
enum SslItemState    { IS_OK = 0, IS_STALE = 1, IS_CLOSED = 2,
                       IS_CLOSED_RECOVER = 3, IS_NO_CHANGE = 4 };
enum SslServiceState { SS_DOWN = 0, SS_UP = 1 };
enum SslDataFormat   { DF_UNDEFINED = 0, DF_ANSI_PAGE = 1,
                       DF_MARKETFEED_RECORD = 2, DF_QFORM = 4, DF_TIBMSG = 5 };
enum SslSessionQuality { SQ_NORMAL = 1, SQ_RECOVERABLE = 2, SQ_PERSISTENT = 3 };
enum SslSessionOption  { SO_PERMISSION_DATA = 1, SO_SINGLE_OPEN = 2,
                         SO_SRC_LOAD = 4, SO_RENAME_RECALL = 8 };
enum SslStatusCode   { SC_NONE = 0, SC_PREEMPTED = 1, SC_NO_RESOURCES = 2,
                       SC_NO_PERMISSION = 3, SC_NON_UPDATING_ITEM = 4,
                       SC_FAILOVER_START = 5, SC_FAILOVER_COMPLETE = 6,
                       SC_TOO_MANY_ITEMS = 7, SC_SRC_UNKNOWN = 8, SC_NOT_OPEN = 9 };

static inline uint16_t be16( const uint8_t *p ) {
  return (uint16_t) ( ( (uint16_t) p[ 0 ] << 8 ) | p[ 1 ] );
}
static inline uint32_t be32( const uint8_t *p ) {
  return ( (uint32_t) p[ 0 ] << 24 ) | ( (uint32_t) p[ 1 ] << 16 ) |
         ( (uint32_t) p[ 2 ] << 8 ) | p[ 3 ];
}
static inline void put16( uint8_t *p,  uint16_t v ) {
  p[ 0 ] = (uint8_t) ( v >> 8 ); p[ 1 ] = (uint8_t) v;
}
static inline void put32( uint8_t *p,  uint32_t v ) {
  p[ 0 ] = (uint8_t) ( v >> 24 ); p[ 1 ] = (uint8_t) ( v >> 16 );
  p[ 2 ] = (uint8_t) ( v >> 8 );  p[ 3 ] = (uint8_t) v;
}

/* one frame of a tcp stream: parse() returns the frame length or 0 if
 * more bytes are needed; then walk the packed messages with next() */
struct SslFrame {
  const uint8_t * buf;
  size_t          len,      /* frame length incl the 6 byte header */
                  off;      /* next message offset */
  uint8_t         flags;

  SslFrame() : buf( 0 ), len( 0 ), off( 0 ), flags( 0 ) {}
  /* 0 = need more, -1 = not a frame */
  int parse( const uint8_t *b,  size_t avail ) noexcept;
  /* next packed message: msg points after the u16 length, returns len */
  size_t next( const uint8_t *&msg ) noexcept;
  bool is_connect_req( void ) const { return this->len == SSL_CONNECT_REQ_LEN; }
};

/* a parsed full-header message */
struct SslMsg {
  const uint8_t * buf;      /* start (the u16 msg_len) */
  size_t          len;
  uint8_t         hdr_len,
                  fixed_len,
                  prot_ver,
                  msg_type;
  uint16_t        prot_type;
  uint32_t        user_id;
  size_t          fixed_off, /* offset of the fixed block */
                  var_off;   /* offset of the variable block */

  bool parse( const uint8_t *b,  size_t l ) noexcept;
  /* find a fixed element; value returned as an unsigned */
  bool get_fixed( uint8_t tag,  uint32_t &val ) const noexcept;
  /* find a variable element */
  bool get_var( uint8_t tag,  const uint8_t *&data,  size_t &dlen ) const noexcept;
  bool get_var( uint8_t tag,  const char *&s,  size_t &slen ) const {
    return this->get_var( tag, (const uint8_t *&) s, slen );
  }
  void print( void ) const noexcept;
};

/* build a full-header message into a buffer: fixed elements first, then
 * variable elements, then finish(); the u16 msg_len is filled by finish */
struct SslMsgWriter {
  uint8_t * buf;
  size_t    buflen,
            off,
            fixed_start;
  bool      in_fixed,
            ok;

  SslMsgWriter( uint8_t *b,  size_t l ) : buf( b ), buflen( l ), off( 0 ),
    fixed_start( 0 ), in_fixed( false ), ok( true ) {}
  SslMsgWriter & start( uint16_t prot_type,  uint8_t prot_ver,
                        uint8_t msg_type,  uint32_t user_id ) noexcept;
  SslMsgWriter & fixed( uint8_t tag,  uint32_t val ) noexcept;
  SslMsgWriter & var( uint8_t tag,  const void *data,  size_t dlen ) noexcept;
  SslMsgWriter & var( uint8_t tag,  const char *s ) {
    return this->var( tag, s, ::strlen( s ) );
  }
  size_t finish( void ) noexcept; /* returns msg length, 0 on error */
};

/* wrap messages into a frame: u16 len | 04 00 06 | flags | {u16 len|msg}* */
struct SslFrameWriter {
  uint8_t * buf;
  size_t    buflen,
            off;
  bool      ok;
  SslFrameWriter( uint8_t *b,  size_t l,  uint8_t flags ) noexcept;
  /* reserve space for a message of at most maxlen, returns pointer */
  uint8_t * reserve( size_t maxlen ) noexcept;
  /* commit a message written at the reserved pointer */
  void commit( size_t msglen ) noexcept;
  /* add a complete message */
  bool add( const uint8_t *msg,  size_t msglen ) noexcept;
  size_t finish( void ) noexcept;
};

}
}
#endif
