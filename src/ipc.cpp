#include <stdio.h>
#include <ossl/ipc.h>

using namespace rai;
using namespace ossl;

#ifndef OSSL_VER
#define OSSL_VER 0.0.0-0
#endif
#define STR_(x) #x
#define STR(x) STR_(x)
extern "C" const char *ossl_get_version( void ) { return STR( OSSL_VER ); }

namespace {
struct FixedDef { uint8_t tag, width; const char *name; };
static const FixedDef fixed_defs[] = {
  { FX_STATUS_CODE,      1, "status_code" },
  { FX_OPEN_REQ_TYPE,    1, "open_req_type" },
  { FX_MUX_TAG,          1, "mux_tag" },
  { FX_MAP,              1, "map" },
  { FX_SPG_OPERATOR,     1, "spg_operator" },
  { FX_STATUS_STATE,     1, "status_state" },
  { FX_MAX_ITEM_NAME,    1, "max_item_name" },
  { FX_NAMES_LIST_FLAG,  1, "names_list_flag" },
  { FX_SESSION_QUALITY,  1, "session_quality" },
  { FX_DISMOUNT_TYPE,    1, "dismount_type" },
  { FX_CRITERIA_NAME_TP, 1, "criteria_name_type" }, /* 11 */

  { FX_REQ_NUM_ITEMS,    2, "req_num_items" },
  { FX_PRIORITY_CLASS,   2, "priority_class" },
  { FX_MOUNT_FLAGS,      2, "mount_flags" },
  { FX_DATA_TYPE_FORMAT, 2, "data_type_format" },
  { FX_DATA_TYPE_DESC,   2, "data_type_descriptor" },
  { FX_FLAGS,            2, "flags" },
  { FX_PING_INTERVAL,    2, "ping_interval" },
  { FX_PROTOCOL,         2, "protocol" },
  { FX_OPEN_REQ_FLAGS,   2, "open_req_flags" },
  { FX_CRITERIA_OPEN_OPT,2, "criteria_open_option" },
  { FX_SERVICE_ID,       2, "service_id" }, /* 11 */

  { FX_ITEM_ID,          4, "item_id" },
  { FX_INSERT_ID,        4, "insert_id" },
  { FX_DB_REQ_ID,        4, "db_req_id" },
  { FX_USER_REQ_ID,      4, "user_req_id" },
  { FX_PRIORITY_COUNT,   4, "priority_count" },
  { FX_CACHE_SIZE,       4, "cache_size" },
  { FX_LOAD,             4, "load" },
  { FX_USER_ID,          4, "user_id" },
  { FX_SEQUENCE_NUMBER,  4, "sequence_number" },
  { FX_CACHE_SIZE_V4,    4, "cache_size_v4" },
  { FX_OPEN_LIMIT,       4, "open_limit" },
  { FX_TRIARCH_CFG_FLAGS,4, "triarch_config_flags" },
  { FX_GROUP,            4, "group" },
  { FX_GROUP2,           4, "group2" },
  { FX_FILTER_ID,        4, "filter_id" },
  { FX_MES_REQ_ID,       4, "mes_req_id" },
  { FX_TABLE_SIZE,       4, "table_size" },
  { FX_NUMBER_OF_ITEMS,  4, "number_of_items" },
  { FX_CRITERIA_ID,      4, "criteria_id" },
  { FX_SESSION_KEY,      4, "session_key" },
  { FX_CONF_SEQ_NUM,     4, "conf_seq_num" },
  { FX_MAX_UNCONFIRMED,  4, "max_unconfirmed" },
  { FX_LAST_SEQ_RECV,    4, "last_seq_recv" },
  { FX_CRITERIA_DATA,    4, "criteria_data_info" } /* 24 */
};
#define bit2( x, y )    ( ( (uint64_t) 1 << x ) | ( (uint64_t) 1 << y ) )
#define bit3( x, y, z ) ( bit2( x, y ) | ( (uint64_t) 1 << z ) )
static const uint64_t tag_w[ 3 ] = {
  bit3( FX_STATUS_CODE,        FX_OPEN_REQ_TYPE,   FX_MUX_TAG         ) |
  bit3( FX_MAP,                FX_SPG_OPERATOR,    FX_STATUS_STATE    ) |
  bit3( FX_MAX_ITEM_NAME,      FX_NAMES_LIST_FLAG, FX_SESSION_QUALITY ) |
  bit2( FX_DISMOUNT_TYPE,      FX_CRITERIA_NAME_TP ), /* 11 */

  bit3( FX_REQ_NUM_ITEMS,      FX_PRIORITY_CLASS,  FX_MOUNT_FLAGS    ) |
  bit3( FX_DATA_TYPE_FORMAT,   FX_DATA_TYPE_DESC,  FX_FLAGS          ) |
  bit3( FX_PING_INTERVAL,      FX_PROTOCOL,        FX_OPEN_REQ_FLAGS ) |
  bit2( FX_CRITERIA_OPEN_OPT,  FX_SERVICE_ID ), /* 11 */

  bit3( FX_ITEM_ID,            FX_INSERT_ID,       FX_DB_REQ_ID         ) |
  bit3( FX_USER_REQ_ID,        FX_PRIORITY_COUNT,  FX_CACHE_SIZE        ) |
  bit3( FX_LOAD,               FX_USER_ID,         FX_SEQUENCE_NUMBER   ) |
  bit3( FX_CACHE_SIZE_V4,      FX_OPEN_LIMIT,      FX_TRIARCH_CFG_FLAGS ) |
  bit3( FX_GROUP,              FX_GROUP2,          FX_FILTER_ID         ) |
  bit3( FX_MES_REQ_ID,         FX_TABLE_SIZE,      FX_NUMBER_OF_ITEMS   ) |
  bit3( FX_CRITERIA_ID,        FX_SESSION_KEY,     FX_CONF_SEQ_NUM      ) |
  bit3( FX_MAX_UNCONFIRMED,    FX_LAST_SEQ_RECV,   FX_CRITERIA_DATA ) /* 24 */
};
#undef bit3
#undef bit2
static const char *var_names[] = {
  "?"          , "source_name" , "item_name"    , "new_name"   , "next_name"  ,
  "prev_name"  , "text"        , "data"         , "attributes" , "user_name"  ,
  "access_lock", "spg_list"    , "app_key"      , "position"   , "instance_id",
  "tag"        , "distrib_name", "criteria_name", "app_name"   , "hostname"
};
static const char *sink40_types[] = {
  "?"          , "GBL_STATUS"  , "GBL_UPDATE"   , "PG_IMAGE"   , "PG_UPDATE"  ,
  "PG_STATUS"  , "RENAME"      , "REC_IMAGE"    , "REC_UPDATE" , "REC_STATUS" ,
  "INSERT_REQ" , "INSERT_ACK"  , "ACCESS_LOCK"  , "MOUNT_REQ"  , "MOUNT_NAK"  ,
  "MOUNT_ACK"  , "CLOSE_REQ"   , "CLOSE_NAK"    , "OPEN_REQ"   , "OPEN_NAK"   ,
  "MUX_CLI_DISMOUNT"           , "MUX_CLI_FORCE_CLOSE"         , "PING_REQ"   ,
  "PING"       , "SRC_TBL_REQ" , "SRC_TBL"      , "PRIORITY_REQ", "PRIORITY_NAK", "INSERT_NAK", "CLIENT_START", "CLIENT_EXIT",
  "SERVICE_UP" , "SERVICE_DOWN", "GROUP_STATUS" , "CHANGE_GROUP", "ITEM_IMAGE",
  "ITEM_UPDATE", "ITEM_STATUS" , "BROADCAST"    , "GROUP_MERGE", "CHANNEL_STATUS",
  "ITEM_UPDATE2", "APPENDIX_A_REQ", "APPENDIX_A", "APPENDIX_A_NAK"
};
static const char *ssl45_types[] = {
  "?"          , "BROADCAST"   , "RENAME"       , "INSERT_REQ" , "INSERT_NAK" ,
  "INSERT_ACK" , "MOUNT_REQ"   , "MOUNT_NAK"    , "MOUNT_ACK"  , "CLOSE_REQ"  ,
  "IMAGE_REQ"  , "PING"        , "PING_ACK"     , "SERVICE_STATUS",
  "PRIORITY_REQ", "ITEM_IMAGE" , "ITEM_UPDATE"  , "ITEM_STATUS",
  "MUX_CLI_DISMOUNT"           , "MUX_CLI_FORCE_CLOSE"         , "MUX_CLI_START",
  "MUX_CLI_EXIT", "GROUP_STATUS", "GROUP_MERGE" , "CHANGE_GROUP",
  "CHANNEL_STATUS"             , "HALT_UPDATES" , "LOAD_REQ"   ,
  "CONFIRM_DELIVERY"           , "CRITERIA_ACK" , "CRITERIA_CLOSE",
  "CRITERIA_NAK"               , "CRITERIA_OPEN", "CRITERIA_ADD_ITEMS",
  "CRITERIA_DELETE_ITEMS"      , "SET_MAX_UNCONFIRMED",
  "DISMOUNT"  , "RECONNECT_ACK", "RECONNECT_NAK", "RECONNECT_REQ",
  "UNSOLICITED_IMAGE"          , "PERMISSION_DATA", "SRC_IMAGE_REQ_THROTTLE",
  "SRC_SERVER_MODE"            , "CRITERIA_INFO", "ITEM_UPDATE2",
  "CONFIG_REQ" , "CONFIG_ACK"  , "CONFIG_NAK"   , "ACCESS_LOCK"
};
static const char *be_types[ 0x15 ] = {
  "?", "ITEM_UPDATE", "ITEM_IMAGE", "?", "?", "PING", "?", "?", "GROUP_STATUS",
  "CHANGE_GROUP", "?", "SERVICE_STATUS", "?", "MOUNT_ACK_TEXT", "SRC_TBL_END",
  "SRC_TBL_REQ", "?", "?", "PING_ACK", "IMAGE_REQ", "CLOSE_REQ"
};
}

uint8_t
rai::ossl::ssl_fixed_width( uint8_t tag ) noexcept
{
  if ( tag < 64 ) {
    uint64_t b = (uint64_t) 1 << tag;
    for ( size_t i = 0; i < 3; i++ )
      if ( ( tag_w[ i ] & b ) != 0 )
        return 1 << i;
  }
  return 0;
}

const char *
rai::ossl::ssl_fixed_name( uint8_t tag ) noexcept
{
  for ( size_t i = 0; i < sizeof( fixed_defs ) / sizeof( fixed_defs[ 0 ] ); i++ )
    if ( fixed_defs[ i ].tag == tag )
      return fixed_defs[ i ].name;
  return "?";
}

const char *
rai::ossl::ssl_var_name( uint8_t tag ) noexcept
{
  if ( tag < sizeof( var_names ) / sizeof( var_names[ 0 ] ) )
    return var_names[ tag ];
  return "?";
}

const char *
rai::ossl::ssl_msg_type_name( uint16_t prot_type,  uint8_t ver,
                              uint8_t msg_type ) noexcept
{
  if ( ver == PV_SSL_40BE && prot_type == 0 ) { /* compact */
    if ( msg_type < sizeof( be_types ) / sizeof( be_types[ 0 ] ) )
      return be_types[ msg_type ];
    return "?";
  }
  if ( prot_type == PT_SSLLIB ) {
    if ( msg_type < sizeof( ssl45_types ) / sizeof( ssl45_types[ 0 ] ) )
      return ssl45_types[ msg_type ];
    return "?";
  }
  if ( msg_type < sizeof( sink40_types ) / sizeof( sink40_types[ 0 ] ) )
    return sink40_types[ msg_type ];
  return "?";
}

/* ---- frame -------------------------------------------------------------- */
int
SslFrame::parse( const uint8_t *b,  size_t avail ) noexcept
{
  this->buf = b;
  this->off = 0;
  if ( avail < 2 )
    return 0;
  size_t l = be16( b );
  if ( l == 0 ) { /* the 12 byte connect request starts 00 00 00 12 */
    if ( avail < SSL_CONNECT_REQ_LEN )
      return 0;
    this->len = SSL_CONNECT_REQ_LEN;
    this->flags = 0;
    return (int) this->len;
  }
  if ( l < SSL_FRAME_HDR )
    return -1;
  if ( avail < l )
    return 0;
  if ( ::memcmp( &b[ 2 ], SSL_FRAME_MAGIC, 3 ) != 0 ) {
    /* the 13 byte connect ack is not framed either */
    if ( l == SSL_CONNECT_ACK_LEN && b[ 2 ] == 0x02 ) {
      this->len = l;
      this->flags = 0;
      return (int) l;
    }
    return -1;
  }
  this->len   = l;
  this->flags = b[ 5 ];
  this->off   = SSL_FRAME_HDR;
  return (int) l;
}

size_t
SslFrame::next( const uint8_t *&msg ) noexcept
{
  if ( this->off + 2 > this->len )
    return 0;
  size_t l = be16( &this->buf[ this->off ] );
  if ( l < 2 || this->off + l > this->len )
    return 0;
  msg = &this->buf[ this->off ]; /* includes the u16 length */
  this->off += l;
  return l;
}

/* ---- full header message -------------------------------------------------- */
bool
SslMsg::parse( const uint8_t *b,  size_t l ) noexcept
{
  this->buf = b;
  this->len = l;
  if ( l < SSL_HDR_LEN )
    return false;
  if ( be16( b ) != l )
    return false;
  this->hdr_len   = b[ 2 ];
  this->fixed_len = b[ 3 ];
  this->prot_type = be16( &b[ 4 ] );
  this->prot_ver  = b[ 6 ];
  this->msg_type  = b[ 7 ];
  this->user_id   = be32( &b[ 8 ] );
  if ( this->hdr_len != SSL_HDR_LEN )
    return false;
  this->fixed_off = SSL_HDR_LEN;
  this->var_off   = SSL_HDR_LEN + this->fixed_len;
  return this->var_off <= l;
}

bool
SslMsg::get_fixed( uint8_t tag,  uint32_t &val ) const noexcept
{
  size_t i = this->fixed_off, end = this->var_off;
  while ( i < end ) {
    uint8_t t = this->buf[ i ], w = ssl_fixed_width( t );
    if ( w == 0 || i + 1 + w > end )
      return false;
    if ( t == tag ) {
      switch ( w ) {
        case 1: val = this->buf[ i + 1 ]; break;
        case 2: val = be16( &this->buf[ i + 1 ] ); break;
        default: val = be32( &this->buf[ i + 1 ] ); break;
      }
      return true;
    }
    i += 1 + w;
  }
  return false;
}

bool
SslMsg::get_var( uint8_t tag,  const uint8_t *&data,  size_t &dlen ) const noexcept
{
  size_t i = this->var_off, end = this->len;
  while ( i + 3 <= end ) {
    uint8_t t = this->buf[ i ];
    size_t  l = be16( &this->buf[ i + 1 ] );
    if ( i + 3 + l > end )
      return false;
    if ( t == tag ) {
      data = &this->buf[ i + 3 ];
      dlen = l;
      return true;
    }
    i += 3 + l;
  }
  return false;
}

void
SslMsg::print( void ) const noexcept
{
  printf( "%s (prot %u ver %u type %u user %u len %u)\n",
          ssl_msg_type_name( this->prot_type, this->prot_ver, this->msg_type ),
          this->prot_type, this->prot_ver, this->msg_type, this->user_id,
          (uint32_t) this->len );
  size_t i = this->fixed_off, end = this->var_off;
  while ( i < end ) {
    uint8_t t = this->buf[ i ], w = ssl_fixed_width( t );
    if ( w == 0 || i + 1 + w > end ) {
      printf( "  ? fixed tag 0x%02x\n", t );
      break;
    }
    uint32_t v;
    this->get_fixed( t, v );
    printf( "  %-20s = %u (0x%x)\n", ssl_fixed_name( t ), v, v );
    i += 1 + w;
  }
  i = this->var_off; end = this->len;
  while ( i + 3 <= end ) {
    uint8_t t = this->buf[ i ];
    size_t  l = be16( &this->buf[ i + 1 ] );
    if ( i + 3 + l > end )
      break;
    if ( t == VR_DATA )
      printf( "  %-20s = <%u bytes>\n", ssl_var_name( t ), (uint32_t) l );
    else
      printf( "  %-20s = \"%.*s\"\n", ssl_var_name( t ), (int) l,
              (const char *) &this->buf[ i + 3 ] );
    i += 3 + l;
  }
}

/* ---- message writer --------------------------------------------------------- */
SslMsgWriter &
SslMsgWriter::start( uint16_t prot_type,  uint8_t prot_ver,  uint8_t msg_type,
                     uint32_t user_id ) noexcept
{
  if ( this->buflen < SSL_HDR_LEN ) { this->ok = false; return *this; }
  uint8_t * p = this->buf;
  put16( p, 0 );            /* msg_len, finish() */
  p[ 2 ] = SSL_HDR_LEN;
  p[ 3 ] = 0;               /* fixed_len, finish() */
  put16( &p[ 4 ], prot_type );
  p[ 6 ] = prot_ver;
  p[ 7 ] = msg_type;
  put32( &p[ 8 ], user_id );
  this->off         = SSL_HDR_LEN;
  this->fixed_start = SSL_HDR_LEN;
  this->in_fixed    = true;
  this->ok          = true;
  return *this;
}

SslMsgWriter &
SslMsgWriter::fixed( uint8_t tag,  uint32_t val ) noexcept
{
  uint8_t w = ssl_fixed_width( tag );
  if ( ! this->in_fixed || w == 0 || this->off + 1 + w > this->buflen ) {
    this->ok = false;
    return *this;
  }
  uint8_t * p = &this->buf[ this->off ];
  p[ 0 ] = tag;
  switch ( w ) {
    case 1: p[ 1 ] = (uint8_t) val; break;
    case 2: put16( &p[ 1 ], (uint16_t) val ); break;
    default: put32( &p[ 1 ], val ); break;
  }
  this->off += 1 + w;
  return *this;
}

SslMsgWriter &
SslMsgWriter::var( uint8_t tag,  const void *data,  size_t dlen ) noexcept
{
  if ( this->in_fixed ) {
    size_t fl = this->off - this->fixed_start;
    if ( fl > 255 ) { this->ok = false; return *this; }
    this->buf[ 3 ] = (uint8_t) fl;
    this->in_fixed = false;
  }
  if ( dlen > 0xffff || this->off + 3 + dlen > this->buflen ) {
    this->ok = false;
    return *this;
  }
  uint8_t * p = &this->buf[ this->off ];
  p[ 0 ] = tag;
  put16( &p[ 1 ], (uint16_t) dlen );
  ::memcpy( &p[ 3 ], data, dlen );
  this->off += 3 + dlen;
  return *this;
}

size_t
SslMsgWriter::finish( void ) noexcept
{
  if ( ! this->ok )
    return 0;
  if ( this->in_fixed ) {
    size_t fl = this->off - this->fixed_start;
    if ( fl > 255 )
      return 0;
    this->buf[ 3 ] = (uint8_t) fl;
    this->in_fixed = false;
  }
  if ( this->off > 0xffff )
    return 0;
  put16( this->buf, (uint16_t) this->off );
  return this->off;
}

/* ---- frame writer ----------------------------------------------------------- */
SslFrameWriter::SslFrameWriter( uint8_t *b,  size_t l,  uint8_t flags ) noexcept
  : buf( b ), buflen( l ), off( SSL_FRAME_HDR ), ok( l >= SSL_FRAME_HDR )
{
  if ( this->ok ) {
    put16( b, 0 );
    ::memcpy( &b[ 2 ], SSL_FRAME_MAGIC, 3 );
    b[ 5 ] = flags;
  }
}

uint8_t *
SslFrameWriter::reserve( size_t maxlen ) noexcept
{
  if ( ! this->ok || this->off + maxlen > this->buflen ) {
    this->ok = false;
    return NULL;
  }
  return &this->buf[ this->off ];
}

void
SslFrameWriter::commit( size_t msglen ) noexcept
{
  this->off += msglen; /* the message carries its own u16 length */
}

bool
SslFrameWriter::add( const uint8_t *msg,  size_t msglen ) noexcept
{
  uint8_t * p = this->reserve( msglen );
  if ( p == NULL )
    return false;
  ::memcpy( p, msg, msglen );
  this->commit( msglen );
  return true;
}

size_t
SslFrameWriter::finish( void ) noexcept
{
  if ( ! this->ok || this->off > 0xffff )
    return 0;
  put16( this->buf, (uint16_t) this->off );
  return this->off;
}
