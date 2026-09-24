#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <raikv/ev_publish.h>
#include <raikv/key_hash.h>
#include <raimd/rwf_msg.h>
#include <raimd/mf_msg.h>
#include <raimd/omm_flags.h>
#include <ossl/ev_ssl.h>

using namespace rai;
using namespace kv;
using namespace md;
using namespace omm;
using namespace ossl;

namespace {
static const uint64_t PING_TIMER_ID    = 1;
static const uint32_t SSL_OPEN_LIMIT   = 200000000; /* what an ADS advertises */
static const char     GONE_DOWN_TEXT[] =
  "Service has gone down. Will recall when service becomes available.";
static const char     REFRESH_TEXT[]   = "Item Refresh Completed";

/* message type per dialect: [op][0]=4.0 sink  [1]=4.5  [2]=BE compact */
static const uint8_t op_types[ OP_COUNT ][ 3 ] = {
/* OP_MOUNT_ACK    */ { SNK_MOUNT_ACK,    S45_MOUNT_ACK,         SNK_MOUNT_ACK },
/* OP_MOUNT_NAK    */ { SNK_MOUNT_NAK,    S45_MOUNT_NAK,         SNK_MOUNT_NAK },
/* OP_SERVICE      */ { SNK_SRC_TBL,      S45_SERVICE_STATUS,    BE_SERVICE_STATUS },
/* OP_SERVICE_END  */ { 0,                0,                     BE_SRC_TBL_END },
/* OP_IMAGE        */ { SNK_ITEM_IMAGE,   S45_ITEM_IMAGE,        BE_ITEM_IMAGE },
/* OP_UNSOLICITED  */ { SNK_ITEM_IMAGE,   S45_UNSOLICITED_IMAGE, BE_ITEM_IMAGE },
/* OP_UPDATE       */ { SNK_ITEM_UPDATE,  S45_ITEM_UPDATE,       BE_ITEM_UPDATE },
/* OP_STATUS       */ { SNK_ITEM_STATUS,  S45_ITEM_STATUS,       BE_ITEM_IMAGE },
/* OP_GROUP_STATUS */ { SNK_GROUP_STATUS, S45_GROUP_STATUS,      BE_GROUP_STATUS },
/* OP_CHANGE_GROUP */ { SNK_GROUP_MERGE,  S45_GROUP_MERGE,       BE_CHANGE_GROUP },
/* OP_PING         */ { SNK_PING_REQ,     S45_PING,              BE_PING },
/* OP_CONFIRM      */ { 0,                S45_CONFIRM_DELIVERY,  0 }
};

static inline size_t
put_str8( uint8_t *p,  const char *s,  size_t len ) {
  p[ 0 ] = (uint8_t) len; ::memcpy( &p[ 1 ], s, len ); return 1 + len;
}
static inline size_t
put_str16( uint8_t *p,  const void *s,  size_t len ) {
  put16( p, (uint16_t) len ); ::memcpy( &p[ 2 ], s, len ); return 2 + len;
}
}

EvSslListen::EvSslListen( EvPoll &p,  OmmDict &d,  OmmSourceDB &db ) noexcept
           : EvTcpListen( p, "ssl_listen", "ssl_sock" ),
             sub_route( p.sub_route ), dict( d ), source_db( db )
{
  md_init_auto_unpack();
}

EvSocket *
EvSslListen::accept( void ) noexcept
{
  EvSslService *c =
    this->poll.get_free_list<EvSslService, EvSslListen &>(
      this->accept_sock_type, *this );
  if ( c == NULL )
    return NULL;
  if ( this->accept2( *c, "ssl" ) ) {
    printf( "ssl accept %.*s\n", (int) c->get_peer_address_strlen(),
            c->peer_address.buf );
    c->init();
    return c;
  }
  return NULL;
}

void
EvSslService::init( void ) noexcept
{
  this->user_id    = 0;
  this->open_count = 0;
  this->connected  = false;
  this->mounted    = false;
  this->dir_sent   = false;
  this->listening  = false;
  this->prot_type  = PT_SSLLIB;
  this->prot_ver   = PV_SSL_45;
  this->ping_interval = 20;
  ::memset( this->svc_state, 0xff, sizeof( this->svc_state ) );
}

/* ---- inbound ------------------------------------------------------------ */
void
EvSslService::process( void ) noexcept
{
  bool failed = false;
  while ( this->off < this->len ) {
    SslFrame fr;
    int fl = fr.parse( (const uint8_t *) &this->recv[ this->off ],
                       this->len - this->off );
    if ( fl < 0 ) {
      fprintf( stderr, "ssl: bad frame from %.*s\n",
               (int) this->get_peer_address_strlen(), this->peer_address.buf );
      failed = true;
      break;
    }
    if ( fl == 0 )
      break;
    this->off += fl;
    if ( ! this->dispatch_frame( fr ) ) {
      failed = true;
      break;
    }
  }
  this->pop( EV_PROCESS );
  if ( ! failed ) {
    if ( ! this->push_write() )
      this->clear_write_buffers();
    return;
  }
  this->push( EV_CLOSE );
}

bool
EvSslService::dispatch_frame( SslFrame &fr ) noexcept
{
  if ( ! this->connected ) {
    if ( ! fr.is_connect_req() )
      return false;
    this->connected = true;
    this->send_connect_ack();
    return true;
  }
  const uint8_t * msg;
  size_t          ml;
  while ( (ml = fr.next( msg )) != 0 ) {
    if ( ! this->dispatch_msg( msg, ml ) )
      return false;
  }
  return true;
}

bool
EvSslService::dispatch_msg( const uint8_t *msg,  size_t len ) noexcept
{
  /* a full header starts with the u16 length then hdr_len 12; a BE
   * compact message follows the u16 length with hdr_len (0/2) and type */
  if ( len >= SSL_HDR_LEN && msg[ 2 ] == SSL_HDR_LEN ) {
    SslMsg m;
    if ( ! m.parse( msg, len ) )
      return false;
    return this->dispatch_full( m );
  }
  if ( this->mounted && this->is_be() )
    return this->dispatch_be( msg, len );
  fprintf( stderr, "ssl: unknown message, len %u\n", (uint32_t) len );
  return false;
}

bool
EvSslService::dispatch_full( SslMsg &m ) noexcept
{
  if ( ! this->mounted ) {
    if ( m.msg_type == ( m.prot_type == PT_SSLLIB ? (uint8_t) S45_MOUNT_REQ
                                                  : (uint8_t) SNK_MOUNT_REQ ) )
      return this->on_mount( m );
    return false;
  }
  const char *svc = NULL, *ric = NULL; size_t sl = 0, rl = 0;
  uint32_t item_id = 0, req = RT_NORMAL;
  m.get_var( VR_SOURCE_NAME, svc, sl );
  m.get_var( VR_ITEM_NAME, ric, rl );
  if ( this->is_45() ) {
    switch ( m.msg_type ) {
      case S45_IMAGE_REQ:
        m.get_fixed( FX_ITEM_ID, item_id );
        m.get_fixed( FX_OPEN_REQ_TYPE, req );
        return this->on_open( svc, sl, ric, rl, item_id, (uint8_t) req );
      case S45_CLOSE_REQ:
        return this->on_close( svc, sl, ric, rl );
      case S45_PING_ACK:
      case S45_PING:
      case S45_CONFIRM_DELIVERY:
      case S45_SET_MAX_UNCONFIRMED:
        return true;
      case S45_DISMOUNT:
        return false;
      default:
        printf( "ssl: 4.5 type %u (%s) ignored\n", m.msg_type,
                ssl_msg_type_name( m.prot_type, m.prot_ver, m.msg_type ) );
        return true;
    }
  }
  switch ( m.msg_type ) { /* 4.0 sink protocol */
    case SNK_OPEN_REQ:
      m.get_fixed( FX_ITEM_ID, item_id );
      m.get_fixed( FX_OPEN_REQ_TYPE, req );
      return this->on_open( svc, sl, ric, rl, item_id, (uint8_t) req );
    case SNK_CLOSE_REQ:
      return this->on_close( svc, sl, ric, rl );
    case SNK_SRC_TBL_REQ:
      return this->on_src_tbl_req();
    case SNK_PING:
    case SNK_PING_REQ:
      return true;
    case SNK_MUX_CLI_DISMOUNT:
    case SNK_CLIENT_EXIT:
      return false;
    default:
      printf( "ssl: 4.0 type %u (%s) ignored\n", m.msg_type,
              ssl_msg_type_name( m.prot_type, m.prot_ver, m.msg_type ) );
      return true;
  }
}

/* BE compact: u16 len | u8 hdr_len | u8 type | ... positional */
bool
EvSslService::dispatch_be( const uint8_t *msg,  size_t len ) noexcept
{
  if ( len < 4 )
    return false;
  /* u16 len | u8 hdr (0: one bitmap byte, 2: two) | u8 type | bitmap | fields */
  uint8_t type = msg[ 3 ];
  size_t  bm   = 1 + ( msg[ 2 ] >> 1 );
  if ( len < 4 + bm )
    return false;
  const uint8_t * p = &msg[ 4 + bm ];
  size_t          n = len - 4 - bm;
  switch ( type ) {
    case BE_SRC_TBL_REQ:   /* 00 0f 05 00 00 00 01 */
      return this->on_src_tbl_req();
    case BE_PING_ACK:      /* 00 12 05 00 00 00 00 */
    case BE_PING:
      return true;
    case BE_IMAGE_REQ: {   /* 02 13 06 03 | u16 svc | u32 item | u8 type | u8len name | ... */
      if ( n < 2 + 4 + 1 + 1 )
        return false;
      uint16_t svc_id = be16( p );
      uint32_t item_id = be32( &p[ 2 ] );
      uint8_t  req = p[ 6 ], nl = p[ 7 ];
      if ( n < 8 + nl )
        return false;
      const char * ric = (const char *) &p[ 8 ];
      if ( svc_id == 0 || svc_id > this->source_db.source_list.count )
        return this->on_open( "", 0, ric, nl, item_id, req );
      OmmSource * src = this->source_db.source_list.ptr[ svc_id - 1 ].hd;
      return this->on_open( src->info.service_name, src->info.service_name_len,
                            ric, nl, item_id, req );
    }
    case BE_CLOSE_REQ: {   /* 00 14 05 | u16 svc | u8len name */
      if ( n < 2 + 1 )
        return false;
      uint16_t svc_id = be16( p );
      uint8_t  nl = p[ 2 ];
      if ( n < 3 + nl || svc_id == 0 ||
           svc_id > this->source_db.source_list.count )
        return false;
      OmmSource * src = this->source_db.source_list.ptr[ svc_id - 1 ].hd;
      return this->on_close( src->info.service_name, src->info.service_name_len,
                             (const char *) &p[ 3 ], nl );
    }
    default:
      printf( "ssl: BE type 0x%02x ignored\n", type );
      return true;
  }
}

bool
EvSslService::on_mount( SslMsg &m ) noexcept
{
  const char *s; size_t sl; uint32_t v;
  this->prot_type = m.prot_type;
  this->prot_ver  = m.prot_ver;
  if ( m.get_var( VR_USER_NAME, s, sl ) )
    ::snprintf( this->user, sizeof( this->user ), "%.*s", (int) sl, s );
  if ( m.get_var( VR_APP_KEY, s, sl ) )
    ::snprintf( this->app_id, sizeof( this->app_id ), "%.*s", (int) sl, s );
  if ( m.get_var( VR_POSITION, s, sl ) )
    ::snprintf( this->position, sizeof( this->position ), "%.*s", (int) sl, s );
  if ( m.get_fixed( FX_PING_INTERVAL, v ) && v >= 1 && v <= 3600 )
    this->ping_interval = v;
  if ( this->prot_ver != PV_SSL_4 && this->prot_ver != PV_SSL_45 &&
       this->prot_ver != PV_SSL_40BE ) {
    this->send_mount_nak( "unsupported protocol version" );
    return false;
  }
  this->mounted = true;
  this->user_id = (uint32_t) this->fd + 1; /* per connection, like an ADS */
  printf( "ssl mount %.*s user %s app %s pos %s prot %u ver %u\n",
          (int) this->get_peer_address_strlen(), this->peer_address.buf,
          this->user, this->app_id, this->position, this->prot_type,
          this->prot_ver );
  this->send_mount_ack();
  if ( this->is_45() )  /* 4.5 pushes the service table, 4.0 / BE ask */
    this->send_service_table();
  if ( ! this->listening ) {
    this->source_db.add_source_listener( this );
    this->listening = true;
  }
  this->poll.timer.add_timer_seconds( this->fd, this->ping_interval,
                                      PING_TIMER_ID, 0 );
  return true;
}

bool
EvSslService::on_src_tbl_req( void ) noexcept
{
  this->send_service_table();
  return true;
}

OmmSource *
EvSslService::find_service( const char *svc,  size_t svc_len,
                            uint32_t &idx ) noexcept
{
  for ( uint32_t i = 0; i < this->source_db.source_list.count; i++ ) {
    OmmSource * src = this->source_db.source_list.ptr[ i ].hd;
    if ( src != NULL && src->info.service_name_len == svc_len &&
         ::memcmp( src->info.service_name, svc, svc_len ) == 0 ) {
      idx = i;
      return src;
    }
  }
  return NULL;
}

SslItem *
EvSslService::find_item( const char *svc,  size_t svc_len,  const char *ric,
                         size_t ric_len,  RouteLoc &loc,
                         uint32_t &hash ) noexcept
{
  char   sub[ 512 ];
  size_t n = svc_len + 5 + ric_len;
  if ( n > sizeof( sub ) )
    return NULL;
  CatPtr cat( sub );
  cat.b( svc, svc_len ).s( ".REC." ).b( ric, ric_len );
  hash = kv_crc_c( sub, n, 0 );
  return this->items.find( hash, sub, n, loc );
}

bool
EvSslService::on_open( const char *svc,  size_t svc_len,  const char *ric,
                       size_t ric_len,  uint32_t item_id,
                       uint8_t req_type ) noexcept
{
  uint32_t    idx = 0, hash;
  RouteLoc    loc;
  OmmSource * src = this->find_service( svc, svc_len, idx );
  SslItem     tmp;
  ::memset( &tmp, 0, sizeof( tmp ) );

  if ( svc_len == 0 || ric_len == 0 || svc_len + 5 + ric_len > 500 ) {
    printf( "ssl open: bad names\n" );
    return true;
  }
  if ( src == NULL ) {
    /* ADS answers an unknown service with an image-less status */
    char   sub[ 512 ];
    CatPtr cat( sub );
    size_t n = cat.b( svc, svc_len ).s( ".REC." ).b( ric, ric_len ).end();
    SslItem * it = (SslItem *) ::alloca( sizeof( SslItem ) + n );
    ::memset( it, 0, sizeof( SslItem ) );
    ::memcpy( it->value, sub, n );
    it->len     = (uint16_t) n;
    it->svc_len = (uint16_t) svc_len;
    it->ric_off = (uint16_t) ( svc_len + 5 );
    it->item_id = item_id;
    it->state   = IS_CLOSED;
    this->send_status( *it, IS_CLOSED, SC_SRC_UNKNOWN, "Service unknown", 15 );
    return true;
  }
  SslItem * it = this->find_item( svc, svc_len, ric, ric_len, loc, hash );
  bool is_new = ( it == NULL );
  if ( is_new ) {
    char   sub[ 512 ];
    CatPtr cat( sub );
    size_t n = cat.b( svc, svc_len ).s( ".REC." ).b( ric, ric_len ).end();
    it = this->items.insert( hash, sub, n, loc );
    if ( it == NULL )
      return false;
    it->hash       = hash;
    it->service_id = src->service_id;
    it->svc_len    = (uint16_t) svc_len;
    it->ric_off    = (uint16_t) ( svc_len + 5 );
    it->seqno      = 0;
    it->state      = IS_OK;
    this->open_count++;
  }
  it->item_id  = item_id;
  it->snapshot = ( req_type == RT_SNAPSHOT );
  it->pending  = 1;
  /* one route table subscription per subject per connection; a re-open
   * re-notifies so the source sends the image again */
  NotifySub nsub( it->value, it->len, NULL, 0, hash, false, 'S', *this );
  nsub.notify_type = NOTIFY_IS_INITIAL;
  if ( is_new )
    this->sub_route.add_sub( nsub );
  else {
    nsub.sub_count = 1;
    this->sub_route.notify_sub( nsub );
  }
  return true;
}

void
EvSslService::close_item( SslItem &it,  RouteLoc &loc ) noexcept
{
  NotifySub nsub( it.value, it.len, NULL, 0, it.hash, false, 'S', *this );
  this->sub_route.del_sub( nsub );
  this->items.remove( loc );
  if ( this->open_count > 0 )
    this->open_count--;
}

bool
EvSslService::on_close( const char *svc,  size_t svc_len,  const char *ric,
                        size_t ric_len ) noexcept
{
  RouteLoc loc; uint32_t hash;
  SslItem * it = this->find_item( svc, svc_len, ric, ric_len, loc, hash );
  if ( it != NULL ) /* duplicate closes (RFA sends several) are fine */
    this->close_item( *it, loc );
  return true;
}

void
EvSslService::close_all( void ) noexcept
{
  RouteLoc  loc;
  SslItem * it;
  while ( (it = this->items.first( loc )) != NULL )
    this->close_item( *it, loc );
}

/* ---- outbound ------------------------------------------------------------- */
uint8_t
EvSslService::msg_type( SslOp op ) const noexcept
{
  return op_types[ op ][ this->is_be() ? 2 : ( this->is_45() ? 1 : 0 ) ];
}

void
EvSslService::send_frame( const uint8_t *msg,  size_t len ) noexcept
{
  size_t    fl = SSL_FRAME_HDR + len;
  uint8_t * p  = (uint8_t *) this->alloc( fl );
  if ( p == NULL )
    return;
  SslFrameWriter fw( p, fl, SSL_FRAME_FROM_SERVER );
  fw.add( msg, len );
  fw.finish();
  this->sz += fl;
}

void
EvSslService::send_connect_ack( void ) noexcept
{
  this->append( SSL_CONNECT_ACK, SSL_CONNECT_ACK_LEN );
}

void
EvSslService::send_mount_ack( void ) noexcept
{
  uint8_t      msg[ 512 ];
  SslMsgWriter w( msg, sizeof( msg ) );
  char         host[ 128 ] = "ossl";
  ::gethostname( host, sizeof( host ) );
  host[ sizeof( host ) - 1 ] = '\0';
  char * dot = ::strchr( host, '.' );
  if ( dot != NULL ) *dot = '\0';

  w.start( this->prot_type, this->prot_ver, this->msg_type( OP_MOUNT_ACK ),
           this->user_id );
  if ( this->is_45() ) {
    w.fixed( FX_OPEN_LIMIT, SSL_OPEN_LIMIT )
     .fixed( FX_PING_INTERVAL, this->ping_interval )
     .fixed( FX_SESSION_QUALITY, SQ_NORMAL )
     .fixed( FX_SESSION_KEY, 0 )
     .fixed( FX_CONF_SEQ_NUM, 0 )
     .fixed( FX_MAX_UNCONFIRMED, 0x3fffffff )
     .fixed( FX_MAX_ITEM_NAME, 25 )
     .fixed( FX_MOUNT_FLAGS, 0x25b7 )
     .var( VR_HOSTNAME, host )
     .var( VR_INSTANCE_ID, "ossl" )
     .var( VR_APP_NAME, "ossl" );
    this->send_frame( msg, w.finish() );
  }
  else if ( this->prot_ver == PV_SSL_4 ) {
    char dist[ 160 ];
    ::snprintf( dist, sizeof( dist ), "%s.ossl.ossl", host );
    w.fixed( FX_MUX_TAG, 0 )
     .fixed( FX_MAX_ITEM_NAME, 0xfe )
     .var( VR_DISTRIBUTOR_NAME, dist );
    this->send_frame( msg, w.finish() );
  }
  else { /* BE: bare ack, then the compact text message */
    this->send_frame( msg, w.finish() );
    char    dist[ 160 ];
    size_t  dl = ::snprintf( dist, sizeof( dist ), "%s.ossl.ossl", host );
    uint8_t be[ 200 ];
    size_t  n = 2;
    be[ n++ ] = 0x00; be[ n++ ] = BE_MOUNT_ACK_TEXT; be[ n++ ] = 0x05;
    be[ n++ ] = 0xfe;
    n += put_str16( &be[ n ], dist, dl );
    put16( be, (uint16_t) n );
    this->send_frame( be, n );
  }
}

void
EvSslService::send_mount_nak( const char *text ) noexcept
{
  uint8_t      msg[ 256 ];
  SslMsgWriter w( msg, sizeof( msg ) );
  w.start( this->prot_type, this->prot_ver, this->msg_type( OP_MOUNT_NAK ), 0 )
   .var( VR_TEXT, text );
  this->send_frame( msg, w.finish() );
}

void
EvSslService::send_service( OmmSource &src,  uint32_t idx,  bool up ) noexcept
{
  uint8_t      msg[ 256 ];
  SslMsgWriter w( msg, sizeof( msg ) );
  if ( this->is_45() ) {
    w.start( this->prot_type, this->prot_ver, this->msg_type( OP_SERVICE ),
             this->user_id )
     .fixed( FX_STATUS_STATE, up ? SS_UP : SS_DOWN )
     .fixed( FX_CONF_SEQ_NUM, 0 )
     .fixed( FX_OPEN_LIMIT, SSL_OPEN_LIMIT )
     .fixed( FX_DATA_TYPE_FORMAT, DF_MARKETFEED_RECORD )
     .var( VR_SOURCE_NAME, src.info.service_name, src.info.service_name_len );
    this->send_frame( msg, w.finish() );
  }
  else if ( this->is_be() ) {
    /* 00 0b 05 | u16 id | 00 01 (state) | 00 00 00 01 | u8len name | 00 02 */
    size_t n = 2;
    msg[ n++ ] = 0x00; msg[ n++ ] = BE_SERVICE_STATUS; msg[ n++ ] = 0x05;
    put16( &msg[ n ], this->svc_be_id( idx ) ); n += 2;
    put16( &msg[ n ], up ? SS_UP : SS_DOWN ); n += 2;
    put32( &msg[ n ], 1 ); n += 4;
    n += put_str8( &msg[ n ], src.info.service_name, src.info.service_name_len );
    put16( &msg[ n ], DF_MARKETFEED_RECORD ); n += 2;
    put16( msg, (uint16_t) n );
    this->send_frame( msg, n );
  }
  /* 4.0 sends the whole table in one SRC_TBL, see send_service_table */
  if ( idx < sizeof( this->svc_state ) )
    this->svc_state[ idx ] = up ? SS_UP : SS_DOWN;
}

void
EvSslService::send_service_table( void ) noexcept
{
  uint32_t cnt = this->source_db.source_list.count;
  if ( this->prot_ver == PV_SSL_4 ) {
    /* SRC_TBL: var 07 = u8 count { u8len name, u8 format, u8 state }* */
    uint8_t      msg[ 2048 ], tbl[ 1500 ];
    size_t       n = 1;
    uint8_t      k = 0;
    for ( uint32_t i = 0; i < cnt && k < 255; i++ ) {
      OmmSource * src = this->source_db.source_list.ptr[ i ].hd;
      if ( src == NULL ) continue;
      if ( n + 3 + src->info.service_name_len > sizeof( tbl ) ) break;
      n += put_str8( &tbl[ n ], src->info.service_name,
                     src->info.service_name_len );
      tbl[ n++ ] = DF_MARKETFEED_RECORD;
      tbl[ n++ ] = ( src->state.service_state != 0 ) ? SS_UP : SS_DOWN;
      if ( i < sizeof( this->svc_state ) )
        this->svc_state[ i ] = tbl[ n - 1 ];
      k++;
    }
    tbl[ 0 ] = k;
    SslMsgWriter w( msg, sizeof( msg ) );
    w.start( this->prot_type, this->prot_ver, SNK_SRC_TBL, this->user_id )
     .var( VR_DATA, tbl, n );
    this->send_frame( msg, w.finish() );
  }
  else {
    for ( uint32_t i = 0; i < cnt; i++ ) {
      OmmSource * src = this->source_db.source_list.ptr[ i ].hd;
      if ( src != NULL )
        this->send_service( *src, i, src->state.service_state != 0 );
    }
    if ( this->is_be() ) { /* 00 0e 05 00 00 00 01 */
      static const uint8_t end[] = { 0x00, 0x09, 0x00, BE_SRC_TBL_END, 0x05,
                                     0x00, 0x00, 0x00, 0x01 };
      this->send_frame( end, sizeof( end ) );
    }
  }
  this->dir_sent = true;
}

void
EvSslService::send_group_status( OmmSource &src,  uint32_t idx,
                                 bool up ) noexcept
{
  if ( up ) /* recovery is the re-image, no message (as the ADS) */
    return;
  uint32_t group = src.service_id;
  uint8_t  msg[ 512 ];
  if ( this->is_be() ) {
    /* 00 08 05 | u16 svc | 01 | 00 | u32 group | u16len text */
    size_t n = 2;
    msg[ n++ ] = 0x00; msg[ n++ ] = BE_GROUP_STATUS; msg[ n++ ] = 0x05;
    put16( &msg[ n ], this->svc_be_id( idx ) ); n += 2;
    msg[ n++ ] = IS_STALE; msg[ n++ ] = SC_NONE;
    put32( &msg[ n ], group ); n += 4;
    n += put_str16( &msg[ n ], GONE_DOWN_TEXT, sizeof( GONE_DOWN_TEXT ) - 1 );
    put16( msg, (uint16_t) n );
    this->send_frame( msg, n );
    /* 00 09 05 | u16 svc | u32 group | u32 0 */
    n = 2;
    msg[ n++ ] = 0x00; msg[ n++ ] = BE_CHANGE_GROUP; msg[ n++ ] = 0x05;
    put16( &msg[ n ], this->svc_be_id( idx ) ); n += 2;
    put32( &msg[ n ], group ); n += 4;
    put32( &msg[ n ], 0 ); n += 4;
    put16( msg, (uint16_t) n );
    this->send_frame( msg, n );
    return;
  }
  SslMsgWriter w( msg, sizeof( msg ) );
  w.start( this->prot_type, this->prot_ver, this->msg_type( OP_GROUP_STATUS ),
           this->user_id )
   .fixed( FX_STATUS_STATE, IS_STALE )
   .fixed( FX_STATUS_CODE, SC_NONE )
   .fixed( FX_GROUP, group );
  if ( this->is_45() ) w.fixed( FX_CONF_SEQ_NUM, 0 );
  w.var( VR_SOURCE_NAME, src.info.service_name, src.info.service_name_len )
   .var( VR_TEXT, GONE_DOWN_TEXT );
  this->send_frame( msg, w.finish() );

  SslMsgWriter w2( msg, sizeof( msg ) );
  w2.start( this->prot_type, this->prot_ver, this->msg_type( OP_CHANGE_GROUP ),
            this->user_id )
    .fixed( FX_GROUP, group )
    .fixed( FX_GROUP2, 0 );
  if ( this->is_45() ) w2.fixed( FX_CONF_SEQ_NUM, 0 );
  w2.var( VR_SOURCE_NAME, src.info.service_name, src.info.service_name_len );
  this->send_frame( msg, w2.finish() );
}

/* image / unsolicited image / update / status for an item */
void
EvSslService::send_data( SslItem &it,  SslOp op,  uint8_t state,
                         uint8_t code,  const char *text,  size_t text_len,
                         const void *mf,  size_t mf_len ) noexcept
{
  size_t    need = 64 + it.len + text_len + mf_len;
  uint8_t * msg  = (uint8_t *) ::alloca( need );
  uint32_t  group = it.service_id;
  uint32_t  idx = 0;
  bool      is_upd = ( op == OP_UPDATE );

  if ( this->is_be() ) {
    size_t n = 2;
    if ( is_upd ) {
      /* 00 01 05 | u16 svc | u8len name | u16 mflen | mf */
      msg[ n++ ] = 0x00; msg[ n++ ] = BE_ITEM_UPDATE; msg[ n++ ] = 0x05;
    }
    else {
      /* 02 02 06 09 | u16 svc | u32 0 | u16 group | 00 02 | 00 00
       * | u8len name | u32 item_id | u16len text | u16 mflen | mf */
      msg[ n++ ] = 0x02; msg[ n++ ] = BE_ITEM_IMAGE; msg[ n++ ] = 0x06;
      msg[ n++ ] = 0x09;
    }
    this->find_service( it.svc(), it.svc_len, idx );
    put16( &msg[ n ], this->svc_be_id( idx ) ); n += 2;
    if ( ! is_upd ) {
      put32( &msg[ n ], 0 ); n += 4;
      put16( &msg[ n ], (uint16_t) group ); n += 2;
      put16( &msg[ n ], DF_MARKETFEED_RECORD ); n += 2;
      put16( &msg[ n ], 0 ); n += 2;
    }
    n += put_str8( &msg[ n ], it.ric(), it.ric_len() );
    if ( ! is_upd ) {
      put32( &msg[ n ], it.item_id ); n += 4;
      n += put_str16( &msg[ n ], text, text_len );
    }
    n += put_str16( &msg[ n ], mf, mf_len );
    put16( msg, (uint16_t) n );
    this->send_frame( msg, n );
    return;
  }
  SslMsgWriter w( msg, need );
  w.start( this->prot_type, this->prot_ver, this->msg_type( op ),
           this->user_id );
  if ( ! is_upd ) {
    w.fixed( FX_STATUS_STATE, state )
     .fixed( FX_STATUS_CODE, code );
  }
  if ( op != OP_STATUS ) {
    w.fixed( FX_DATA_TYPE_FORMAT, DF_MARKETFEED_RECORD )
     .fixed( FX_DATA_TYPE_DESC, 0 );
  }
  if ( ! is_upd && op != OP_STATUS )
    w.fixed( FX_GROUP, group );
  if ( this->is_45() )
    w.fixed( FX_SEQUENCE_NUMBER, it.seqno );
  if ( ! is_upd )
    w.fixed( FX_ITEM_ID, it.item_id );
  if ( this->is_45() && ! is_upd )
    w.fixed( FX_CONF_SEQ_NUM, 0 );
  w.var( VR_SOURCE_NAME, it.svc(), it.svc_len )
   .var( VR_ITEM_NAME, it.ric(), it.ric_len() );
  if ( ! is_upd ) {
    if ( op != OP_STATUS )
      w.var( VR_NEXT_NAME, "", 0 ).var( VR_PREV_NAME, "", 0 );
    w.var( VR_TEXT, text, text_len );
  }
  if ( op != OP_STATUS )
    w.var( VR_DATA, mf, mf_len );
  this->send_frame( msg, w.finish() );
  if ( this->is_45() && ! is_upd && op != OP_STATUS )
    this->send_confirm();
}

void
EvSslService::send_status( SslItem &it,  uint8_t state,  uint8_t code,
                           const char *text,  size_t text_len ) noexcept
{
  if ( this->is_be() ) {
    /* no compact status type known: the ADS answers with an image
     * carrying the text and a REC_STATUS field; do the same */
    char body[ 320 ];
    size_t n = ::snprintf( body, sizeof( body ),
                           "\x1c" "340" "\x1f" "XX" "\x1d" "%.*s" "\x1f" "0"
                           "\x1f" "1" "\x1e" "3857" "\x1f" "0" "\x1e" "1008"
                           "\x1f" "%.*s" "\x1c",
                           (int) it.ric_len(), it.ric(), (int) text_len, text );
    this->send_data( it, OP_IMAGE, state, code, text, text_len, body, n );
    return;
  }
  this->send_data( it, OP_STATUS, state, code, text, text_len, NULL, 0 );
}

void
EvSslService::send_ping( void ) noexcept
{
  if ( this->is_be() ) {
    static const uint8_t ping[] = { 0x00, 0x09, 0x00, BE_PING, 0x05,
                                    0x00, 0x00, 0x00, 0x00 };
    this->send_frame( ping, sizeof( ping ) );
    return;
  }
  uint8_t      msg[ 32 ];
  SslMsgWriter w( msg, sizeof( msg ) );
  w.start( this->prot_type, this->prot_ver, this->msg_type( OP_PING ),
           this->user_id );
  this->send_frame( msg, w.finish() );
}

void
EvSslService::send_confirm( void ) noexcept
{
  uint8_t      msg[ 32 ];
  SslMsgWriter w( msg, sizeof( msg ) );
  w.start( this->prot_type, this->prot_ver, this->msg_type( OP_CONFIRM ),
           this->user_id )
   .fixed( FX_CONF_SEQ_NUM, 0 );
  this->send_frame( msg, w.finish() );
}

/* ---- data from the route table (the OMM client publishes RWF) ------------- */
bool
EvSslService::on_msg( EvPublish &pub ) noexcept
{
  if ( pub.msg_enc != RWF_MSG_TYPE_ID )
    return true;
  RouteLoc  loc;
  SslItem * it = this->items.find( pub.subj_hash, pub.subject,
                                   pub.subject_len, loc );
  if ( it == NULL )
    return true;

  MDMsgMem mem;
  RwfMsg * m = RwfMsg::unpack_message( (void *) pub.msg, 0, pub.msg_len,
                                       RWF_MSG_TYPE_ID, this->dict.rdm_dict,
                                       mem );
  if ( m == NULL )
    return true;
  RwfMsgHdr & hdr = m->msg;

  if ( hdr.msg_class == STATUS_MSG_CLASS ) {
    uint8_t state = IS_OK;
    if ( hdr.test( X_HAS_STATE ) ) {
      if ( hdr.state.stream_state == STREAM_STATE_CLOSED_RECOVER )
        state = IS_CLOSED_RECOVER;
      else if ( hdr.state.stream_state != STREAM_STATE_OPEN )
        state = IS_CLOSED;
      else if ( hdr.state.data_state != DATA_STATE_OK )
        state = IS_STALE;
    }
    const char * text = hdr.test( X_HAS_STATE ) ? hdr.state.text.buf : "";
    size_t       tlen = hdr.test( X_HAS_STATE ) ? hdr.state.text.len : 0;
    it->state = state;
    this->send_status( *it, state, SC_NONE, text, tlen );
    if ( state == IS_CLOSED || state == IS_CLOSED_RECOVER )
      this->close_item( *it, loc );
    this->idle_push_write();
    return true;
  }
  if ( hdr.msg_class != REFRESH_MSG_CLASS && hdr.msg_class != UPDATE_MSG_CLASS )
    return true;
  if ( hdr.msg_class == UPDATE_MSG_CLASS && it->pending )
    return true; /* no image yet: an update would be out of sequence */

  RwfMsg * fl = m->get_container_msg();
  if ( fl == NULL )
    return true;

  MDMsgMem       wmem;
  uint8_t        buf[ 4096 ];
  MktfdMsgWriter w( wmem, this->dict.dict, buf, sizeof( buf ) );
  bool is_image = ( hdr.msg_class == REFRESH_MSG_CLASS );
  it->seqno++;
  if ( is_image ) {
    w.start( Rec_340, it->ric(), it->ric_len() );
    if ( fl->get_type_id() == RWF_FIELD_LIST_TYPE_ID &&
         ( fl->fields.flags & RwfFieldListHdr::HAS_FIELD_LIST_INFO ) != 0 )
      w.add_flist( (uint16_t) fl->fields.flist );
    else
      w.add_flist( 0 );
    w.add_rtl( it->seqno );
  }
  else {
    w.start( Upd_316, it->ric(), it->ric_len() ).add_rtl();
  }
  if ( w.convert_msg( *fl, false ) != 0 || w.err != 0 ) {
    printf( "ssl: mf convert error %d for %.*s\n", w.err, (int) it->len,
            it->value );
    return true;
  }
  size_t mf_len = w.update_hdr();

  if ( is_image ) {
    bool solicited = hdr.test( X_SOLICITED );
    const char * text = hdr.test( X_HAS_STATE ) ? hdr.state.text.buf : REFRESH_TEXT;
    size_t       tlen = hdr.test( X_HAS_STATE ) ? hdr.state.text.len
                                                : sizeof( REFRESH_TEXT ) - 1;
    uint8_t state = IS_OK;
    if ( hdr.test( X_HAS_STATE ) && hdr.state.data_state != DATA_STATE_OK )
      state = IS_STALE;
    SslOp op = ( it->pending || solicited ) ? OP_IMAGE : OP_UNSOLICITED;
    it->pending = 0;
    it->state   = state;
    this->send_data( *it, op, state, SC_NONE, text, tlen, w.buf, mf_len );
    if ( it->snapshot && hdr.test( X_REFRESH_COMPLETE ) )
      this->close_item( *it, loc );
  }
  else {
    this->send_data( *it, OP_UPDATE, IS_OK, SC_NONE, NULL, 0, w.buf, mf_len );
  }
  this->idle_push_write();
  return true;
}

/* ---- service state changes ------------------------------------------------- */
void
EvSslService::on_src_change( void ) noexcept
{
  if ( ! this->mounted || this->poll.quit )
    return;
  uint32_t cnt = this->source_db.source_list.count;
  for ( uint32_t i = 0; i < cnt && i < sizeof( this->svc_state ); i++ ) {
    OmmSource * src = this->source_db.source_list.ptr[ i ].hd;
    if ( src == NULL ) continue;
    uint8_t st = ( src->state.service_state != 0 ) ? SS_UP : SS_DOWN;
    if ( this->svc_state[ i ] == 0xff ) { /* new service */
      if ( this->dir_sent && this->prot_ver != PV_SSL_4 )
        this->send_service( *src, i, st == SS_UP );
      this->svc_state[ i ] = st;
    }
    else if ( this->svc_state[ i ] != st ) {
      if ( this->prot_ver != PV_SSL_4 )
        this->send_service( *src, i, st == SS_UP );
      this->send_group_status( *src, i, st == SS_UP );
      this->svc_state[ i ] = st;
    }
  }
  this->idle_push_write();
}

/* ---- lifecycle ---------------------------------------------------------------- */
bool
EvSslService::timer_expire( uint64_t timer_id,  uint64_t ) noexcept
{
  if ( timer_id == PING_TIMER_ID && this->mounted ) {
    this->send_ping();
    this->idle_push_write();
    return true;
  }
  return false;
}

void
EvSslService::release( void ) noexcept
{
  printf( "ssl release %.*s (%u items)\n",
          (int) this->get_peer_address_strlen(), this->peer_address.buf,
          this->open_count );
  if ( this->listening ) {
    this->source_db.listener_list.pop( this );
    this->listening = false;
  }
  this->close_all();
  this->items.release();
  this->EvConnection::release_buffers();
}

void
EvSslService::process_shutdown( void ) noexcept
{
  this->pushpop( EV_CLOSE, EV_SHUTDOWN );
}

void
EvSslService::process_close( void ) noexcept
{
  this->EvSocket::process_close();
}
