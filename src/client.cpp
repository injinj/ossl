/* ossl_client: an SSL 4.5 sink client.  Mounts to an ADS (or an ossl
 * server) on the SSL port, prints the service directory, opens items and
 * prints the Marketfeed images / updates decoded with raimd.
 *
 *   ossl_client -d ads1.www[:8101] [-u user] [-c dict_path] [-s] SVC.ITEM ...
 *
 * The item syntax is omm_client's: ADH1.INTC.O -> service ADH1, item INTC.O
 * (ADH1.REC.INTC.O is accepted too, the REC is dropped).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ossl/ipc.h>
#include <raimd/md_msg.h>
#include <raimd/md_dict.h>
#include <raimd/dict_load.h>
#include <raimd/mf_msg.h>

using namespace rai;
using namespace ossl;
using namespace md;

static volatile sig_atomic_t stop_flag = 0;
static void on_sig( int ) { stop_flag = 1; }

struct Item {
  char     svc[ 64 ], name[ 256 ];
  uint32_t id;
  bool     open;
};

struct SslClient {
  int          fd;
  uint32_t     user_id,
               conf_seq,   /* our request sequence (conf_seq_num) */
               next_item;
  uint8_t      rbuf[ 64 * 1024 ];
  size_t       rlen;
  MDDict     * dict;
  MDOutput     mout;
  Item       * items;
  size_t       nitems,
               svc_count;
  bool         snapshot,
               verbose;

  SslClient() : fd( -1 ), user_id( 0 ), conf_seq( 0 ), next_item( 0 ),
                rlen( 0 ), dict( 0 ), items( 0 ), nitems( 0 ), svc_count( 0 ),
                snapshot( false ), verbose( false ) {}

  bool connect_to( const char *host,  int port ) noexcept;
  bool send_all( const uint8_t *b,  size_t l ) noexcept;
  bool send_msg( const uint8_t *msg,  size_t l ) noexcept;
  bool mount( const char *user,  const char *host ) noexcept;
  bool open_item( Item &it ) noexcept;
  bool close_item( Item &it ) noexcept;
  bool ping_ack( void ) noexcept;
  bool read_frames( int timeout_ms ) noexcept;
  void on_msg( const SslMsg &m ) noexcept;
  void print_data( const SslMsg &m,  const char *what ) noexcept;
};

bool
SslClient::connect_to( const char *host,  int port ) noexcept
{
  struct addrinfo hints, *res = NULL;
  char portstr[ 16 ];
  ::memset( &hints, 0, sizeof( hints ) );
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  ::snprintf( portstr, sizeof( portstr ), "%d", port );
  if ( ::getaddrinfo( host, portstr, &hints, &res ) != 0 ) {
    fprintf( stderr, "cannot resolve %s\n", host );
    return false;
  }
  for ( struct addrinfo *a = res; a != NULL; a = a->ai_next ) {
    this->fd = ::socket( a->ai_family, a->ai_socktype, a->ai_protocol );
    if ( this->fd < 0 )
      continue;
    if ( ::connect( this->fd, a->ai_addr, a->ai_addrlen ) == 0 )
      break;
    ::close( this->fd );
    this->fd = -1;
  }
  ::freeaddrinfo( res );
  if ( this->fd < 0 ) {
    fprintf( stderr, "connect %s:%d failed: %s\n", host, port,
             strerror( errno ) );
    return false;
  }
  int one = 1;
  ::setsockopt( this->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof( one ) );
  return true;
}

bool
SslClient::send_all( const uint8_t *b,  size_t l ) noexcept
{
  while ( l > 0 ) {
    ssize_t n = ::send( this->fd, b, l, 0 );
    if ( n <= 0 ) {
      if ( n < 0 && errno == EINTR )
        continue;
      return false;
    }
    b += n; l -= n;
  }
  return true;
}

/* one message per frame, as the ADS does for 4.5 */
bool
SslClient::send_msg( const uint8_t *msg,  size_t l ) noexcept
{
  uint8_t frame[ SSL_MAX_FRAME + 64 ];
  SslFrameWriter fw( frame, sizeof( frame ), SSL_FRAME_FROM_CLIENT );
  if ( ! fw.add( msg, l ) )
    return false;
  size_t fl = fw.finish();
  if ( this->verbose ) {
    SslMsg m;
    if ( m.parse( msg, l ) ) { printf( "-> " ); m.print(); }
  }
  return fl != 0 && this->send_all( frame, fl );
}

bool
SslClient::mount( const char *user,  const char *host ) noexcept
{
  /* connect record, then the ack */
  if ( ! this->send_all( SSL_CONNECT_REQ, SSL_CONNECT_REQ_LEN ) )
    return false;
  uint8_t ack[ SSL_CONNECT_ACK_LEN ];
  size_t  got = 0;
  while ( got < sizeof( ack ) ) {
    ssize_t n = ::recv( this->fd, &ack[ got ], sizeof( ack ) - got, 0 );
    if ( n <= 0 ) return false;
    got += n;
  }
  if ( ack[ 0 ] != 0 || ack[ 1 ] != SSL_CONNECT_ACK_LEN ) {
    fprintf( stderr, "bad connect ack\n" );
    return false;
  }
  /* position "ip/net" from the local address */
  char position[ 80 ] = "127.0.0.1/net";
  struct sockaddr_storage ss; socklen_t sl = sizeof( ss );
  if ( ::getsockname( this->fd, (struct sockaddr *) &ss, &sl ) == 0 ) {
    char ip[ 64 ];
    void * a = ( ss.ss_family == AF_INET ?
                 (void *) &((struct sockaddr_in *) &ss)->sin_addr :
                 (void *) &((struct sockaddr_in6 *) &ss)->sin6_addr );
    if ( ::inet_ntop( ss.ss_family, a, ip, sizeof( ip ) ) != NULL )
      ::snprintf( position, sizeof( position ), "%s/net", ip );
  }
  /* MOUNT_REQ, 4.5: the elements the SSL 4.5 library sends */
  uint8_t msg[ 512 ];
  SslMsgWriter w( msg, sizeof( msg ) );
  w.start( PT_SSLLIB, PV_SSL_45, S45_MOUNT_REQ, 0 )
   .fixed( FX_REQ_NUM_ITEMS, 0xffff )
   .fixed( FX_MOUNT_FLAGS, 0x27b7 )
   .fixed( FX_MUX_TAG, 0 )
   .fixed( FX_PING_INTERVAL, 20 )
   .fixed( FX_SESSION_QUALITY, SQ_NORMAL )
   .fixed( FX_SESSION_KEY, 0 )
   .fixed( FX_MAX_UNCONFIRMED, 10 )
   .var( VR_USER_NAME, user )
   .var( VR_APP_KEY, "256" )
   .var( VR_POSITION, position )
   .var( VR_HOSTNAME, host );
  size_t l = w.finish();
  return l != 0 && this->send_msg( msg, l );
}

bool
SslClient::open_item( Item &it ) noexcept
{
  uint8_t msg[ 512 ];
  SslMsgWriter w( msg, sizeof( msg ) );
  it.id = ++this->next_item;
  w.start( PT_SSLLIB, PV_SSL_45, S45_IMAGE_REQ, 0 )
   .fixed( FX_OPEN_REQ_TYPE, this->snapshot ? RT_SNAPSHOT : RT_NORMAL )
   .fixed( FX_ITEM_ID, it.id )
   .fixed( FX_PRIORITY_CLASS, 1 )
   .fixed( FX_PRIORITY_COUNT, 1 )
   .fixed( FX_CONF_SEQ_NUM, ++this->conf_seq )
   .var( VR_SOURCE_NAME, it.svc )
   .var( VR_ITEM_NAME, it.name )
   .var( VR_ATTRIBUTES, "", 0 );
  size_t l = w.finish();
  it.open = true;
  return l != 0 && this->send_msg( msg, l );
}

bool
SslClient::close_item( Item &it ) noexcept
{
  uint8_t msg[ 512 ];
  SslMsgWriter w( msg, sizeof( msg ) );
  w.start( PT_SSLLIB, PV_SSL_45, S45_CLOSE_REQ, 0 )
   .fixed( FX_CONF_SEQ_NUM, ++this->conf_seq )
   .var( VR_SOURCE_NAME, it.svc )
   .var( VR_ITEM_NAME, it.name );
  size_t l = w.finish();
  it.open = false;
  return l != 0 && this->send_msg( msg, l );
}

bool
SslClient::ping_ack( void ) noexcept
{
  uint8_t msg[ 32 ];
  SslMsgWriter w( msg, sizeof( msg ) );
  w.start( PT_SSLLIB, PV_SSL_45, S45_PING_ACK, 0 );
  size_t l = w.finish();
  return l != 0 && this->send_msg( msg, l );
}

void
SslClient::print_data( const SslMsg &m,  const char *what ) noexcept
{
  const char *svc = "", *item = "", *text = ""; size_t sl = 0, il = 0, tl = 0;
  const uint8_t * data = NULL; size_t dlen = 0;
  uint32_t seq = 0, state = 0, grp = 0;
  m.get_var( VR_SOURCE_NAME, svc, sl );
  m.get_var( VR_ITEM_NAME, item, il );
  m.get_var( VR_TEXT, text, tl );
  m.get_fixed( FX_SEQUENCE_NUMBER, seq );
  m.get_fixed( FX_STATUS_STATE, state );
  m.get_fixed( FX_GROUP, grp );
  printf( "## %s %.*s.%.*s seq %u group %u state %u%s%.*s\n", what,
          (int) sl, svc, (int) il, item, seq, grp, state,
          tl ? " text=" : "", (int) tl, text );
  if ( m.get_var( VR_DATA, data, dlen ) && dlen > 0 ) {
    MDMsgMem mem;
    MDMsg * mf = MDMsg::unpack( (void *) data, 0, dlen, MARKETFEED_TYPE_ID,
                                this->dict, mem );
    if ( mf != NULL )
      mf->print( &this->mout );
    else
      printf( "  (marketfeed %u bytes, not decoded)\n", (uint32_t) dlen );
  }
}

void
SslClient::on_msg( const SslMsg &m ) noexcept
{
  if ( this->verbose ) { printf( "<- " ); m.print(); }
  if ( m.prot_type != PT_SSLLIB ) {
    printf( "unexpected protocol %u type %u\n", m.prot_type, m.msg_type );
    return;
  }
  switch ( m.msg_type ) {
    case S45_MOUNT_ACK: {
      /* 4.5 ack: hostname + instance + app name; 4.0 ack: distributor */
      const char *hn = "", *inst = "", *app = ""; size_t hl = 0, il = 0, al = 0;
      uint32_t ping = 0, lim = 0;
      if ( ! m.get_var( VR_HOSTNAME, hn, hl ) )
        m.get_var( VR_DISTRIBUTOR_NAME, hn, hl );
      m.get_var( VR_INSTANCE_ID, inst, il );
      m.get_var( VR_APP_NAME, app, al );
      m.get_fixed( FX_PING_INTERVAL, ping );
      m.get_fixed( FX_OPEN_LIMIT, lim );
      this->user_id = m.user_id;
      printf( "mounted: user_id %u server %.*s.%.*s.%.*s ping %us open_limit %u\n",
              m.user_id, (int) hl, hn, (int) il, inst, (int) al, app, ping, lim );
      break;
    }
    case S45_MOUNT_NAK: {
      const char *text = ""; size_t tl = 0;
      m.get_var( VR_TEXT, text, tl );
      printf( "mount rejected: %.*s\n", (int) tl, text );
      stop_flag = 1;
      break;
    }
    case S45_SERVICE_STATUS: {
      const char *svc = ""; size_t sl = 0; uint32_t st = 0, fmt = 0, lim = 0;
      m.get_var( VR_SOURCE_NAME, svc, sl );
      m.get_fixed( FX_STATUS_STATE, st );
      m.get_fixed( FX_DATA_TYPE_FORMAT, fmt );
      m.get_fixed( FX_OPEN_LIMIT, lim );
      printf( "service %-16.*s %s format %u open_limit %u\n", (int) sl, svc,
              st == SS_UP ? "UP  " : "DOWN", fmt, lim );
      this->svc_count++;
      /* open the items whose service just came up */
      for ( size_t i = 0; i < this->nitems; i++ ) {
        Item & it = this->items[ i ];
        if ( ! it.open && st == SS_UP && ::strlen( it.svc ) == sl &&
             ::memcmp( it.svc, svc, sl ) == 0 )
          this->open_item( it );
      }
      break;
    }
    case S45_ITEM_IMAGE:        this->print_data( m, "image" ); break;
    case S45_UNSOLICITED_IMAGE: this->print_data( m, "unsolicited image" ); break;
    case S45_ITEM_UPDATE:       this->print_data( m, "update" ); break;
    case S45_ITEM_STATUS:       this->print_data( m, "status" ); break;
    case S45_GROUP_STATUS: {
      const char *svc = "", *text = ""; size_t sl = 0, tl = 0;
      uint32_t grp = 0, st = 0, code = 0;
      m.get_var( VR_SOURCE_NAME, svc, sl );
      m.get_var( VR_TEXT, text, tl );
      m.get_fixed( FX_GROUP, grp );
      m.get_fixed( FX_STATUS_STATE, st );
      m.get_fixed( FX_STATUS_CODE, code );
      printf( "## group status %.*s group %u state %u code %u: %.*s\n",
              (int) sl, svc, grp, st, code, (int) tl, text );
      break;
    }
    case S45_GROUP_MERGE:
    case S45_CHANGE_GROUP: {
      const char *svc = ""; size_t sl = 0; uint32_t g1 = 0, g2 = 0;
      m.get_var( VR_SOURCE_NAME, svc, sl );
      m.get_fixed( FX_GROUP, g1 );
      m.get_fixed( FX_GROUP2, g2 );
      printf( "## group merge %.*s group %u -> %u\n", (int) sl, svc, g1, g2 );
      break;
    }
    case S45_PING:
      this->ping_ack();
      break;
    case S45_CONFIRM_DELIVERY:
      break;
    default:
      if ( ! this->verbose ) { printf( "<- " ); m.print(); }
      break;
  }
}

bool
SslClient::read_frames( int timeout_ms ) noexcept
{
  struct pollfd pfd = { this->fd, POLLIN, 0 };
  int n = ::poll( &pfd, 1, timeout_ms );
  if ( n < 0 )
    return errno == EINTR;
  if ( n == 0 )
    return true;
  ssize_t r = ::recv( this->fd, &this->rbuf[ this->rlen ],
                      sizeof( this->rbuf ) - this->rlen, 0 );
  if ( r <= 0 ) {
    if ( r < 0 && errno == EINTR )
      return true;
    printf( "connection closed\n" );
    return false;
  }
  this->rlen += r;
  size_t off = 0;
  for (;;) {
    SslFrame fr;
    int fl = fr.parse( &this->rbuf[ off ], this->rlen - off );
    if ( fl < 0 ) {
      fprintf( stderr, "bad frame at %u\n", (uint32_t) off );
      return false;
    }
    if ( fl == 0 )
      break;
    const uint8_t * msg;
    size_t          ml;
    while ( (ml = fr.next( msg )) != 0 ) {
      SslMsg m;
      if ( m.parse( msg, ml ) )
        this->on_msg( m );
      else
        fprintf( stderr, "bad message, len %u\n", (uint32_t) ml );
    }
    off += fl;
  }
  if ( off > 0 ) {
    ::memmove( this->rbuf, &this->rbuf[ off ], this->rlen - off );
    this->rlen -= off;
  }
  return true;
}

int
main( int argc,  char **argv )
{
  const char * host = "127.0.0.1", * user = getenv( "USER" ),
             * dict_path = getenv( "cfile_path" );
  int          port = 8101;
  SslClient    cl;
  char         hostbuf[ 256 ];

  if ( user == NULL ) user = "ossl";
  int i = 1;
  for ( ; i < argc && argv[ i ][ 0 ] == '-'; i++ ) {
    if ( ::strcmp( argv[ i ], "-d" ) == 0 && i + 1 < argc ) {
      ::snprintf( hostbuf, sizeof( hostbuf ), "%s", argv[ ++i ] );
      char * c = ::strchr( hostbuf, ':' );
      if ( c != NULL ) { *c = '\0'; port = atoi( c + 1 ); }
      host = hostbuf;
    }
    else if ( ::strcmp( argv[ i ], "-u" ) == 0 && i + 1 < argc ) user = argv[ ++i ];
    else if ( ::strcmp( argv[ i ], "-c" ) == 0 && i + 1 < argc ) dict_path = argv[ ++i ];
    else if ( ::strcmp( argv[ i ], "-s" ) == 0 ) cl.snapshot = true;
    else if ( ::strcmp( argv[ i ], "-v" ) == 0 ) cl.verbose = true;
    else {
      fprintf( stderr, "usage: %s [-d host[:port]] [-u user] [-c dict_path] "
               "[-s] [-v] SVC.ITEM ...\n"
               "  -d  ADS / ossl server (127.0.0.1:8101)\n"
               "  -u  mount user name ($USER)\n"
               "  -c  dictionary path, RDMFieldDictionary + enumtype.def ($cfile_path)\n"
               "  -s  snapshot requests\n"
               "  -v  print every message header\n", argv[ 0 ] );
      return 1;
    }
  }
  cl.nitems = argc - i;
  cl.items  = (Item *) ::calloc( cl.nitems + 1, sizeof( Item ) );
  for ( size_t k = 0; i < argc; i++, k++ ) {
    /* SVC.ITEM or SVC.REC.ITEM */
    const char * s = argv[ i ], * dot = ::strchr( s, '.' );
    if ( dot == NULL ) {
      fprintf( stderr, "item %s needs SVC.ITEM\n", s );
      return 1;
    }
    ::snprintf( cl.items[ k ].svc, sizeof( cl.items[ k ].svc ), "%.*s",
                (int) ( dot - s ), s );
    const char * item = dot + 1;
    if ( ::strncmp( item, "REC.", 4 ) == 0 )
      item += 4;
    ::snprintf( cl.items[ k ].name, sizeof( cl.items[ k ].name ), "%s", item );
  }
  if ( dict_path != NULL )
    cl.dict = load_dict_files( dict_path, false );

  ::signal( SIGINT, on_sig );
  ::signal( SIGTERM, on_sig );

  char me[ 128 ] = "ossl";
  ::gethostname( me, sizeof( me ) );
  if ( ! cl.connect_to( host, port ) )
    return 2;
  printf( "connected to %s:%d, mounting as %s\n", host, port, user );
  if ( ! cl.mount( user, me ) )
    return 3;
  while ( ! stop_flag ) {
    if ( ! cl.read_frames( 250 ) )
      break;
  }
  for ( size_t k = 0; k < cl.nitems; k++ )
    if ( cl.items[ k ].open )
      cl.close_item( cl.items[ k ] );
  ::close( cl.fd );
  return 0;
}
