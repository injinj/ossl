/* ossl_server: SSL sink distributor fed by an OMM (RSSL) upstream.
 *
 *   ossl_server -o 8101 -p ads1.www:14002 -c /path/to/dict
 *
 * SSL consumers mount on -o as on an ADS port 8101; items are requested
 * from the OMM upstream (-p, an ADS RSSL port or an omm_server), converted
 * RWF -> Marketfeed and distributed as SSL images / updates.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <raikv/mainloop.h>
#include <raimd/md_dict.h>
#include <omm/ev_omm.h>
#include <omm/ev_omm_client.h>
#include <omm/src_dir.h>
#include <ossl/ev_ssl.h>

using namespace rai;
using namespace kv;
using namespace md;
using namespace omm;
using namespace ossl;

extern "C" const char *ossl_get_version( void );

struct Args : public MainLoopVars {
  OmmDict               dict;
  OmmSourceDB           source_db;
  const char          * path;
  EvOmmClientParameters ads;
  int                   ssl_port;
  Args() : path( 0 ), ads( NULL, "ossl_server", "256", NULL, NULL, NULL ),
           ssl_port( 0 ) {}
};

struct PrintSrcs : public OmmSrcListener {
  EvPoll      & poll;
  OmmSourceDB & source_db;
  PrintSrcs( EvPoll &p,  OmmSourceDB &db ) : poll( p ), source_db( db ) {}
  virtual void on_src_change( void ) noexcept {
    if ( ! this->poll.quit )
      this->source_db.print_sources();
  }
};

/* reconnect the upstream every 5 seconds until it answers */
struct OmmReconnect : public EvTimerCallback, public EvConnectionNotify {
  EvOmmClient           & client;
  EvOmmClientParameters & param;
  int                     reconnect_count;
  void * operator new( size_t, void *ptr ) { return ptr; }
  OmmReconnect( EvOmmClient &cl,  EvOmmClientParameters &p )
    : client( cl ), param( p ), reconnect_count( 0 ) {}
  void do_connect( void ) {
    if ( ! this->client.omm_connect( this->param, this, NULL ) ) {
      if ( this->reconnect_count++ == 0 ) {
        fprintf( stderr, "upstream reconnect, 5 second interval\n" );
        this->param.opts &= ~OPT_VERBOSE;
      }
      this->client.poll.timer.add_timer_seconds( *this, 5, 0, 0 );
    }
  }
  virtual void on_connect( EvSocket &conn ) noexcept {
    printf( "upstream connected: %.*s\n", (int) conn.get_peer_address_strlen(),
            conn.peer_address.buf );
    this->reconnect_count = 0;
  }
  virtual void on_shutdown( EvSocket &conn,  const char *err,
                            size_t errlen ) noexcept {
    printf( "upstream shutdown: %.*s %.*s\n",
            (int) conn.get_peer_address_strlen(), conn.peer_address.buf,
            (int) errlen, err );
    if ( ! this->client.poll.quit )
      this->do_connect();
  }
  virtual bool timer_cb( uint64_t,  uint64_t ) noexcept {
    if ( ! this->client.poll.quit )
      this->do_connect();
    return false;
  }
};

struct Loop : public MainLoop<Args> {
  Loop( EvShm &m,  Args &args,  size_t num )
    : MainLoop( m, args, num ), ssl_sv( 0 ), omm_client( 0 ), omm_conn( 0 ),
      print_srcs( this->poll, args.source_db ) {}
  EvSslListen  * ssl_sv;
  EvOmmClient  * omm_client;
  OmmReconnect * omm_conn;
  PrintSrcs      print_srcs;

  virtual bool finish( void ) noexcept { return true; }
  virtual bool initialize( void ) noexcept {
    printf( "ossl_version:         %s\n", ossl_get_version() );
    this->r.source_db.add_source_listener( &this->print_srcs );
    if ( this->r.path != NULL && this->r.dict.load( this->r.path, true ) ) {
      if ( this->r.dict.rdm_dict != NULL )
        printf( "rdm dictionary:       %s (RDMFieldDictionary enumtype.def)\n",
                this->r.path );
    }
    if ( this->r.dict.rdm_dict == NULL ) {
      fprintf( stderr, "an RDM dictionary (-c path) is required to encode "
               "Marketfeed\n" );
      return false;
    }
    if ( this->r.ssl_port != 0 ) {
      this->ssl_sv = new ( aligned_malloc( sizeof( EvSslListen ) ) )
        EvSslListen( this->poll, this->r.dict, this->r.source_db );
      if ( this->ssl_sv->listen( NULL, this->r.ssl_port,
                                 this->r.tcp_opts ) != 0 ) {
        fprintf( stderr, "unable to listen on ssl port %d\n", this->r.ssl_port );
        return false;
      }
      printf( "ssl_sink port:        %d\n", this->r.ssl_port );
    }
    if ( this->r.ads.daemon != NULL ) {
      this->omm_client = new ( aligned_malloc( sizeof( EvOmmClient ) ) )
        EvOmmClient( this->poll, this->r.dict, this->r.source_db );
      this->omm_client->have_dictionary = true; /* loaded from -c */
      this->omm_conn = new ( ::malloc( sizeof( OmmReconnect ) ) )
        OmmReconnect( *this->omm_client, this->r.ads );
      printf( "omm upstream:         %s:%d\n", this->r.ads.daemon,
              this->r.ads.port );
      this->omm_conn->do_connect();
    }
    else {
      fprintf( stderr, "no upstream (-p host[:port]), nothing to serve\n" );
    }
    return true;
  }
};

int
main( int argc, const char *argv[] )
{
  EvShm shm( "ossl_server" );
  Args  r;
  r.no_threads   = true;
  r.no_reuseport = true;
  r.no_map       = true;
  r.no_default   = true;
  r.all          = true;
  r.add_desc( "  -o port   = listen ssl sink port         (8101)" );
  r.add_desc( "  -p host   = omm upstream host[:port]     (14002)" );
  r.add_desc( "  -c path   = dictionary path              ($cfile_path)" );
  r.add_desc( "  -u user   = upstream login user          (ossl_server)" );
  r.add_desc( "  -i app_id = upstream application id      (256)" );
  if ( ! r.parse_args( argc, argv ) )
    return 1;
  shm.print();
  r.ssl_port   = r.parse_port( argc, argv, "-o", "8101" );
  r.path       = r.get_arg( argc, argv, 1, "-c", ".", "cfile_path" );
  r.ads.user   = r.get_arg( argc, argv, 1, "-u", "ossl_server" );
  r.ads.app_id = r.get_arg( argc, argv, 1, "-i", "256" );
  const char * up = r.get_arg( argc, argv, 1, "-p", NULL );
  static char host[ 256 ];
  if ( up != NULL ) {
    ::snprintf( host, sizeof( host ), "%s", up );
    char * c = ::strchr( host, ':' );
    if ( c != NULL ) { *c = '\0'; r.ads.port = atoi( c + 1 ); }
    r.ads.daemon = host;
  }
  Runner<Args, Loop> runner( r, shm );
  if ( r.thr_error == 0 )
    return 0;
  return 1;
}
