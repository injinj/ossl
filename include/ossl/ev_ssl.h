#ifndef __rai_ossl__ev_ssl_h__
#define __rai_ossl__ev_ssl_h__

#include <raikv/ev_net.h>
#include <raikv/ev_tcp.h>
#include <raikv/route_ht.h>
#include <raikv/dlinklist.h>
#include <raimd/md_msg.h>
#include <omm/ev_omm.h>
#include <omm/src_dir.h>
#include <ossl/ipc.h>

/* ossl_server: an SSL sink distributor.  SSL 4.x consumers (SSL SDK, RFA 7
 * SSLED, SFC, ADS-POP) mount here as they would on an ADS port 8101; items
 * are subscribed through the raikv route table, where an OMM client
 * (omm/EvOmmClient, connected to an ADS / omm_server) publishes RWF
 * messages by subject "SVC.REC.RIC".  Each RWF refresh / update is
 * converted to a Marketfeed record with raimd's MktfdMsgWriter and sent as
 * an SSL image / update in the dialect the sink negotiated at mount:
 * 4.5 (PT_SSLLIB), 4.0 (PT_SINK_DIST) or 4.0 BE (compact messages). */

namespace rai {
namespace ossl {

typedef struct md::MDMsgDict OmmDict;

struct EvSslListen : public kv::EvTcpListen {
  kv::RoutePublish & sub_route;
  OmmDict          & dict;
  omm::OmmSourceDB & source_db;
  EvSslListen( kv::EvPoll &p,  OmmDict &d,  omm::OmmSourceDB &db ) noexcept;
  virtual kv::EvSocket *accept( void ) noexcept;
};

/* one open item on a sink connection, keyed by subject "SVC.REC.RIC" */
struct SslItem {
  uint32_t hash,
           item_id,     /* the client's item tag (FX_ITEM_ID) */
           seqno,       /* FX_SEQUENCE_NUMBER: image 1, updates 2.. */
           service_id;
  uint16_t svc_len,     /* value = "SVC.REC.RIC": svc [0,svc_len) */
           ric_off;     /* ric at value[ ric_off ] */
  uint8_t  state,       /* SslItemState */
           snapshot,    /* RT_SNAPSHOT: close after the image */
           pending;     /* waiting for the solicited image */
  uint16_t len;
  char     value[ 2 ];
  const char *svc( void ) const { return this->value; }
  const char *ric( void ) const { return &this->value[ this->ric_off ]; }
  size_t ric_len( void ) const { return this->len - this->ric_off; }
};
struct SslItemTab : public kv::RouteVec<SslItem> {};

/* which message goes out how */
enum SslOp {
  OP_MOUNT_ACK, OP_MOUNT_NAK, OP_SERVICE, OP_SERVICE_END, OP_IMAGE,
  OP_UNSOLICITED, OP_UPDATE, OP_STATUS, OP_GROUP_STATUS, OP_CHANGE_GROUP,
  OP_PING, OP_CONFIRM, OP_COUNT
};

struct EvSslService : public kv::EvConnection, public omm::OmmSrcListener {
  EvSslListen      & listener;
  kv::RoutePublish & sub_route;
  OmmDict          & dict;
  omm::OmmSourceDB & source_db;
  SslItemTab         items;
  uint32_t           user_id,
                     ping_interval,   /* seconds, from the mount */
                     open_count;
  uint16_t           prot_type;       /* PT_SINK_DIST / PT_SSLLIB */
  uint8_t            prot_ver;        /* PV_SSL_4 / PV_SSL_45 / PV_SSL_40BE */
  bool               connected,       /* connect record exchanged */
                     mounted,
                     dir_sent,        /* service table pushed / requested */
                     listening;       /* on the source db listener list */
  char               user[ 64 ],
                     app_id[ 16 ],
                     position[ 64 ];
  uint8_t            svc_state[ 64 ]; /* last SslServiceState sent per source idx */

  void * operator new( size_t, void *ptr ) { return ptr; }
  EvSslService( kv::EvPoll &p,  uint8_t st,  EvSslListen &l )
    : kv::EvConnection( p, st ), listener( l ), sub_route( l.sub_route ),
      dict( l.dict ), source_db( l.source_db ), user_id( 0 ),
      ping_interval( 20 ), open_count( 0 ), prot_type( PT_SSLLIB ),
      prot_ver( PV_SSL_45 ), connected( false ), mounted( false ),
      dir_sent( false ), listening( false ) {
    this->user[ 0 ] = this->app_id[ 0 ] = this->position[ 0 ] = '\0';
    ::memset( this->svc_state, 0xff, sizeof( this->svc_state ) );
  }
  void init( void ) noexcept;
  /* EvConnection */
  virtual void process( void ) noexcept;
  virtual void release( void ) noexcept;
  virtual void process_shutdown( void ) noexcept;
  virtual void process_close( void ) noexcept;
  virtual bool timer_expire( uint64_t timer_id, uint64_t event_id ) noexcept;
  virtual bool on_msg( kv::EvPublish &pub ) noexcept;
  /* OmmSrcListener: a service came, went or changed state */
  virtual void on_src_change( void ) noexcept;

  /* inbound */
  bool dispatch_frame( SslFrame &fr ) noexcept;
  bool dispatch_msg( const uint8_t *msg,  size_t len ) noexcept;
  bool dispatch_full( SslMsg &m ) noexcept;
  bool dispatch_be( const uint8_t *msg,  size_t len ) noexcept;
  bool on_mount( SslMsg &m ) noexcept;
  bool on_open( const char *svc,  size_t svc_len,  const char *ric,
                size_t ric_len,  uint32_t item_id,  uint8_t req_type ) noexcept;
  bool on_close( const char *svc,  size_t svc_len,  const char *ric,
                 size_t ric_len ) noexcept;
  bool on_src_tbl_req( void ) noexcept;
  SslItem * find_item( const char *svc,  size_t svc_len,  const char *ric,
                       size_t ric_len,  kv::RouteLoc &loc,
                       uint32_t &hash ) noexcept;
  void close_item( SslItem &it,  kv::RouteLoc &loc ) noexcept;
  void close_all( void ) noexcept;
  omm::OmmSource * find_service( const char *svc,  size_t svc_len,
                                 uint32_t &idx ) noexcept;
  uint16_t svc_be_id( uint32_t idx ) const { return (uint16_t) ( idx + 1 ); }

  /* outbound; each builds one message and frames it */
  uint8_t msg_type( SslOp op ) const noexcept;
  void send_connect_ack( void ) noexcept;
  void send_mount_ack( void ) noexcept;
  void send_mount_nak( const char *text ) noexcept;
  void send_service_table( void ) noexcept;
  void send_service( omm::OmmSource &src,  uint32_t idx,  bool up ) noexcept;
  void send_group_status( omm::OmmSource &src,  uint32_t idx,  bool up ) noexcept;
  void send_data( SslItem &it,  SslOp op,  uint8_t state,  uint8_t code,
                  const char *text,  size_t text_len,
                  const void *mf,  size_t mf_len ) noexcept;
  void send_status( SslItem &it,  uint8_t state,  uint8_t code,
                    const char *text,  size_t text_len ) noexcept;
  void send_ping( void ) noexcept;
  void send_confirm( void ) noexcept;
  /* append a finished message to the output as one frame */
  void send_frame( const uint8_t *msg,  size_t len ) noexcept;
  bool is_be( void ) const { return this->prot_ver == PV_SSL_40BE; }
  bool is_45( void ) const { return this->prot_type == PT_SSLLIB; }
};

}
}
#endif
