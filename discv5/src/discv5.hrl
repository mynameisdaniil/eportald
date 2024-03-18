-ifndef(DISCV5).

-define(APP, discv5).
-define(NODE_SUP, discv5_node_sup).

-define(ORDINARY_MSG_FLAG, 0).
-define(WHOAREYOU_MSG_FLAG, 1).
-define(HANDSHAKE_MSG_FLAG, 2).

-define(MAX_UNSIGNED_256_BIT, (1 bsl 256) - 1).
-define(MAX_UNSIGNED_128_BIT, (1 bsl 128) - 1).

-define(TAG_LEN, 16).

-define(PING_ID, 16#01).
-define(PONG_ID, 16#02).
-define(FINDNODE_ID, 16#03).
-define(NODES_ID, 16#04).
-define(TALKREQ_ID, 16#05).
-define(TALKRESP_ID, 16#06).
-define(REGTOPIC_ID, 16#07).
-define(TICKET_ID, 16#08).
-define(REGCONFIRMATION_ID, 16#09).
-define(TOPICQUERY_ID, 16#0A).

-type node_id()    :: 0..?MAX_UNSIGNED_256_BIT.
-type masking_iv() :: 0..?MAX_UNSIGNED_128_BIT.

-type protocol_id()   :: binary().
-type version()       :: binary().
-type flag()          :: non_neg_integer().
-type nonce()         :: binary().
-type authdata_size() :: non_neg_integer().

-type message_ad()    :: binary().

-type pubkey()        :: binary().

-type id_signature()  :: binary().

-type id_nonce()      :: binary().

-record(static_header, {
          protocol_id = <<"discv5">> :: protocol_id(),
          version                    :: version(),
          flag                       :: flag(),
          nonce                      :: nonce(),
          authdata_size              :: authdata_size()
         }).

-type static_header() :: #static_header{}.

-record(authdata_head, {
          src_id,
          sig_size,
          eph_key_size
         }).

-type authdata_head() :: #authdata_head{}.

-record(authdata, {
          % ordinary message
          src_id        :: node_id(),
          % whoareyou
          id_nonce      :: id_nonce(),
          enr_seq       :: enr:enr_seq(),
          % handshake
          authdata_head :: authdata_head(),
          id_signature  :: id_signature(),
          eph_pubkey    :: pubkey(),
          record        :: enr:enr_v4()
         }).

-type authdata() :: #authdata{}.

-record(ordinary_message, {
          data          :: binary(),
          static_header :: static_header(),
          authdata      :: authdata(),
          message_ad    :: message_ad()
         }).

-record(whoareyou_message, {
          static_header :: static_header(),
          authdata      :: authdata(),
          message_ad    :: message_ad()
         }).

-record(handshake_message, {
          data          :: binary(),
          static_header :: static_header(),
          authdata      :: authdata(),
          message_ad    :: message_ad()
         }).

-record(ping, {
          request_id :: binary(), % byte array <= 8 bytes
          enr_seq :: non_neg_integer()
         }).

-record(pong, {
          request_id,
          enr_seq,
          recipient_ip,
          recipient_port
         }).

-record(findnode, {
          request_id :: non_neg_integer(),
          distances :: list(distance()),
          enr_seq
         }).

-record(nodes, {
          request_id :: non_neg_integer(),
          total,
          enrs :: list(enr:enr())
         }).

-record(talkreq, {
          request_id :: non_neg_integer(),
          protocol :: rlp:rlp(),
          request :: rlp:rlp()
         }).

-record(talkresp, {
          request_id :: non_neg_integer(),
          response :: rlp:rlp()
         }).

-record(regtopic, {
          request_id :: non_neg_integer(),
          topic :: binary(),
          enr :: enr:enr(),
          ticket :: rlp:rlp()
         }).

-record(ticket, {
          request_id :: non_neg_integer(),
          ticket :: rlp:rlp(),
          wait_time :: integer()
         }).

-record(regconfirmation, {
          request_id :: non_neg_integer(),
          topic :: binary()
         }).

-record(topicquery, {
          request_id :: non_neg_integer(),
          topic :: binary()
         }).

-type distance() :: 0..255. % TODO: is the 255 really max value possible?

-define(DISCV5, 1).
-endif.
