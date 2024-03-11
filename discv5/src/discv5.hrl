-ifndef(DISCV5).

-define(APP, discv5).

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

-define(BOOTSTRAP_NODE, begin
                          {ok, List} = application:get_env(?APP, bootstrap_nodes, [])
                          lists:nth(rand:uniform(length(List)), List)
                        end).


-type node_id() :: 0..?MAX_UNSIGNED_256_BIT.
-type masking_iv() :: 0..?MAX_UNSIGNED_128_BIT.

-record(static_header, {
          version,
          flag,
          nonce,
          authdata_size
         }).

-record(meta, {
          nonce :: binary(),
          message_ad :: binary()
         }).

-record(ordinary_message, {
          src_id :: node_id(),
          data :: binary(),
          meta :: #meta{}
         }).

-record(whoareyou_message, {
          id_nonce :: binary(), % uint128
          enr_seq :: non_neg_integer() % uint64
         }).

-record(handshake_message, {
          authdata_head,
          id_signature,
          eph_pubkey,
          record,
          data :: binary(),
          meta :: #meta{}
         }).

-record(authdata_head, {
          src_id,
          sig_size,
          eph_key_size
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
