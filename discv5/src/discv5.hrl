-ifndef(DISCV5).

-define(ORDINARY_MSG_FLAG, 0).
-define(WHOAREYOU_MSG_FLAG, 1).
-define(HANDSHAKE_MSG_FLAG, 2).

-define(MAX_UNSIGNED_256_BIT, (1 bsl 256) - 1).
-define(MAX_UNSIGNED_128_BIT, (1 bsl 128) - 1).

-define(TAG_LEN, 16).

-type node_id() :: 0..?MAX_UNSIGNED_256_BIT.
-type masking_iv() :: 0..?MAX_UNSIGNED_128_BIT.

-record(static_header, {
          version,
          flag,
          nonce,
          authdata_size
         }).

-record(ordinary_message, {
          src_id :: node_id(),
          data :: binary()
         }).

-record(whoareyou_message, {
          id_nonce,
          enr_seq
         }).

-record(handshake_message, {
          authdata_head,
          id_signature,
          eph_pubkey,
          record
         }).

-record(authdata_head, {
          src_id,
          sig_size,
          eph_key_size
         }).

-record(ping, {
          request_id,
          enr_seq
         }).

-record(pong, {
          request_id,
          enr_seq,
          recipient_ip,
          recipient_port
         }).

-record(findnode, {
          request_id,
          distances :: list(distance()),
          enr_seq
         }).

-record(nodes, {
          request_id,
          total,
          enrs :: list(enr:enr())
         }).

-record(talkreq, {
          request_id,
          protocol :: rlp:rlp(),
          request :: rlp:rlp()
         }).

-record(talkresp, {
          request_id,
          response :: rlp:rlp()
         }).

-record(regtopic, {
          request_id,
          topic :: binary(),
          enr :: enr:enr(),
          ticket :: rlp:rlp()
         }).

-record(ticket, {
          request_id,
          ticket :: rlp:rlp(),
          wait_time :: integer()
         }).

-record(regconfirmation, {
          request_id,
          topic :: binary()
         }).

-record(topicquery, {
          request_id,
          topic :: binary()
         }).

-type distance() :: 0..255. % TODO: is the 255 really max value possible?

-define(DISCV5, 1).
-endif.
