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

-define(DISCV5, 1).
-endif.
