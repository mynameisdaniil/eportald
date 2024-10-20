-module(discv5_node).

-include_lib("kernel/include/logger.hrl").
-include_lib("../enr/src/enr.hrl").
-include_lib("discv5.hrl").

-define(WHOAREYOU_TIMEOUT, 1000).
-define(COOLDOWN_TIMEOUT, rand:uniform(1000) + 1000). % 1 to 2 seconds

-behaviour(gen_statem).

-record(data, {
          node_id                  :: node_id(),
          enr                      :: enr:enr_v4(),
          loaded_from_disk = false :: boolean(),
          nonce                    :: nonce(),
          session_key              :: binary()
         }).

-type data() :: #data{}.

%% API
-export([
         start_link/1
        ]).

%% gen_statem callbacks
-export([
         callback_mode/0,
         init/1,
         terminate/3
        ]).

%% states
-export([
         initial_state/3,
         begin_handshake/3,
         await_whoareyou/3,
         cooldown_before_retry/3,
         session_established/3
        ]).

%%%===================================================================
%%% API
%%%===================================================================

start_link(ENR) ->
  {ok, #enr_v4{kv = KV}} = enr:decode(ENR),
  PubKey = maps:get(<<"secp256k1">>, KV),
  NodeId = enr:compressed_pub_key_to_node_id(PubKey),
  Result = gen_statem:start_link({via, gproc, {n, l, NodeId}}, ?MODULE, {NodeId, ENR}, []),
  Result.

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================
-spec callback_mode() -> gen_statem:callback_mode().
callback_mode() ->
  [state_functions, state_enter].

init({NodeId, EnrStr}) ->
  ?LOG_INFO("Starting discv5 node with NodeId: 0x~s", [binary:encode_hex(NodeId, lowercase)]),
  case enr:decode(EnrStr) of
    {ok, Enr} ->
      {ok, initial_state, #data{node_id = NodeId, enr = Enr, loaded_from_disk = false}};
    {error, Reason} ->
      {stop, Reason}
  end.

terminate(_Reason, _State, _Data) ->
  ok.

initial_state(enter, OldState, _Data) ->
  ?LOG_INFO(">>>initial_state enter from: ~p", [OldState]),
  self() ! begin_handshake,
  keep_state_and_data;

initial_state(info, begin_handshake, Data) ->
  {next_state, begin_handshake, Data}.

begin_handshake(enter, OldState, _Data) ->
  ?LOG_INFO(">>>begin_handshake enter from: ~p", [OldState]),
  self() ! do_handshake,
  keep_state_and_data;

begin_handshake(info, do_handshake, #data{node_id = NodeId, enr = #enr_v4{kv = EnrKV}} = Data) ->
  ?LOG_INFO("1. Starting handshake with NodeId: 0x~p", [binary:encode_hex(NodeId, lowercase)]),
  Nonce = discv5_codec:nonce(),
  {ok, SrcId} = discv5_enr_maintainer:get_node_id(),
  StaticHeader = #static_header{version       = 1,
                                flag          = ?ORDINARY_MSG_FLAG,
                                nonce         = Nonce,
                                authdata_size = byte_size(SrcId)},
  MaskingIV = discv5_codec:masking_iv(),
  MessageAd = discv5_codec:create_message_ad(MaskingIV, StaticHeader, SrcId), % TODO Here we just passing srcid binary as authdata but!
  {ok, RequestId} = discv5_request_id:new_request(self()), % TODO we MUST remove this pid() later after receiving reply to this message or on timeout
  Msg = #findnode{request_id = RequestId, distances = [0]},
  SessionKey = case discv5_session_keys:get_session_keys_for(NodeId) of
                 {error, not_found} -> crypto:strong_rand_bytes(16);
                 {ok, SK} -> SK
               end,
  {ok, Encoded} = discv5_codec:encode_protocol_message(SessionKey, Msg, StaticHeader, MessageAd),
  Message = #ordinary_message{data = Encoded,
                              static_header = StaticHeader,
                              authdata = #authdata{src_id = SrcId}, % TODO here we are passing a structure
                              message_ad = MessageAd},
  Packet = discv5_codec:encode_packet(Message),
  #{<<"ip">> := IpBin, <<"udp">> := UdpBin} = EnrKV,
  % Port = binary_to_integer(binary:encode_hex(UdpBin), 16),
  <<Port:16/unsigned-big-integer>> = UdpBin,
  <<A:8/unsigned-integer, B:8/unsigned-integer, C:8/unsigned-integer, D:8/unsigned-integer>> = IpBin, % TODO maybe move it to ENR?
  Ip = {A, B, C, D},
  ?LOG_INFO(">>>Port ~p", [Port]),
  discv5_udp_listener:send_message(Ip, Port, Packet),
  gproc:reg({n, l, {nonce, Nonce}}, self()),
  {next_state, await_whoareyou, Data#data{nonce = Nonce},
   [{state_timeout, ?WHOAREYOU_TIMEOUT, initial_state}]}.

await_whoareyou(enter, OldState, _Data) ->
  ?LOG_INFO(">>> await_whoareyou enter from: ~p", [OldState]),
  keep_state_and_data;

await_whoareyou(state_timeout, initial_state, #data{nonce = Nonce, node_id = NodeId} = Data) ->
  ?LOG_ERROR("Timeout waiting for WHOAREYOU from NodeId: 0x~p",
             [binary:encode_hex(NodeId, lowercase)]),
  gproc:unreg({n, l, {nonce, Nonce}}),
  % ok = discv5_request_id:delete_request(RequestId), % TODO Somehow get RequestId into this place
  {next_state, cooldown_before_retry, Data#data{nonce = undefined},
   [{state_timeout, ?COOLDOWN_TIMEOUT, cooldown}]};

await_whoareyou(info,
                #whoareyou_message{} = Msg,
                #data{node_id = NodeId, enr = #enr_v4{kv = EnrKV}} = Data
               ) ->
  ?LOG_INFO("2. Received WHOAREYOU from NodeId: 0x~p", [binary:encode_hex(NodeId, lowercase)]),
  %TODO process challenge
  #whoareyou_message{
     authdata = #authdata{
                   enr_seq = RemoteEnrSeq
                  },
     message_ad = ChallengeData
    } = Msg,
  % ok = discv5_request_id:delete_request(RequestId), % TODO Somehow get RequestId into this place
  EphKey = crypto:strong_rand_bytes(32),
  EphPubKey = libsecp256k1:ec_pubkey_create(EphKey, compressed),
  #{<<"secp256k1">> := PubKey} = EnrKV,
  {ok, Secret} = libsecp256k1:ec_pubkey_tweak_mul(PubKey, EphKey),
  LocalNodeId = discv5_enr_maintainer:get_node_id(),
  KDFInfo = <<?KDF_INFO_TEXT/binary, LocalNodeId/binary, NodeId/binary>>,
  PRK = hkdf:extract(sha256, ChallengeData, Secret),
  KeyData = hkdf:expand(sha256, PRK, KDFInfo, 32),
  <<InitiatorKey:16/binary, _RecipientKey:16/binary>> = KeyData, % TODO do something with it

  IdSignatureInput = <<?ID_SIGNATURE_TEXT/binary,
                       ChallengeData/binary,
                       EphPubKey/binary,
                       NodeId/binary>>,
  Sha256 = crypto:hash(sha256, IdSignatureInput),
  LocalPrivKey = discv5_enr_maintainer:get_private_key(),
  {ok, IdSignature, _RecoveryId} = libsecp256k1:ecdsa_sign_compact(Sha256, LocalPrivKey, default, <<>>), % TODO this should be possible with crypto:sign/4
  64 = byte_size(IdSignature), % TODO remove
  33 = byte_size(EphKey), % TODO remove
  AuthdataHead = #authdata_head{
                    src_id       = LocalNodeId,
                    sig_size     = 64,
                    eph_key_size = 33
                    },
  Authdata = #authdata{
                authdata_head = AuthdataHead,
                id_signature  = IdSignature,
                eph_pubkey    = EphPubKey
               },
  Authdata1 = case discv5_enr_maintainer:get_enr_seq() of
                {ok, LocalEnrSeq} when LocalEnrSeq > RemoteEnrSeq ->
                  {ok, Record} = discv5_enr_maintainer:get_enr(),
                  Authdata#authdata{record = Record};
                _Else ->
                  Authdata
              end,

  RequestId = discv5_request_id:new_request(),
  Msg = #findnode{request_id = RequestId, distances = [0]},
  MaskingIV = discv5_codec:masking_iv(),
  Nonce = discv5_codec:nonce(),
  StaticHeader = #static_header{version       = 1,
                                flag          = ?HANDSHAKE_MSG_FLAG,
                                nonce         = Nonce,
                                authdata_size = byte_size(Authdata)},
  MessageAd = discv5_codec:create_message_ad(MaskingIV, StaticHeader, Authdata),
  {ok, Encoded} = discv5_codec:encode_protocol_message(InitiatorKey, Msg, StaticHeader, MessageAd),
  Message = #handshake_message{
               data = Encoded,
               static_header = StaticHeader,
               authdata = Authdata1,
               message_ad = MessageAd
              },
  Packet = discv5_codec:encode_packet(Message),
  #{<<"ip">> := Ip, <<"port">> := Port} = EnrKV,
  discv5_udp_listener:send_message(Ip, Port, Packet),
  % TODO send handshake message with signature
  {next_state, session_established, Data#data{nonce = undefined, session_key = InitiatorKey}}.

cooldown_before_retry(enter, OldState, _Data) ->
  ?LOG_INFO(">>>cooldown_before_retry enter from: ~p", [OldState]),
  keep_state_and_data;

cooldown_before_retry(state_timeout, cooldown, #data{node_id = NodeId} = Data) ->
  ?LOG_INFO("Retrying handshake with NodeId: 0x~p", [binary:encode_hex(NodeId, lowercase)]),
  {next_state, begin_handshake, Data}.

session_established(enter, _OldState, #data{node_id = NodeId}) ->
  ?LOG_INFO("Session established with NodeId: 0x~p", [binary:encode_hex(NodeId, lowercase)]),
  keep_state_and_data;

session_established(info, #ordinary_message{} = Msg, #data{node_id = NodeId} = Data) ->
  ?LOG_INFO("4. Processing reply from NodeId: 0x~p", [binary:encode_hex(NodeId, lowercase)]),
  keep_state_and_data.

