-module(discv5_parser).

-export([parse/2]).
-export_type([parse_result/0]).

-export([node_a/0, node_b/0, ping_msg/0]).

-include("discv5.hrl").

-type parse_result() ::
  {ok, term()}
  | {error, unexpected}.

-spec parse(binary(), binary()) -> parse_result().

-record(state, {static_header, authdata, bytes_to_decode, node_id, crypto, payload}).

parse(Input, NodeId)
  when is_binary(Input)
       andalso byte_size(Input) >= 63
       andalso byte_size(Input) =< 1280 ->

  do_parse(init_crypto, #state{bytes_to_decode = Input, node_id = NodeId});

parse(_, _) ->
  {error, unexpected1}.

do_parse(init_crypto, #state{bytes_to_decode = <<MaskingIV:16/binary, Rest/binary>>,
                             node_id = <<MaskingKey:16/binary, _/binary>>} = State) ->

  Crypto = crypto:crypto_init(aes_128_ctr, MaskingKey, MaskingIV, [{encrypt, false}]),
  do_parse(protocol_id, State#state{crypto = Crypto, bytes_to_decode = Rest});

do_parse(protocol_id, #state{bytes_to_decode = <<ProtocolId:6/binary, Rest/binary>>,
                             crypto = Crypto} = State) ->

  case crypto:crypto_update(Crypto, ProtocolId) of
    <<"discv5">> ->
      do_parse(static_header, State#state{bytes_to_decode = Rest});

    _ -> {error, "Incorrect protocol ID"}
  end;

do_parse(static_header, #state{bytes_to_decode = <<StaticHeader:17/binary, Rest/binary>>,
                               crypto = Crypto} = State) ->

  case crypto:crypto_update(Crypto, StaticHeader) of
    <<Version:2/big-unsigned-integer-unit:8,
      Flag:1/big-unsigned-integer-unit:8,
      Nonce:12/big-unsigned-integer-unit:8,
      AuthdataSize:2/big-unsigned-integer-unit:8>> ->

      DecodedStaticHeader = #static_header{
                               version       = Version,
                               flag          = Flag,
                               nonce         = Nonce,
                               authdata_size = AuthdataSize
                              },
      do_parse(authdata, State#state{bytes_to_decode = Rest, static_header = DecodedStaticHeader});

    _ -> {error, "Cannot parse static header"}
  end;

do_parse(authdata, #state{bytes_to_decode = Input,
                          static_header = #static_header{authdata_size = AuthdataSize},
                          crypto = Crypto} = State) ->

  case Input of
    <<AuthData:AuthdataSize/binary, Rest/binary>> ->
      DecodedAuthData = crypto:crypto_update(Crypto, AuthData),
      do_parse(finalize_crypto, State#state{bytes_to_decode = Rest, authdata = DecodedAuthData});

    _ -> {error, "Cannot parse AuthData"}
  end;

do_parse(finalize_crypto, #state{crypto = Crypto} = State) ->
  crypto:crypto_final(Crypto),
  do_parse(decode_flag, State);

do_parse(decode_flag, #state{static_header = #static_header{flag = Flag}} = State) ->
  case Flag of
    ?ORDINARY_MSG_FLAG ->
      do_parse(message, State#state{});

    ?WHOAREYOU_MSG_FLAG ->
      do_parse(whoareyou, State#state{});

    ?HANDSHAKE_MSG_FLAG ->
      do_parse(handshake, State#state{});

    _ -> {error, "Unknown flag."}
  end;

do_parse(message, #state{static_header = #static_header{authdata_size = AuthdataSize}})
  when AuthdataSize /= 32 ->
  {error, "Incorrect Authdata size"};

do_parse(message, #state{bytes_to_decode = Payload, authdata = AuthData} = State) ->
  OrdinaryMsg = #ordinary_message{src_id = AuthData, data = Payload},
  do_parse(message_data, State#state{payload = OrdinaryMsg});

do_parse(message_data, #state{payload = OrdinaryMsg} = State) ->
  {ok, State};

do_parse(whoareyou, #state{static_header = #static_header{authdata_size = AuthdataSize}})
  when AuthdataSize /= 24 ->
  {error, "Incorrect Authdata size"};

do_parse(whoareyou, #state{bytes_to_decode = <<IdNonce:16/big-unsigned-integer-unit:8,
                                               EnrSeq:8/big-unsigned-integer-unit:8>>} = State) ->
  WhoAreYou = #whoareyou_message{id_nonce = IdNonce, enr_seq = EnrSeq},
  {ok, State#state{payload = WhoAreYou}};

do_parse(handshake, #state{static_header = #static_header{authdata_size = AuthdataSize}})
  when AuthdataSize < 34 ->
  {error, "Invalid Authdata size"};

do_parse(handshake, #state{authdata = Authdata,
                           static_header = #static_header{authdata_size = AuthdataSize}} = State) ->
  <<SrcId:32/binary,
    SigSize:1/big-unsigned-integer-unit:8,
    EphKeySize:1/big-unsigned-integer-unit:8,
    Rest/binary>> = Authdata,
  AuthdataHead = #authdata_head{
                    src_id       = SrcId,
                    sig_size     = SigSize,
                    eph_key_size = EphKeySize
                   },
  RecordLen = AuthdataSize - (34 + 1 + 1),
  <<IdSignature:SigSize/binary, EphPubkey:EphKeySize/binary, Record:RecordLen/binary>> = Rest,
  Handshake = #handshake_message{
                 authdata_head = AuthdataHead,
                 id_signature  = IdSignature,
                 eph_pubkey    = EphPubkey,
                 record        = Record
                },
  do_parse(message, State#state{payload = Handshake});

do_parse(_, _) ->
  {error, unexpected}.

node_a() ->
  binary:decode_hex(<<"aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb">>).

node_b() ->
  binary:decode_hex(<<"bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9">>).

ping_msg() ->
  binary:decode_hex(<<"00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad",
                      "52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102",
                      "ed931f66d1492acb308fa1c6715b9d139b81acbdcc">>).
