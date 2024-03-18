-module(discv5_codec).

-export([
         decode_packet/2,
         decode_protocol_message/4,
         encode_protocol_message/4,
         create_message_ad/3,
         nonce/0,
         nonce/1
        ]).
-export_type([parse_result/0]).

-include_lib("discv5.hrl").

-type parse_result() ::
  {ok, #ordinary_message{}} |
  {ok, #whoareyou_message{}} |
  {ok, #handshake_message{}} |
  {error, binary()}.

-spec decode_packet(binary(), binary()) -> parse_result().

-record(state, {
          bytes_to_decode :: binary(),
          masking_iv      :: binary(),
          static_header   :: static_header(),
          authdata        :: authdata(),
          node_id,
          crypto,
          message_ad      :: binary()
         }).

decode_packet(Input, NodeId)
  when is_binary(Input)
       andalso byte_size(Input) >= 63
       andalso byte_size(Input) =< 1280 ->

  do_decode(init_crypto, #state{bytes_to_decode = Input, node_id = NodeId});

decode_packet(_, _) ->
  {error, unexpected1}.

do_decode(init_crypto, #state{bytes_to_decode = <<MaskingIV:16/binary, Rest/binary>>,
                              node_id         = <<MaskingKey:16/binary, _/binary>>} = State) ->

  Crypto = crypto:crypto_init(aes_128_ctr, MaskingKey, MaskingIV, [{encrypt, false}]),
  do_decode(protocol_id, State#state{
                           masking_iv      = MaskingIV,
                           crypto          = Crypto,
                           bytes_to_decode = Rest
                          });

do_decode(protocol_id, #state{bytes_to_decode = <<ProtocolId:6/binary, Rest/binary>>,
                              crypto          = Crypto} = State) ->

  case crypto:crypto_update(Crypto, ProtocolId) of
    <<"discv5">> ->
      do_decode(static_header, State#state{
                                 bytes_to_decode = Rest
                                });

    _ -> {error, "Incorrect protocol ID"}
  end;

do_decode(static_header, #state{bytes_to_decode = <<StaticHeader:17/binary, Rest/binary>>,
                                crypto          = Crypto} = State) ->

  case crypto:crypto_update(Crypto, StaticHeader) of
    <<Version:2/big-unsigned-integer-unit:8,
      Flag:1/big-unsigned-integer-unit:8,
      Nonce:12/binary,
      AuthdataSize:2/big-unsigned-integer-unit:8>> = DecodedStaticHeader ->

      StaticHeaderRecord = #static_header{
                              version       = Version,
                              flag          = Flag,
                              nonce         = Nonce,
                              authdata_size = AuthdataSize
                             },
      do_decode(authdata, State#state{
                            bytes_to_decode = Rest,
                            static_header   = StaticHeaderRecord
                           });

    _ -> {error, "Cannot parse static header"}
  end;

do_decode(authdata, #state{bytes_to_decode = Input,
                           masking_iv      = MaskingIV,
                           static_header   = StaticHeader,
                           crypto          = Crypto} = State) ->

  #static_header{authdata_size = AuthdataSize} = StaticHeader,

  case Input of
    <<AuthData:AuthdataSize/binary, Rest/binary>> ->
      DecodedAuthData = crypto:crypto_update(Crypto, AuthData),
      MessageAd = create_message_ad(MaskingIV, StaticHeader, DecodedAuthData),
      do_decode(finalize_crypto, State#state{
                                   bytes_to_decode = Rest,
                                   authdata        = DecodedAuthData,
                                   message_ad      = MessageAd
                                  });

    _ -> {error, "Cannot parse AuthData"}
  end;

do_decode(finalize_crypto, #state{crypto = Crypto} = State) ->
  crypto:crypto_final(Crypto),
  do_decode(decode_flag, State);

do_decode(decode_flag, #state{static_header = #static_header{flag = Flag}} = State) ->
  case Flag of
    ?ORDINARY_MSG_FLAG ->
      do_decode(ordinary_message, State);

    ?WHOAREYOU_MSG_FLAG ->
      do_decode(whoareyou, State);

    ?HANDSHAKE_MSG_FLAG ->
      do_decode(handshake, State);

    _ -> {error, "Unknown flag."}
  end;

do_decode(ordinary_message, #state{static_header = #static_header{authdata_size = AuthdataSize}})
  when AuthdataSize /= 32 ->
  {error, "Incorrect Authdata size"};

do_decode(ordinary_message, #state{bytes_to_decode = Payload,
                                   authdata        = SrcId,
                                   static_header   = StaticHeader,
                                   message_ad      = MessageAd
                                  }) ->
  {ok, #ordinary_message{
          data          = Payload,
          static_header = StaticHeader,
          authdata      = #authdata{src_id = SrcId},
          message_ad    = MessageAd
         }};

do_decode(whoareyou, #state{static_header = #static_header{authdata_size = AuthdataSize}})
  when AuthdataSize /= 24 ->
  {error, "Incorrect Authdata size"};

do_decode(whoareyou, #state{authdata = <<IdNonce:16/binary,
                                         EnrSeq:8/big-unsigned-integer-unit:8>>,
                            static_header = StaticHeader
                           }) ->
  WhoAreYou = #whoareyou_message{
                 static_header = StaticHeader,
                 authdata      = #authdata{
                                    id_nonce = IdNonce,
                                    enr_seq  = EnrSeq
                                   }
                },
  {ok, WhoAreYou};

do_decode(handshake, #state{static_header = #static_header{authdata_size = AuthdataSize}})
  when AuthdataSize < 34 ->
  {error, "Invalid Authdata size"};

do_decode(handshake, #state{authdata        = Authdata,
                            bytes_to_decode = BytesToDecode,
                            static_header   = StaticHeader,
                            message_ad      = MessageAd
                           }) ->
  <<SrcId:32/binary,
    SigSize:1/big-unsigned-integer-unit:8,
    EphKeySize:1/big-unsigned-integer-unit:8,
    Rest/binary>> = Authdata,
  AuthdataHead = #authdata_head{
                    src_id       = SrcId,
                    sig_size     = SigSize,
                    eph_key_size = EphKeySize
                   },
  #static_header{authdata_size = AuthdataSize} = StaticHeader,
  RecordLen = AuthdataSize - (34 + SigSize + EphKeySize),
  <<IdSignature:SigSize/binary, EphPubkey:EphKeySize/binary, EncodedRecord:RecordLen/binary>> = Rest,
  Record = case enr:decode_rlp(EncodedRecord) of
           {ok, Rec} -> Rec;
           {error, _} -> nil
         end,
  Handshake = #handshake_message{
                 data          = BytesToDecode,
                 static_header = StaticHeader,
                 authdata      = #authdata{
                                    authdata_head = AuthdataHead,
                                    id_signature  = IdSignature,
                                    eph_pubkey    = EphPubkey,
                                    record        = Record
                                   },
                 message_ad    = MessageAd
                },
  {ok, Handshake};

do_decode(Stage, #state{bytes_to_decode = BytesToDecode} = State) ->
  io:format(">>>WTF\n Stage: ~p\n State: ~p\n BytesToDecode: ~p\n", [Stage, State, BytesToDecode]),
  {error, unexpected}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
decode_protocol_message(Key, Encrypted, StaticHeader, MessageAd) ->
  #static_header{nonce = Nonce} = StaticHeader,
  DataLen = byte_size(Encrypted),
  <<Data:(DataLen - ?TAG_LEN)/binary, Tag/binary>> = Encrypted,
  Result = crypto:crypto_one_time_aead(
             aes_128_gcm,
             Key,
             Nonce,
             Data,
             MessageAd,
             Tag,
             false
            ),
  case Result of
    error ->
      {error, "Cannot decrypt message"};
    DecryptedData ->
      do_decode_protocol_message(DecryptedData)
  end.

do_decode_protocol_message(<<MsgType:8/big-unsigned-integer, EncodedMsg/binary>>) ->
  {ok, [RequestId | DecodedMsg]} = rlp:decode(EncodedMsg),
  case MsgType of
    ?PING_ID ->
      [EnrSeq] = DecodedMsg,
      {ok, #ping{request_id = RequestId, enr_seq = EnrSeq}};
    ?PONG_ID ->
      [EnrSeq, RecipientIp, RecipientPort] = DecodedMsg,
      {ok, #pong{request_id     = RequestId,
                 enr_seq        = EnrSeq,
                 recipient_ip   = RecipientIp,
                 recipient_port = RecipientPort}};
    ?FINDNODE_ID ->
      Distances = DecodedMsg,
      {ok, #findnode{request_id = RequestId, distances = Distances}};
    ?NODES_ID ->
      [Total, Enrs] = DecodedMsg,
      {ok, #nodes{request_id = RequestId, total = Total, enrs = Enrs}};
    ?TALKREQ_ID ->
      [Protocol, Request] = DecodedMsg,
      {ok, #talkreq{request_id = RequestId, protocol = Protocol, request = Request}};
    ?TALKRESP_ID ->
      [Response] = DecodedMsg,
      {ok, #talkresp{request_id = RequestId, response = Response}};
    ?REGTOPIC_ID ->
      [Topic, ENR, Ticket] = DecodedMsg,
      {ok, #regtopic{request_id = RequestId, topic = Topic, enr = ENR, ticket = Ticket}};
    ?TICKET_ID ->
      [Tocket, WaitTime] = DecodedMsg,
      {ok, #ticket{request_id = RequestId, ticket = Tocket, wait_time = WaitTime}};
    ?REGCONFIRMATION_ID ->
      [Topic] = DecodedMsg,
      {ok, #regconfirmation{request_id = RequestId, topic = Topic}};
    ?TOPICQUERY_ID ->
      [Topic] = DecodedMsg,
      {ok, #topicquery{request_id = RequestId, topic = Topic}}
  end;

do_decode_protocol_message(_) ->
  {error, "Unknown message type"}.

encode_protocol_message(Key, Message, StaticHeader, MessageAd) ->
  #static_header{nonce = Nonce} = StaticHeader,
  {Selector, List} = do_encode_protocol_message(Message),
  case rlp:encode(List) of
    {ok, Encoded} ->
      Payload = <<Selector:1/big-unsigned-integer-unit:8, Encoded/binary>>,
      Result = crypto:crypto_one_time_aead(
                 aes_128_gcm,
                 Key,
                 Nonce,
                 Payload,
                 MessageAd,
                 ?TAG_LEN,
                 true),
      case Result of
        error ->
          {error, "Cannot encrypt message"};
        {Encrypted, Tag} ->
          {ok, <<Encrypted/binary, Tag/binary>>}
      end;
    {error, _} = E -> E
  end.

do_encode_protocol_message(#ping{request_id = RequestId, enr_seq = EnrSeq}) ->
  {?PING_ID, [RequestId, EnrSeq]};

do_encode_protocol_message(#pong{request_id     = RequestId,
                                 enr_seq        = EnrSeq,
                                 recipient_ip   = RecipientIp,
                                 recipient_port = RecipientPort}) ->
  {?PONG_ID, [RequestId, EnrSeq, RecipientIp, RecipientPort]};

do_encode_protocol_message(#findnode{request_id = RequestId,
                                     distances  = Distances}) ->
  {?FINDNODE_ID, [RequestId, Distances]};

do_encode_protocol_message(#nodes{request_id = RequestId,
                                  total      = Total,
                                  enrs       = Enrs}) ->
  {?NODES_ID, [RequestId, Total, Enrs]};

do_encode_protocol_message(#talkreq{request_id = RequestId,
                                    protocol   = Protocol,
                                    request    = Request}) ->
  {?TALKREQ_ID, [RequestId, Protocol, Request]};

do_encode_protocol_message(#talkresp{request_id = RequestId, response = Response}) ->
  {?TALKRESP_ID, [RequestId, Response]};

do_encode_protocol_message(#regtopic{request_id = RequestId,
                                     topic      = Topic,
                                     enr        = ENR,
                                     ticket     = Ticket}) ->
  {?REGTOPIC_ID, [RequestId, Topic, ENR, Ticket]};

do_encode_protocol_message(#ticket{request_id = RequestId,
                                   ticket     = Tocket,
                                   wait_time  = WaitTime}) ->
  {?TICKET_ID, [RequestId, Tocket, WaitTime]};

do_encode_protocol_message(#regconfirmation{request_id = RequestId,
                                            topic      = Topic}) ->
  {?REGCONFIRMATION_ID, [RequestId, Topic]};

do_encode_protocol_message(#topicquery{request_id = RequestId,
                                       topic      = Topic}) ->
  {?TOPICQUERY_ID, [RequestId, Topic]}.

create_message_ad(MaskingIV, StaticHeader, AuthData) ->
  #static_header{protocol_id   = ProtocolId,
                 version       = Version,
                 flag          = Flag,
                 nonce         = Nonce,
                 authdata_size = AuthdataSize} = StaticHeader,
  <<MaskingIV/binary,
    ProtocolId:6/binary,
    Version:2/big-unsigned-integer-unit:8,
    Flag:1/big-unsigned-integer-unit:8,
    Nonce:12/binary,
    AuthdataSize:2/big-unsigned-integer-unit:8,
    AuthData/binary>>.

nonce() ->
  crypto:strong_rand_bytes(12).

nonce(Counter) ->
  Random = crypto:strong_rand_bytes(8),
  <<Counter:4/big-unsigned-integer-unit:8, Random/binary>>.
