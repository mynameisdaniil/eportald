-module(discv5_codec).

-export([decode_packet/2, decode_protocol_message/3, encode_protocol_message/3]).
-export_type([parse_result/0]).

-include("discv5.hrl").

-type parse_result() ::
  {ok, term()}
  | {error, unexpected}.

-spec decode_packet(binary(), binary()) -> parse_result().

-record(state, {
          static_header,
          authdata,
          bytes_to_decode,
          node_id,
          crypto,
          message_ad
         }).

decode_packet(Input, NodeId)
  when is_binary(Input)
       andalso byte_size(Input) >= 63
       andalso byte_size(Input) =< 1280 ->

  do_decode(init_crypto, #state{bytes_to_decode = Input, node_id = NodeId});

decode_packet(_, _) ->
  {error, unexpected1}.

do_decode(init_crypto, #state{bytes_to_decode = <<MaskingIV:16/binary, Rest/binary>>,
                             node_id          = <<MaskingKey:16/binary, _/binary>>} = State) ->

  Crypto = crypto:crypto_init(aes_128_ctr, MaskingKey, MaskingIV, [{encrypt, false}]),
  do_decode(protocol_id, State#state{
                           crypto          = Crypto,
                           bytes_to_decode = Rest,
                           message_ad      = [{masking_iv, MaskingIV}]
                          });

do_decode(protocol_id, #state{bytes_to_decode = <<ProtocolId:6/binary, Rest/binary>>,
                              message_ad      = MessageAd,
                              crypto          = Crypto} = State) ->

  case crypto:crypto_update(Crypto, ProtocolId) of
    <<"discv5">> = DecodedProtocolID ->
      do_decode(static_header, State#state{
                                 bytes_to_decode = Rest,
                                 message_ad      = [{protocol_id, DecodedProtocolID} | MessageAd]
                                });

    _ -> {error, "Incorrect protocol ID"}
  end;

do_decode(static_header, #state{bytes_to_decode = <<StaticHeader:17/binary, Rest/binary>>,
                                message_ad      = MessageAd,
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
                            static_header   = StaticHeaderRecord,
                            message_ad      = [{static_header, DecodedStaticHeader} | MessageAd]
                           });

    _ -> {error, "Cannot parse static header"}
  end;

do_decode(authdata, #state{bytes_to_decode = Input,
                          static_header    = #static_header{authdata_size = AuthdataSize},
                          message_ad       = MessageAd,
                          crypto           = Crypto} = State) ->

  case Input of
    <<AuthData:AuthdataSize/binary, Rest/binary>> ->
      DecodedAuthData = crypto:crypto_update(Crypto, AuthData),
      do_decode(finalize_crypto, State#state{
                                   bytes_to_decode = Rest,
                                   authdata        = DecodedAuthData,
                                   message_ad      = [{authdata, DecodedAuthData} | MessageAd]
                                  });

    _ -> {error, "Cannot parse AuthData"}
  end;

do_decode(finalize_crypto, #state{crypto = Crypto} = State) ->
  crypto:crypto_final(Crypto),
  do_decode(decode_flag, State);

do_decode(decode_flag, #state{static_header = #static_header{flag = Flag}} = State) ->
  case Flag of
    ?ORDINARY_MSG_FLAG ->
      do_decode(ordinary_message, State#state{});

    ?WHOAREYOU_MSG_FLAG ->
      do_decode(whoareyou, State#state{});

    ?HANDSHAKE_MSG_FLAG ->
      do_decode(handshake, State#state{});

    _ -> {error, "Unknown flag."}
  end;

do_decode(ordinary_message, #state{static_header = #static_header{authdata_size = AuthdataSize}})
  when AuthdataSize /= 32 ->
  {error, "Incorrect Authdata size"};

do_decode(ordinary_message, #state{bytes_to_decode = Payload,
                          authdata        = SrcId,
                          static_header   = #static_header{nonce = Nonce},
                          message_ad      = MessageAdProplist}) ->
  %% TODO: rewrite this to use offsets in the binary, rather than copying
  MessageAd = lists:foldl(fun({_Key, Value}, Acc) ->
                             <<Value/binary, Acc/binary>>
                           end, <<>>, MessageAdProplist),
  {ok, #ordinary_message{
          data   = Payload,
          src_id = SrcId,
          meta   = #meta{nonce      = Nonce,
                         message_ad = MessageAd}}};

do_decode(whoareyou, #state{static_header = #static_header{authdata_size = AuthdataSize}})
  when AuthdataSize /= 24 ->
  {error, "Incorrect Authdata size"};

do_decode(whoareyou, #state{authdata = <<IdNonce:16/binary,
                                         EnrSeq:8/big-unsigned-integer-unit:8>>}) ->
  WhoAreYou = #whoareyou_message{id_nonce = IdNonce, enr_seq = EnrSeq},
  {ok, WhoAreYou};

do_decode(handshake, #state{static_header = #static_header{authdata_size = AuthdataSize}})
  when AuthdataSize < 34 ->
  {error, "Invalid Authdata size"};

do_decode(handshake, #state{authdata = Authdata, bytes_to_decode = BytesToDecode,
                           static_header = #static_header{authdata_size = AuthdataSize},
                           message_ad = MessageAdProplist}) ->
  <<SrcId:32/binary,
    SigSize:1/big-unsigned-integer-unit:8,
    EphKeySize:1/big-unsigned-integer-unit:8,
    Rest/binary>> = Authdata,
  AuthdataHead = #authdata_head{
                    src_id       = SrcId,
                    sig_size     = SigSize,
                    eph_key_size = EphKeySize
                   },
  RecordLen = AuthdataSize - (34 + SigSize + EphKeySize),
  <<IdSignature:SigSize/binary, EphPubkey:EphKeySize/binary, EncodedRecord:RecordLen/binary>> = Rest,
  Record = case enr:decode_rlp(EncodedRecord) of
           {ok, Rec} -> Rec;
           {error, _} -> nil
         end,
  MessageAd = lists:foldl(fun({_Key, Value}, Acc) ->
                             <<Value/binary, Acc/binary>>
                           end, <<>>, MessageAdProplist),
  Handshake = #handshake_message{
                 authdata_head = AuthdataHead,
                 id_signature  = IdSignature,
                 eph_pubkey    = EphPubkey,
                 record        = Record,
                 data          = BytesToDecode,
                 meta          = #meta{message_ad = MessageAd}},
  {ok, Handshake};

do_decode(Stage, #state{bytes_to_decode = BytesToDecode} = State) ->
  io:format(">>>WTF\n Stage: ~p\n State: ~p\n BytesToDecode: ~p\n", [Stage, State, BytesToDecode]),
  {error, unexpected}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
decode_protocol_message(Key, Encrypted, Meta) ->
  #meta{message_ad = MessageAd, nonce = Nonce} = Meta,
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

encode_protocol_message(Key, Message, Meta) ->
  {Selector, List} = do_encode_protocol_message(Message),
  case rlp:encode(List) of
    {ok, Encoded} ->
      Payload = <<Selector/binary, Encoded/binary>>,
      #meta{message_ad = MessageAd, nonce = Nonce} = Meta,
      Result = crypto:crypto_one_time_aead(
                 aes_128_gcm,
                 Key,
                 Nonce,
                 Payload,
                 MessageAd,
                 ?TAG_LEN,
                 true
                ),
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
