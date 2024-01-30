-module(discv5_codec).

-export([decode_packet/2, decode_protocol_message/3]).
-export_type([parse_result/0]).

-export([node_a_id/0,
         node_b_id/0,
         ping_msg/0,
         whoareyou_msg/0,
         to_hex/1,
         handshake_msg/0,
         handshake_msg_with_enr/0
        ]).

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
    16#01 ->
      [EnrSeq] = DecodedMsg,
      {ok, #ping{request_id = RequestId, enr_seq = EnrSeq}}
  end;

do_decode_protocol_message(_) ->
  {error, "Unknown message type"}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

node_a_id() ->
  binary:decode_hex(<<"aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb">>).

node_b_id() ->
  binary:decode_hex(<<"bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9">>).

ping_msg() ->
  binary:decode_hex(<<"00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad",
                      "52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102",
                      "ed931f66d1492acb308fa1c6715b9d139b81acbdcc">>).

whoareyou_msg() ->
  binary:decode_hex(<<"00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad1d6035f15e",
                      "528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d">>).


handshake_msg() ->
  binary:decode_hex(<<"00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad",
                      "521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb252",
                      "012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef268ccb9065aeecfd67a999e7fdc137",
                      "e062b2ec4a0eb92947f0d9a74bfbf44dfba776b21301f8b65efd5796706adff216ab862a91",
                      "86875f9494150c4ae06fa4d1f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a8",
                      "85b1f8bd2a5d839cf8">>).

handshake_msg_with_enr() ->
  binary:decode_hex(<<"00000000000000000000000000000000088b3d4342774649305f313964a39e55",
                      "ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3",
                      "4c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be9856",
                      "2fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b2",
                      "1481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1",
                      "f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6",
                      "cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb1",
                      "2a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a",
                      "80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e",
                      "4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b1394">>).

to_hex({ok, Bin}) ->
  to_hex(Bin);
to_hex(Int) when is_integer(Int) ->
  to_hex(binary:encode_unsigned(Int));
to_hex(Bin) when is_binary(Bin) ->
  io_lib:format("~s\n", [[io_lib:format("~2.16.0b",[X]) || <<X:8>> <= Bin ]]).
