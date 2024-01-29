-module(discv5_codec_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("src/discv5.hrl").

-define(PING_MSG,
        binary:decode_hex(<<"00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad",
                            "52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102",
                            "ed931f66d1492acb308fa1c6715b9d139b81acbdcc">>)).

-define(WHOAREYOU_MSG,
        binary:decode_hex(<<"00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad1d6035f15e",
                            "528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d">>)).

-define(HANDSHAKE_PING_MSG,
        binary:decode_hex(<<"00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad"
                            "521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb252"
                            "012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef268ccb9065aeecfd67a999e7fdc137"
                            "e062b2ec4a0eb92947f0d9a74bfbf44dfba776b21301f8b65efd5796706adff216ab862a91"
                            "86875f9494150c4ae06fa4d1f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a8"
                            "85b1f8bd2a5d839cf8">>)).

-define(HANDSHAKE_PING_MSG_WITH_ENR,
        binary:decode_hex(<<"00000000000000000000000000000000088b3d4342774649305f313964a39e55"
                            "ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3"
                            "4c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be9856"
                            "2fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b2"
                            "1481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1"
                            "f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6"
                            "cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb1"
                            "2a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a"
                            "80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e"
                            "4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b1394"
                            "71">>)).

% -define(NODE_A_PRIVKEY, binary:decode_hex(<<"eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f">>)).
% -define(NODE_B_PRIVKEY, binary:decode_hex(<<"66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628">>)).

-define(SRC_NODE_ID, binary:decode_hex(<<"aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb">>)).
-define(DST_NODE_ID, binary:decode_hex(<<"bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9">>)).

-define(READ_KEY_A, binary:decode_hex(<<"00000000000000000000000000000000">>)).
-define(READ_KEY_B, binary:decode_hex(<<"4f9fac6de7567d1e3b1241dffe90f662">>)).
-define(READ_KEY_C, binary:decode_hex(<<"53b1c075f41876423154e157470c2f48">>)).

decode_ping_test() ->
  {ok, #ordinary_message{src_id = SrcId,
                         data   = Encoded,
                         meta   = Meta}} = discv5_codec:decode_packet(?PING_MSG, ?DST_NODE_ID),
  ?assertEqual(?SRC_NODE_ID, SrcId),
  Decoded = discv5_codec:decode_protocol_message(?READ_KEY_A, Encoded, Meta),
  ?assertEqual({ok, #ping{request_id = <<0, 0, 0, 1>>, enr_seq = 2}}, Decoded).

decode_whoareyou_test() ->
  {ok, Decoded} = discv5_codec:decode_packet(?WHOAREYOU_MSG, ?DST_NODE_ID),
  IdNonce = binary:decode_hex(<<"0102030405060708090a0b0c0d0e0f10">>),
  ?assertEqual(#whoareyou_message{id_nonce = IdNonce, enr_seq = 0}, Decoded).

decode_handshake_ping_test() ->
  {ok, Handshake} = discv5_codec:decode_packet(?HANDSHAKE_PING_MSG, ?DST_NODE_ID),
  #handshake_message{
     data          = Data,
     authdata_head = #authdata_head{
                        src_id = SrcId
                       },
     % id_signature  = IdSignature,
     eph_pubkey    = EphemeralPubkey,
     record        = Record,
     meta          = #meta{message_ad = MessageAd}
    } = Handshake,
  ?assertEqual(?SRC_NODE_ID, SrcId),
  % ?assertEqual(<<>>, IdSignature),
  ?assertEqual(binary:decode_hex(<<"039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5">>), EphemeralPubkey),
  ?assertEqual(nil, Record),
  Nonce = binary:decode_hex(<<"ffffffffffffffffffffffff">>),
  Meta = #meta{nonce = Nonce, message_ad = MessageAd},
  {ok, Ping} = discv5_codec:decode_protocol_message(?READ_KEY_B, Data, Meta),
  ?assertEqual(#ping{request_id = <<0, 0, 0, 1>>, enr_seq = 1}, Ping).

decode_handshake_ping_with_enr_test() ->
  {ok, Handshake} = discv5_codec:decode_packet(?HANDSHAKE_PING_MSG_WITH_ENR, ?DST_NODE_ID),
  #handshake_message{
     data          = Data,
     authdata_head = #authdata_head{
                        src_id = SrcId
                       },
     % id_signature  = IdSignature,
     eph_pubkey    = EphemeralPubkey,
     record        = Record,
     meta          = #meta{message_ad = MessageAd}
    } = Handshake,
  io:format(">>> Record: ~p~n", [Record]),
  ?assertEqual(?SRC_NODE_ID, SrcId),
  % ?assertEqual(<<>>, IdSignature),
  ?assertEqual(binary:decode_hex(<<"039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5">>), EphemeralPubkey),
  Nonce = binary:decode_hex(<<"ffffffffffffffffffffffff">>),
  Meta = #meta{nonce = Nonce, message_ad = MessageAd},
  {ok, Ping} = discv5_codec:decode_protocol_message(?READ_KEY_C, Data, Meta),
  ?assertEqual(#ping{request_id = <<0, 0, 0, 1>>, enr_seq = 1}, Ping).
