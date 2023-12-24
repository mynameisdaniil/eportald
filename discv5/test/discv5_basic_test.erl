-module(discv5_basic_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("src/discv5.hrl").

-define(PING_MSG, binary:decode_hex(<<"00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad",
                                      "52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102",
                                      "ed931f66d1492acb308fa1c6715b9d139b81acbdcc">>)).

-define(NODE_A_PRIVKEY, binary:decode_hex(<<"eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f">>)).
-define(NODE_B_PRIVKEY, binary:decode_hex(<<"66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628">>)).

-define(SRC_NODE_ID, binary:decode_hex(<<"aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb">>)).
-define(DST_NODE_ID, binary:decode_hex(<<"bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9">>)).

decode_ping_test() ->
  Decoded = discv5_codec:decode(?PING_MSG, ?DST_NODE_ID),
  ?assertEqual({ok, #ordinary_message{src_id = ?SRC_NODE_ID}}, Decoded).
