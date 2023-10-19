-module(vectors_SUITE).

-include_lib("common_test/include/ct.hrl").
-include("discv5.hrl").

-export([all/0]).
-export([decode_static_header/1, decode_variable_header/1]).

all() -> [decode_static_header, decode_variable_header].

decode_static_header(_Config) ->
  Message = ping_msg(),
  LocalId = node_b(),
  {ok, MaskedHeader, _Rest} = discv5_parser:decode_masked_header(Message, LocalId).

decode_variable_header(_Config) ->
  ok.

node_a() ->
  binary:decode_hex(<<"aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb">>).

node_b() ->
  binary:decode_hex(<<"bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9">>).

ping_msg() ->
  binary:decode_hex(<<"00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc">>).
