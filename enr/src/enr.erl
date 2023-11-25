-module(enr).

-export([encode/1, decode/1]).

-record(enr_v4, {
  signature = <<>> :: nonempty_binary(),
  seq       = 0 :: non_neg_integer(),
  id        = <<"v4">> :: nonempty_binary(),
  secp256k1 = <<>> :: nonempty_binary(),
  ip        = <<>> :: nonempty_binary(),
  tcp_port  = 0 :: non_neg_integer(),
  udp_port  = 0 :: non_neg_integer(),
  ipv6      = <<>> :: binary(),
  tcp6_port = 0 :: non_neg_integer(),
  udp6_port = 0 :: non_neg_integer(),
  kv        = [] :: list(tuple())
}).

-opaque enr_v4() :: #enr_v4{}.
-export_type([enr_v4/0]).

-spec encode(enr_v4()) -> {ok, binary()} | {error, binary()}.
encode(Record) ->
  {ok, <<"">>}.

-spec decode(binary()) -> {ok, enr_v4()} | {error, binary()}.
% Max length of ENR is 300 bytes according to spec
% https://github.com/ethereum/devp2p/blob/master/enr.md#rlp-encoding
decode(ENR) when byte_size(ENR) > 300 ->
  {error, <<"ENR is too long">>};

% Minimal ENR is 64 + 8 + 2 + 33 bytes
% 64 bytes is sginature
% 8 bytes is 64 bit seq
% 4 bytes is {"id","v4"} in key-value pairs, rquired by the spec
% 33 bytes is {"secp256k1", <<>>} in key-value pairs - although spec says it's not required,
% in fact it is, otherwise it is impossible to verify singature
decode(ENR) when byte_size(ENR) < 118 ->
  {error, <<"ENR is too short">>};

decode(ENR) ->
  {ok, #enr_v4{}}.
