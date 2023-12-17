-module(enr).

-export([
         encode/1,
         decode/1,
         test_vector_struct/0,
         test_vector_base64/0,
         test_vector_decode_base64/0,
         test_compressed/0
        ]).

-record(enr_v4, {
  signature    = <<>> :: nonempty_binary(),
  content_hash = <<>> :: nonempty_binary(),
  seq          = 0 :: non_neg_integer(),
  kv           = [] :: list(tuple())
}).

-opaque enr_v4() :: #enr_v4{}.
-export_type([enr_v4/0]).

-spec encode(enr_v4()) -> {ok, binary()} | {error, binary()}.
encode(Record) ->
  SortedKV = lists:sort(lists:uniq(Record#enr_v4.kv), fun ({A, _}, {B, _}) -> A < B end),
  FlatKV = lists:foldl(fun ({Key, Value}, Acc) -> [Key, Value | Acc] end, [], SortedKV),
  EncodedKV = rlp:encode(Record#enr_v4.kv),
  Raw = <<>>,
  Encoded = base64:encode(Raw, #{mode => urlsafe}),
  Ret = <<"enr:"/binary, Encoded/binary>>,
  {ok, Ret}.

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
  [Encoded] = binary:split(ENR, <<"enr:">>, [trim_all]),
  Raw = base64:decode(Encoded, #{mode => urlsafe, padding => false}),
  {ok, List} = rlp:decode(Raw),
  case decode(signature, List, #enr_v4{}) of
    {ok, Struct} ->
      {ok, Struct};
    {error, Reason} ->
      {error, Reason}
  end.

decode(signature, [Signature | Rest], Struct) ->
  io:format("Signature: ~p~nRest: ~p~n", [Signature, Rest]),
  {ok, EncodedRest} = rlp:encode(Rest),
  ContentHash = keccak:keccak_256(EncodedRest),
  decode(seq, Rest, Struct#enr_v4{signature = Signature, content_hash = ContentHash});

% TODO seq is 64 bit integer according to spec
% but in fact it is not, it is variable in size from 1 to 4 bytes
decode(seq, [Seq | Rest], Struct) ->
  io:format("Seq: ~p~n", [Seq]),
  decode(id, Rest, Struct#enr_v4{seq = Seq});

decode(id, [<<"id">>, ID | Rest], Struct) when ID == <<"v4">> ->
  io:format("ID: ~p~n", [ID]),
  decode(pair, Rest, Struct#enr_v4{kv = [<<"id">>, ID]});

decode(pair, [<<"secp256k1">> = Key, Value | Rest], #enr_v4{kv = KV, signature = Signature, content_hash = ContentHash} = Struct) ->
  io:format("Key: ~p, Value: ~p\n", [Key, Value]),
  case verify(ContentHash, Signature, Value) of
    true ->
      decode(pair, Rest, Struct#enr_v4{kv = [{Key, Value}| KV]});
    false ->
      {error, <<"Signature verification failed">>}
  end;

decode(pair, [Key, Value | Rest], #enr_v4{kv = KV} = Struct) ->
  io:format("Key: ~p, Value: ~p\n", [Key, Value]),
  decode(pair, Rest, Struct#enr_v4{kv = [{Key, Value}| KV]});

decode(pair, [], Struct) ->
  io:format("Base case~n"),
  {ok, Struct};

decode(Stage, List, State) ->
  io:format("Stage: ~p, List: ~p, State: ~p~n", [Stage, List, State]),
  {error, <<"Cannot decode ENR">>}.

verify(Digest, Signature, PubKey) ->
  case libsecp256k1:ecdsa_verify_compact(Digest, Signature, PubKey) of
    ok -> true;
    error -> false;
    {error, _} -> false
  end.

% sign(Content, PrivateKey) ->
%   Digest = keccak:keccak_256(Content),
%   {ok, Signature, RecoveryId} = libsecp256k1:ecdsa_sign_compact(Digest, PrivateKey, default, <<>>),
%   io:format(">>> Signature: ~p~nRecoveryId: ~p~n", [Signature, RecoveryId]),
%   Signature.

test_compressed() ->
	Msg = <<"Test">>,
	A = crypto:strong_rand_bytes(32),
	{ok, Pubkey} = libsecp256k1:ec_pubkey_create(A, compressed),
  io:format(">>> PubKey length: ~p~n", [byte_size(Pubkey)]),
  io:format(">>> Pubkey: ~p~n", [Pubkey]),
	{ok, Signature, _} = libsecp256k1:ecdsa_sign_compact(Msg, A, default, <<>>),
  io:format(">>> Signature: ~p~n", [Signature]),
  io:format(">>> Signature length: ~p~n", [byte_size(Signature)]),
  libsecp256k1:ecdsa_verify_compact(Msg, Signature, Pubkey).

test_vector_struct() ->
  [
   integer_to_binary(16#7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c, 16),
   integer_to_binary(16#01, 16),
   <<"id">>,
   <<"v4">>,
   <<"ip">>,
   integer_to_binary(16#7f000001, 16),
   <<"secp256k1">>,
   integer_to_binary(16#03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138, 16),
   <<"udp">>,
   integer_to_binary(16#765f, 16)
  ].

test_vector_base64() ->
  <<"enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8">>.

test_vector_decode_base64() ->
  [Encoded] = binary:split(test_vector_base64(), <<"enr:">>, [trim_all]),
  base64:decode(Encoded, #{mode => urlsafe, padding => false}).


to_hex({ok, Bin}) ->
  to_hex(Bin);
to_hex(Bin) when is_binary(Bin) ->
  io_lib:format("~s\n", [[io_lib:format("~2.16.0B ",[X]) || <<X:8>> <= Bin ]]).
