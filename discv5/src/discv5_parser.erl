-module(discv5_parser).

-export([parse/2]).

-export([node_a/0, node_b/0, ping_msg/0]).

-export([decode_masked_header/2, decode_variable_header/1]).

-define(ORDINARY_MSG_FLAG, 0).
-define(WHOAREYOU_MSG_FLAG, 1).
-define(HJANDSHAKE_MSG_FLAG, 2).

-type parse_result() ::
  {ok, term()}
  | {error, unexpected}.

-spec parse(binary(), binary()) -> parse_result().

-record(state, {static_header, variable_header, body, bytes_to_decode, node_id}).
-record(masked_header, {version, flag, nonce, authdata_size}).

parse(Input, NodeId)
  when is_binary(Input)
       andalso byte_size(Input) >= 63
       andalso byte_size(Input) =< 1280 ->

  do_parse(masked_header, #state{bytes_to_decode = Input, node_id = NodeId});

parse(_, _) ->
  {error, unexpected1}.

do_parse(masked_header, #state{bytes_to_decode = Input, node_id = NodeId} = State) ->
  case decode_masked_header(Input, NodeId) of
    {error, _} = E -> E;
    {ok, StaticHeader, Rest} ->
      do_parse(variable_header, State#state{bytes_to_decode = Rest, static_header = StaticHeader})
  end;

do_parse(variable_header, #state{bytes_to_decode = Input} = State) ->
  case decode_variable_header(Input) of
    {error, _} = E -> E;
    {ok, VariableHeader, Rest} ->
      do_parse(body, State#state{bytes_to_decode = Rest, variable_header = VariableHeader})
  end;

do_parse(body, #state{bytes_to_decode = Input} = State) ->
  case decode_body(Input) of
    {error, _} = E -> E;
    {ok, Body} ->
      {ok, State#state{body = Body, bytes_to_decode = <<>>}}
  end;

do_parse(_, _) ->
  {error, unexpected2}.

decode_masked_header(<<MaskingIV:16/binary, StaticHeader:23/binary, Rest/binary>>, <<MaskingKey:16/binary, _/binary>> = _NodeId) ->
  case crypto:crypto_one_time(aes_128_ctr, MaskingKey, MaskingIV, StaticHeader, [{encrypt, false}]) of
    <<"discv5", Version:2/big-unsigned-integer-unit:8, Flag:1/big-unsigned-integer-unit:8, Nonce:12/big-unsigned-integer-unit:8, AuthdataSize:2/big-unsigned-integer-unit:8>> ->
      {ok, #masked_header{version = Version, flag = Flag, nonce = Nonce, authdata_size = AuthdataSize}, Rest};
    _ -> {error, unexpected_protocol}
  end;

decode_masked_header(_, _) ->
  {error, unexpected3}.

decode_variable_header(Input) ->
  {error, unexpected}.

decode_body(Input) ->
  {error, unexpected}.

node_a() ->
  binary:decode_hex(<<"aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb">>).

node_b() ->
  binary:decode_hex(<<"bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9">>).

ping_msg() ->
  binary:decode_hex(<<"00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc">>).
