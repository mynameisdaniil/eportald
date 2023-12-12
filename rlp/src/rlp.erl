-module(rlp).

-include_lib("rlp_constants.hrl").

%% API exports
-export([encode/1, decode/1]).

encode(Value) ->
  do_encode(Value, <<>>).

decode(Binary) ->
  case do_decode(Binary, []) of
    {ok, [Ret]} -> {ok, Ret};
    {error, _} = E -> E
  end.

do_encode(Value, Acc) ->
  {ok, Acc}.

% byte -> itself
do_decode(<<Value:1/unsigned-big-integer-unit:8, Rest/binary>>, Acc)
  when Value < ?RLP_ZERO ->
  do_decode(Rest, [Value | Acc]);

% 0-55 bytes string
do_decode(<<Value:1/unsigned-big-integer-unit:8, Rest/binary>>, Acc)
  when Value >= ?RLP_ZERO andalso Value =< ?RLP_SHORT_PAYLOAD_BORDER ->
  Length = Value - ?RLP_ZERO,
  case extract_bytes(Length, Rest) of
    {ok, Bytes, Rest2} ->
      do_decode(Rest2, [Bytes | Acc]);
    {error, _} = E -> E
  end;

% string longer than 55 bytes
do_decode(<<Value:1/unsigned-big-integer-unit:8, Rest/binary>>, Acc)
  when Value > ?RLP_SHORT_PAYLOAD_BORDER andalso Value < ?RLP_SHORT_LIST_BORDER ->
  LengthOfLength = Value - ?RLP_SHORT_PAYLOAD_BORDER,
  case extract_bytes(LengthOfLength, Rest) of
    {ok, <<Length:LengthOfLength/big-unsigned-integer-unit:8>>, Rest2} ->
      case extract_bytes(Length, Rest2) of
        {ok, Bytes2, Rest3} ->
          do_decode(Rest3, [Bytes2 | Acc]);
        {error, _} = E -> E
      end;
    {error, _} = E -> E
  end;

% 0-55 bytes list
do_decode(<<Value:1/unsigned-big-integer-unit:8, Rest/binary>>, Acc)
  when Value >= ?RLP_SHORT_LIST_BORDER andalso Value < ?RLP_LONG_LIST_BORDER ->
  Length = Value - ?RLP_SHORT_LIST_BORDER,
  case extract_bytes(Length, Rest) of
    {ok, Bytes, Rest2} ->
      %TODO I don't really like this recursion
      % as it potentially can blow up the stack
      case do_decode(Bytes, []) of
        {ok, Decoded} ->
          do_decode(Rest2, [lists:reverse(Decoded) | Acc]);
        {error, _} = E -> E
      end;
    {error, _} = E -> E
  end;

do_decode(<<Value:1/unsigned-big-integer-unit:8, Rest/binary>>, Acc)
  when Value >= ?RLP_LONG_LIST_BORDER ->
  LengthOfLength = Value - ?RLP_LONG_LIST_BORDER,
  case extract_bytes(LengthOfLength, Rest) of
    {ok, <<Length:LengthOfLength/big-unsigned-integer-unit:8>>, Rest2} ->
      case extract_bytes(Length, Rest2) of
        {ok, Bytes2, Rest3} ->
          % TODO same as above
          case do_decode(Bytes2, []) of
            {ok, Decoded} ->
              do_decode(Rest3, [lists:reverse(Decoded) | Acc]);
            {error, _} = E -> E
          end;
        {error, _} = E -> E
      end;
    {error, _} = E -> E
  end;

do_decode(<<>>, Acc) ->
  {ok, Acc};

do_decode(Binary, Acc) ->
  io:format("Unexpected binary: ~p\n>>>~p\n", [Binary, Acc]),
  {error, <<"Invalid RLP">>}.

extract_bytes(Len, Binary) ->
  case Binary of
    <<Bytes:Len/binary, Rest/binary>> ->
      {ok, Bytes, Rest};
    _ ->
      {error, <<"Invalid RLP">>}
  end.
