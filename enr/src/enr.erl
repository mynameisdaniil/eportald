-module(enr).

-export([
         reset_state/0,
         update/2,
         get_value/1,
         get_enr/0
        ]).

reset_state() ->
  gen_server:call(enr_maintainer, reset_state).

update(K, V) ->
  gen_server:call(enr_maintainer, {update, K, V}).

get_value(K) ->
  gen_server:call(enr_maintainer, {get, K}).

get_enr() ->
  gen_server:call(enr_maintainer, get_enr).
