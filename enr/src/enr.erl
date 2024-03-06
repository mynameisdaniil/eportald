-module(enr).

-export([
         reset_state/0,
         update_kv/2,
         get_enr/0
        ]).

reset_state() ->
  gen_server:call(enr_maintainer, reset_state).

update_kv(K, V) ->
  gen_server:call(enr_maintainer, {update_kv, K, V}).

get_enr() ->
  gen_server:call(enr_maintainer, get_enr).
