-module(enr_maintainer_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("src/enr.hrl").

default_state_test() ->
  % SETUP
  Filename = ?cmd("mktemp --dry-run"),
  {ok, Pid} = enr_maintainer:start_link(Filename),

  %TEST
  {ok, Enr} = enr_maintainer:get_enr(),
  {ok, DecodedEnr} = enr:decode(Enr),
  #enr_v4{seq = Seq} = DecodedEnr,

  ?assertEqual(0, Seq),

  %TEARDOWN
  gen_server:stop(Pid),
  wait_for_exit(Pid),
  file:delete(Filename).

enr_seq_increase_test() ->
  % SETUP
  Filename = ?cmd("mktemp --dry-run"),
  {ok, Pid} = enr_maintainer:start_link(Filename),

  %TEST
  {ok, Enr} = enr_maintainer:get_enr(),
  {ok, DecodedEnr} = enr:decode(Enr),
  #enr_v4{seq = Seq} = DecodedEnr,

  ?assertEqual(0, Seq),

  enr_maintainer:update_kv(<<"ip">>, <<"127.0.0.1">>),

  {ok, Enr1} = enr_maintainer:get_enr(),
  {ok, DecodedEnr1} = enr:decode(Enr1),
  #enr_v4{seq = Seq1} = DecodedEnr1,

  ?assertEqual(1, Seq1),

  %TEARDOWN
  gen_server:stop(Pid),
  wait_for_exit(Pid),
  file:delete(Filename).


enr_reload_test() ->
  % SETUP
  Filename = ?cmd("mktemp --dry-run"),
  {ok, Pid} = enr_maintainer:start_link(Filename),

  %TEST
  enr_maintainer:update_kv(<<"ip">>, <<"127.0.0.1">>),

  {ok, Enr} = enr_maintainer:get_enr(),
  {ok, DecodedEnr} = enr:decode(Enr),
  #enr_v4{seq = Seq} = DecodedEnr,

  ?assertEqual(1, Seq),

  gen_server:stop(Pid),
  wait_for_exit(Pid),
  {ok, Pid1} = enr_maintainer:start_link(Filename),

  {ok, Enr1} = enr_maintainer:get_enr(),
  {ok, DecodedEnr1} = enr:decode(Enr1),
  #enr_v4{seq = Seq1, kv = KV} = DecodedEnr1,
  IP = maps:get(<<"ip">>, KV),

  ?assertEqual(1, Seq1),
  ?assertEqual(<<"127.0.0.1">>, IP),

  %TEARDOWN
  gen_server:stop(Pid1),
  wait_for_exit(Pid1),
  file:delete(Filename).

%% Helpers
wait_for_exit(Pid) ->
    MRef = erlang:monitor(process, Pid),
    receive {'DOWN', MRef, _, _, _} -> ok end.
