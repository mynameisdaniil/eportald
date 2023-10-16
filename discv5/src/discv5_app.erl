%%%-------------------------------------------------------------------
%% @doc discv5 public API
%% @end
%%%-------------------------------------------------------------------

-module(discv5_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
  sync:go(),
  discv5_sup:start_link().

stop(_State) ->
  ok.

%% internal functions
