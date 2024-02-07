%%%-------------------------------------------------------------------
%% @doc discv5 public API
%% @end
%%%-------------------------------------------------------------------

-module(discv5_app).

-include_lib("kernel/include/logger.hrl").

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
  ?LOG_INFO("Starting discv5 application~n", []),
  sync:go(),
  discv5_sup:start_link().

stop(_State) ->
  ok.

%% internal functions
