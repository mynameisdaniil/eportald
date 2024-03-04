%%%-------------------------------------------------------------------
%% @doc discv5 public API
%% @end
%%%-------------------------------------------------------------------

-module(enr_app).

-include_lib("kernel/include/logger.hrl").

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
  ?LOG_INFO("Starting enr application~n", []),
  enr_sup:start_link().

stop(_State) ->
  ok.

%% internal functions
