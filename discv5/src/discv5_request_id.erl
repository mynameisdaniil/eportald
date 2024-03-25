-module(discv5_request_id).

-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-define(SERVER, ?MODULE).

-record(state, {
          table :: ets:table()
         }).

-type state() :: #state{}.

%% API
-export([
         start_link/0,
         new_request/0,
         new_request/1,
         get_request/1,
         delete_request/1
        ]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

new_request() ->
  gen_server:call(?SERVER, new_empty_request).

new_request(Data) ->
  gen_server:call(?SERVER, {new_request, Data}).

get_request(RequestId) ->
  gen_server:call(?SERVER, {get_request, RequestId}).

delete_request(RequestId) ->
  gen_server:call(?SERVER, {delete_request, RequestId}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

-spec init([string()]) -> state().
init([]) ->
  ?LOG_INFO("Starting local ENR maintainer"),
  Table = ets:new(?MODULE, [named_table, public, set]),
  {ok, #state{table = Table}}.

handle_call(new_empty_request, _From, State) ->
  RequestId = erlang:monotonic_time(nanosecond),
  {reply, {ok, RequestId}, State};

handle_call({new_request, Data} = Request, From, #state{table = Table} = State) ->
  RequestId = erlang:monotonic_time(nanosecond),
  case ets:insert_new(Table, {RequestId, Data}) of
    true ->
      {reply, {ok, RequestId}, State};
    false ->
      % since we're using nanoseconds as a key it's unlikely to ever happen, let alone twice or more
      ?LOG_WARNING("Failed to insert new RequestID (~p), retrying...", [RequestId]),
      handle_call(Request, From, State)
  end;

handle_call({get_request, RequestId}, _From, #state{table = Table} = State) ->
  case ets:lookup(Table, RequestId) of
    [{RequestId, Data}] ->
      {reply, {ok, Data}, State};
    [] ->
      {reply, {error, not_found}, State}
  end;

handle_call({delete_request, RequestId}, _From, #state{table = Table} = State) ->
  ets:delete(Table, RequestId),
  {reply, ok, State};

handle_call(_Request, _From, State) ->
  Reply = {error, unexpected},
  {reply, Reply, State}.

handle_cast(_Msg, State) ->
  {noreply, State}.

handle_info(Info, State) ->
  ?LOG_ERROR("Unexpected handle_info: ~p", [Info]),
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
