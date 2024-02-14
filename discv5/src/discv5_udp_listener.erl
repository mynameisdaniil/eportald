-module(discv5_udp_listener).

-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-define(SERVER, ?MODULE).

-record(state, {
          socket :: gen_udp:socket()
         }).

-type state() :: #state{}.

-define(MAX_SAFE_UDP_SIZE, 508).
-define(MIN_DISCV5_PACKET_SIZE, 63).

%% API
-export([
         start_link/2
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

start_link(Port, IP) ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, {Port, IP}, []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
-spec init({inet:port_number(), inet:ip_address()}) -> state().
init({Port, IP}) ->
  ?LOG_INFO("Starting UDP listener on ~p~n", [Port]),
  {ok, Socket} = gen_udp:open(Port, [binary, {ip, IP}, inet, {active, once}]),
  {ok, #state{socket = Socket}}.

handle_call(_Request, _From, State) ->
  Reply = {error, unexpected},
  {reply, Reply, State}.

handle_cast(_Msg, State) ->
  {noreply, State}.

handle_info({udp, _Socket, _IP, _InPort, Packet}, #state{socket = _} = State) ->
  ?LOG_DEBUG("Received: ~p~n", [Packet]),
  {noreply, State};

handle_info(Info, State) ->
  ?LOG_ERROR("Unexpected handle_info: ~p~n", [Info]),
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
