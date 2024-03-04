-module(enr_maintainer).

-include_lib("kernel/include/logger.hrl").
-include_lib("enr.hrl").

-behaviour(gen_server).

-define(SERVER, ?MODULE).

-define(PRIVKEY_SIZE_BYTES, 32).

-record(state, {
          privkey :: binary(),
          pubkey :: binary(),
          seq :: non_neg_integer(),
          kv :: map()
         }).

-type state() :: #state{}.

%% API
-export([
         start_link/0
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

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

-spec init([]) -> state().
init([]) ->
  ?LOG_INFO("Starting enr maintainer"),
  Filename = application:get_env(enr, file, "./priv/enr_state"),
  State = try load_state(Filename) of
            LoadedState -> LoadedState
          catch
            _ ->
              EmptyState = default_state(),
              save_state(Filename, EmptyState),
              EmptyState
          end,
  {ok, State}.

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

save_state(Filename, State) ->
  Serialized = erlang:term_to_binary(State),
  file:write_file(Filename, Serialized).

default_state() ->
  PrivKey = crypto:strong_rand_bytes(?PRIVKEY_SIZE_BYTES),
  {ok, PubKey} = libsecp256k1:ec_pubkey_create(PrivKey, uncompressed),
  Seq = 0,
  #state{seq = Seq, privkey = PrivKey, pubkey = PubKey, kv = #{}}.

load_state(Filename) ->
  case file:read_file(Filename) of
    {ok, Serialized} ->
      erlang:binary_to_term(Serialized, [safe]);
    {error, _} = E -> E
  end.
