-module(enr_maintainer).

-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-define(SERVER, ?MODULE).

-define(PRIVKEY_SIZE_BYTES, 32).

-record(enr_data, {
          privkey :: binary(),
          pubkey :: binary(),
          seq :: non_neg_integer(),
          kv :: map()
         }).

-type enr_data() :: #enr_data{}.

-record(state, {
          enr_data :: enr_data(),
          filename :: string()
         }).

-type state() :: #state{}.

%% API
-export([
         start_link/1,
         reset_state/0,
         update/2,
         get_value/1,
         get_enr/0
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

start_link(Filename) ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [Filename], []).

reset_state() ->
  gen_server:call(?SERVER, reset_state).

update(K, V) ->
  gen_server:call(?SERVER, {update, K, V}).

get_value(K) ->
  gen_server:call(?SERVER, {get_value, K}).

get_enr() ->
  gen_server:call(?SERVER, get_enr).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

-spec init([string()]) -> state().
init([Filename]) ->
  ?LOG_INFO("Starting enr maintainer"),
  case load_enr_data(Filename) of
    {ok, EnrData} ->
      {ok, #state{enr_data = EnrData, filename = Filename}};
    {error, _} ->
      EnrData = default_enr_data(),
      save_enr_data(Filename, EnrData),
      {ok, #state{enr_data = EnrData, filename = Filename}}
  end.

handle_call(reset_state, _From, State) ->
  EnrData = default_enr_data(),
  {reply, ok, State#state{enr_data = EnrData}};

handle_call({update, K, V},
            _From,
            #state{enr_data = EnrData, filename = Filename} = State) ->
  #enr_data{kv = KV, seq = Seq} = EnrData,
  NewKV = maps:put(K, V, KV),
  Enr1 = EnrData#enr_data{kv = NewKV, seq = Seq + 1},
  save_enr_data(Filename, Enr1),
  {reply, ok, State#state{enr_data = Enr1}};

handle_call({get_value, K},
            _From,
            #state{enr_data = #enr_data{kv = KV}} = State) ->
  {reply, maps:get(K, KV, undefined), State};
handle_call(get_enr,
            _From,
            #state{enr_data = #enr_data{seq = Seq, privkey = PrivKey, kv = KV}} = State) ->
  Enr = enr_codec:encode(Seq, KV, PrivKey),
  {reply, Enr, State};

handle_call(get_state, _From, State) ->
  {reply, State, State};

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

save_enr_data(Filename, EnrData) ->
  Serialized = erlang:term_to_binary(EnrData),
  Result = file:write_file(Filename, Serialized),
  Result.

default_enr_data() ->
  PrivKey = crypto:strong_rand_bytes(?PRIVKEY_SIZE_BYTES),
  {ok, PubKey} = libsecp256k1:ec_pubkey_create(PrivKey, uncompressed),
  Seq = 0,
  #enr_data{seq = Seq, privkey = PrivKey, pubkey = PubKey, kv = #{}}.

load_enr_data(Filename) ->
  case file:read_file(Filename) of
    {ok, Serialized} ->
      EnrData = erlang:binary_to_term(Serialized, [safe]),
      #enr_data{privkey = PrivKey, pubkey = PubKey} = EnrData,
      case verify_keys(PrivKey, PubKey) of
        true -> {ok, EnrData};
        false -> {error, <<"Public and private keys are inconsistent with each other.">>}
      end;
    {error, _} = E -> E
  end.

verify_keys(PrivKey, PubKey) ->
  {ok, DerivedPubKey} = libsecp256k1:ec_pubkey_create(PrivKey, uncompressed),
  PubKey == DerivedPubKey.
