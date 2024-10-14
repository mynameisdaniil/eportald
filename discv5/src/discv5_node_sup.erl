-module(discv5_node_sup).

-behaviour(supervisor).

-export([start_link/0]).

-export([init/1]).

-define(SERVER, ?MODULE).

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

init([]) ->
    SupFlags = #{strategy => simple_one_for_one,
                 intensity => 0,
                 period => 1},
    ChildSpecs = [
                  #{id       => discv5_node
                  , start    => {discv5_node, start_link, []}
                  , restart  => transient
                  , shutdown => 5000
                  , type     => worker
                  , modules  => [discv5_node]
                   }
                 ],
    {ok, {SupFlags, ChildSpecs}}.
