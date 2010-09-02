-module(yaws_security_context).
-behavior(gen_server).

-include_lib("eunit/include/eunit.hrl").
-include_lib("yaws_security.hrl").

-export([
    start_link/0, init/1,
    handle_call/3, handle_cast/2, handle_info/2,
    terminate/2, code_change/3
]).

-record(state, {}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init(_Args) ->
    {ok, #state{}}.

handle_call(Request, _From, State) -> {stop, {unknown_call, Request}, State}.

handle_cast(_Message, State) -> {noreply, State}.

handle_info(_Info, State) -> {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) -> {ok, State}.
