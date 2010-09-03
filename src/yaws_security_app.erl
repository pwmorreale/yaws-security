% @private
-module(yaws_security_app).
-behavior(application).
-export([start/2, stop/1]).

start(_Type, _StartArgs) ->
    yaws_security_sup:start_link().

stop(_State) -> ok.
