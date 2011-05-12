-module(yaws_security_saml).


-include("yaws.hrl").
-include("yaws_api.hrl").

-include("yaws_security.hrl").

-export([init/0, create_filter/2, register_provider/0]).

-record(saml_token, {type=undefined, timeout=undefined, session=undefined}).
-record(session, {orig_url, principal=undefined}).

-record(state, {default_authorities, records}).
-record(post, {response = undefined, relay=undefined}).

-record(filteroptions, {login_redirect = "/saml/login"}).

init() ->
    create_filter(saml, []).

parse_options([{login_redirect, Redirect} | T], Options) ->
    parse_options(T, Options#filteroptions{login_redirect = Redirect});
parse_options([Option | T], Options) ->
    throw({invalid_option, Option});
parse_options([], Options) ->
    Options.

create_filter(Name, RawOptions) ->
    Options = parse_options(RawOptions, #filteroptions{}),
    ok = yaws_security:register_filterchain(
	   Name,
	   [{function, fun(Arg, Ctx) -> saml_filter(Arg, Ctx, Options) end}],
	   []
	  ).

saml_filter(Arg, Ctx, Options) ->
    Req = Arg#arg.req,
    Sock = Arg#arg.clisock,
    Url = yaws_api:request_url(Arg),
    io:fwrite("saml_filter: Incoming: ~p~n", [Url#url.path]),
    Token = yaws_security_context:token_get(Ctx),
    saml_filter(Token, Sock, Req#http_request.method,
		  string:tokens(Url#url.path, "/"), Arg, Ctx, Options).

%% https login redirect.
saml_filter(_, {sslsocket, _, _}, 'GET', ["login"], Arg, Ctx, Options) ->
    	{ok, Cookie, Session} = yaws_security_util:get_session("saml.login", Arg),
	U = esaml:auth_request(Session#session.principal),
	{redirect, U};


%% http login attempt, redirect to https
saml_filter(_, _ ,'GET', ["login"], Arg, Ctx, _) ->
	io:fwrite("saml_filter/redirect~n"),
	yaws_api:redirect(#filteroptions.login_redirect);

saml_filter({ok, _}, _, _, _, Arg, Ctx, _) ->
io:fwrite("saml_filter/6-2~n"),
    yaws_security_filterchain:next(Arg, Ctx);    

saml_filter(null, _, 'POST', ["saml", "sso", "post"], Arg, Ctx, _) ->
    io:fwrite("saml_filter/post~n"),
    R = yaws_api:parse_post(Arg),
    {ok, Cookie, Session} = yaws_security_util:get_session("saml.login", Arg),
    {ok, Timeout, SessionTimeStamp} = esaml:parse_validate_response(R, Session#session.principal),
    SamlToken = #saml_token{timeout=Timeout, session=SessionTimeStamp},
    Token = #token{type=saml,
		   principal=Session#session.principal,
		   extra=SamlToken},
    ok = yaws_security_context:token_set(Ctx, Token),
    yaws_api:delete_cookie_session(Cookie),
    yaws_api:redirect(Session#session.orig_url);

saml_filter(null, _, 'GET', _Request, Arg, Ctx, Options) ->
    io:fwrite("saml_filter/GET - trying next~n"),
    try yaws_security_filterchain:next(Arg, Ctx)
    catch
	throw:unauthorized ->
	    Url = yaws_api:request_url(Arg),
	    Session = #session{orig_url = Url#url.path, principal = esaml:generate_principal()},
	    Cookie = yaws_api:new_cookie_session(Session),
	    [yaws_api:redirect(Options#filteroptions.login_redirect),
	     yaws_api:setcookie("saml.login", Cookie)]
    end;

saml_filter(null, _, _Cmd, _Request, Arg, Ctx, Options) -> % catchall
    io:fwrite("saml_filter/catchall~n"),
    yaws_security_filterchain:next(Arg, Ctx).

saml_authenticate(Token) ->
	SamlToken = Token#token.extra,
    	case esaml:authenticate(SamlToken#saml_token.timeout,
			SamlToken#saml_token.session) of
		true ->
		     {ok, Token#token{authenticated=true}};
		Error ->
		     {error, Error}
	end.

register_provider() ->
    yaws_security:register_provider(
      [saml],
      fun(Token) -> saml_authenticate(Token) end
     ).

invalidoption_test() ->

    try create_filter(bad_filter, [foo]) of
	_ ->
	    throw(unexpected_success)
    catch
	throw:{invalid_option, foo} ->
	    ok
    end.
