-module(esaml).

-include("yaws.hrl").
-include("yaws_api.hrl").
-include("esaml.hrl").
-include_lib("public_key/include/public_key.hrl"). 

-export([init/0, 
	auth_request/1, 
	parse_validate_response/2, 
	timestamp/0,
	generate_principal/0,
	authenticate/2
]).

-record(post_data, {response = undefined, relay = undefined}).
-record(response_data, {id=undefined, recipient=undefined, status_code=undefined, onorafter=undefined, signature=undefined, session_timestamp=undefined, session_index=undefined}).

-define(REDIRECT_XPATH, "//*[local-name()='SingleSignOnService'][@Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"]").
-define(ID_XPATH,       "@entityID").
-define(CONSUMER_XPATH, "//*[local-name() = 'AssertionConsumerService'][@index=\"0\"]").
-define(SUBJECT_XPATH,  "//*[local-name() = 'SubjectConfirmationData']").
-define(AUTH_XPATH,     "//*[local-name() = 'AuthnStatement']").

init() ->
	ok.

%% Parse the Response and RelayState from the saml authnResponse
parse_post([{"SAMLResponse", Data} | T], Post) ->
	parse_post(T, Post#post_data{response = Data});
parse_post([{"RelayState", Data} | T], Post) ->
	parse_post(T, Post#post_data{relay = Data});
parse_post([], Post) ->
Post.

%% Parse XML attributes from the auth response
parse_attrs([{_, _,"Value", Data} | T], State) ->
	N = string:rstr(Data, ":"),
      	D = string:substr(Data, N+1),
	parse_attrs(T, State#response_data{status_code = D});
parse_attrs([{_, _,"NotOnOrAfter", Data} | T], Params) ->
        parse_attrs(T, Params#response_data{onorafter = Data});
parse_attrs([{_, _, "Recipient", Data} | T], Params) ->
        parse_attrs(T, Params#response_data{recipient = Data});
parse_attrs([{_, _, "InResponseTo", Data} | T], Params) ->
        parse_attrs(T, Params#response_data{id = Data});
parse_attrs([{_, _, "SessionNotOnOrAfter", Data} | T], Params) ->
        parse_attrs(T, Params#response_data{session_timestamp = Data});
parse_attrs([_ | T], Params) ->
        parse_attrs(T, Params);
parse_attrs([], Params) ->
Params.


saml_response_parser({startElement, _, "StatusCode", _, Attr}, Location, Params) ->
        parse_attrs(Attr, Params);
saml_response_parser({startElement, _, "AuthnStatement", _, Attr}, Location, Params) ->
        parse_attrs(Attr, Params);
saml_response_parser({startElement, _, "SubjectConfirmationData", _, Attr}, Location, Params) ->
        parse_attrs(Attr, Params);
saml_response_parser(_, Location, Params) ->
        Params.

saml_get_idp_metadata() ->
	xmerl_scan:file(?IDP_XML).

saml_get_sp_metadata() ->
	xmerl_scan:file(?SP_XML).

saml_redirect_url() ->
	{Result, _} = saml_get_idp_metadata(),
	[{_,_,_,_,_,_,_,[_,{_,_,_,_,_,_,_,_,Out,_}],_,_,_,_}] = xmerl_xpath:string(?REDIRECT_XPATH, Result),
	Out.

saml_consumer_service() ->
	{Result, _} = saml_get_sp_metadata(),
	[{_,_,_,_,_,_,_,[_,_,_,{_,_,_,_,_,_,_,_,Out,_}],_,_,_,_}] = xmerl_xpath:string(?CONSUMER_XPATH, Result),
	Out.

saml_issuer() ->
	{Result, _} = saml_get_sp_metadata(),
	[{_,_,_,_,_,_,_,_,Out,_}] = xmerl_xpath:string(?ID_XPATH, Result),
	Out.

saml_key_from_mime(K) ->
	H = base64:mime_decode(K),
	OtpCert = public_key:pkix_decode_cert(H, otp),
	TBSCert = OtpCert#'OTPCertificate'.tbsCertificate,
	PublicKeyInfo = TBSCert#'OTPTBSCertificate'.subjectPublicKeyInfo,
	PublicKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey.


saml_get_metadata_key(XPath) ->
	{Result, _} = saml_get_idp_metadata(),
	[{_,_,_,_,K,_}] = xmerl_xpath:string(XPath, Result),
	K.

saml_timestamp() ->
       %% Generate a timestamp in UTC from the current time.
       {{Year, Month, Day}, {Hour, Min, Sec}} = calendar:universal_time(),
       integer_to_list(Year) ++ "-" ++ 
       lists:flatten(io_lib:format("~2.2.0w", [Month])) ++ "-" ++ 
       lists:flatten(io_lib:format("~2.2.0w", [Day])) ++ "T" ++ 
       lists:flatten(io_lib:format("~2.2.0w", [Hour])) ++ ":" ++ 
       lists:flatten(io_lib:format("~2.2.0w", [Min])) ++ ":" ++
       lists:flatten(io_lib:format("~2.2.0w", [Sec])) ++ "Z".

saml_deflate(Request) ->
       Z = zlib:open(),
       ok = zlib:deflateInit(Z, default, deflated, -15, 8, default),
       [Data] = zlib:deflate(Z, Request, finish),
       ok = zlib:deflateEnd(Z),
       ok = zlib:close(Z),
       base64:encode_to_string(Data).

saml_auth_request(Principal) ->
       Ts = saml_timestamp(),
       I = saml_issuer(),
       "<samlp:AuthnRequest" 
               ++ " xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
               ++ " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\""
               ++ " ID=\"" ++ Principal ++ "\""
               ++ " Version=\"2.0\""
               ++ " IssueInstant=" ++ "\"" ++ Ts ++ "\""
               ++ " AssertionConsumerServiceIndex=\"0\">"
               ++ " <saml:Issuer>" ++ I ++ "</saml:Issuer>"
               ++ " <samlp:NameIDPolicy AllowCreate=\"true\""
               ++ " Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\"/>"
               ++ " </samlp:AuthnRequest>".



%% XXX Verify the key in the cert against what we have in the metadata
saml_verify_key(R, Params) ->
	true.


%% XXX
saml_verify_signature([], Params) ->
	ok;
saml_verify_signature(R, Params) ->
	true = saml_verify_key(R, Params),
	ok.


%% Verifies that the given timestamp is >= now
%% NULL timestamps mean valid for infinity
saml_verify_timestamp([]) ->
	true;
saml_verify_timestamp(Ts) ->
	T = saml_timestamp(),
	Ts >= T.

%% Extract all the fields we will need.  Note that if the response was unsolicited, we will 
%% (correctly) generate an exception.
saml_parse_response(Response, Params) ->
	H =  fun(E, L, S) -> saml_response_parser(E, L, S) end,
	Options = [{event_state, Params}, {event_fun, H}],
	{ok, P, _} = xmerl_sax_parser:stream(Response, Options),
	P.

saml_validate_response(Response, Principal, Params) ->
	ok = saml_verify_signature(Response, Params), 

	%% Verify recipient, which is the URL for the consumer service
	true = Params#response_data.recipient =:= saml_consumer_service(),

	%% Verify the NotOnOrAfter timestamp.
	true = saml_verify_timestamp(Params#response_data.onorafter),

	%% Verify InResponseTo
	true = Principal =:= Params#response_data.id,

	ok.

%% --- Exports ---------

auth_request(Principal) ->
	R = saml_auth_request(Principal),
	D = saml_deflate(R),
	E = yaws_api:url_encode(D),
	saml_redirect_url() ++ "?SAMLRequest=" ++ E.

%% Generate exceptions for invalid or unsolicited responses.
parse_validate_response(Response, Principal) ->
	P = parse_post(Response, #post_data{}),
	R = base64:decode_to_string(P#post_data.response),
	Params = saml_parse_response(R, #response_data{}),
	ok = saml_validate_response(Response, Principal, Params),
	TimeStamp = Params#response_data.onorafter,
	SessionTimeStamp = Params#response_data.session_timestamp,
	{ok, TimeStamp, SessionTimeStamp}.

timestamp() ->
	saml_timestamp().

%% XXX should be a UID or something...
generate_principal() ->
	"deadBeef".

authenticate(TimeStamp, undefined) -> 
	T = saml_timestamp(),
	TimeStamp > T;
authenticate(TimeStamp, SessionTimeStamp) ->
	T = saml_timestamp(),
	TimeStamp > T andalso SessionTimeStamp > T.
