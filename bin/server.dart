import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_auth/shelf_auth.dart';
import 'package:shelf_cors/shelf_cors.dart' as cors;
import 'package:shelf_exception_handler/shelf_exception_handler.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'package:uuid/uuid.dart';
import 'package:logging/logging.dart';
import 'package:shelf_route/shelf_route.dart';

final corsHeaders = {
  'Access-Control-Allow-Origin': "*",
  'Access-Control-Allow-Methods': "POST, GET, OPTIONS, DELETE, HEAD",
  'Access-Control-Allow-Headers': "Origin, X-Requested-With, Content-Type, Accept, Authorization"
};

/**
 * This example has a login route where username and password are POSTed
 * and other routes which are authenticated via the JWT session established
 * via the login route
 *
 * To try this example start the server then do
 *
 *     curl -i -X POST 'http://localhost:8080/login' -d 'username=fred&password=blah' -H 'content-type: application/x-www-form-urlencoded'
 *
 * You should see a response like
 *
 *     HTTP/1.1 200 OK
 *      date: Fri, 06 Feb 2015 23:45:39 GMT
 *      transfer-encoding: chunked
 *      authorization: ShelfAuthJwtSession eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjMyNjYzMzksImV4cCI6MTQyMzI2ODEzOSwiaXNzIjoic3VwZXIgYXBwIiwic3ViIjoiZnJlZCIsImF1ZCI6bnVsbCwidHNlIjoxNDIzMzUyNzM5fQ.Og4r1DnW6nOm1Ms5Vr9qiSePbL43Xt0DUVj3KwJT_38
 *      x-frame-options: SAMEORIGIN
 *      content-type: text/plain; charset=utf-8
 *      x-xss-protection: 1; mode=block
 *      x-content-type-options: nosniff
 *      server: dart:io with Shelf
 *
 * copy the authorization line and use in the following curl
 *
 *     curl -i  'http://localhost:8080/authenticated/foo' -H 'content-type: application/json' -H 'authorization: ShelfAuthJwtSession eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjMyNjYzMzksImV4cCI6MTQyMzI2ODEzOSwiaXNzIjoic3VwZXIgYXBwIiwic3ViIjoiZnJlZCIsImF1ZCI6bnVsbCwidHNlIjoxNDIzMzUyNzM5fQ.Og4r1DnW6nOm1Ms5Vr9qiSePbL43Xt0DUVj3KwJT_38'
 *
 * You should see a response like
 *
 *     HTTP/1.1 200 OK
 *     date: Fri, 06 Feb 2015 23:57:51 GMT
 *     transfer-encoding: chunked
 *     authorization: ShelfAuthJwtSession eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjMyNjcwNzEsImV4cCI6MTQyMzI2ODg3MSwiaXNzIjoic3VwZXIgYXBwIiwic3ViIjoiZnJlZCIsImF1ZCI6bnVsbCwidHNlIjoxNDIzMzUyNzM5fQ.0DtXFz4S0cg8aKRtc_ieAhzubfco3ioK1Uh7efEc26Y
 *     x-frame-options: SAMEORIGIN
 *     content-type: text/plain; charset=utf-8
 *     x-xss-protection: 1; mode=block
 *     x-content-type-options: nosniff
 *     server: dart:io with Shelf
 *
 *     Doing foo as fred
 *
 */
void main() {
  Logger.root.level = Level.FINER;
  Logger.root.onRecord.listen((lr) {
    print('${lr.time} ${lr.level} ${lr.message}');
  });

  var testLookup = new TestUserLookup();

  // use Jwt based sessions. Create the secret using a UUID
  var sessionHandler = new JwtSessionHandler(
      'super app', new Uuid().v4(), testLookup.lookupByUsername);

  // allow http for testing with curl. Don't use in production
  // i.e. in addition to https, allow non-https too
  var allowHttp = true;

  // authentication middleware for a login handler (e.g. submitted from a form)
  var loginMiddleware = authenticate(
      [new UsernamePasswordAuthenticator(testLookup.lookupByUsernamePassword)],
      sessionHandler: sessionHandler,
      allowHttp: allowHttp,
      allowAnonymousAccess: false);

  // authentication middleware for routes other than login that require a logged
  // in user. Here we are relying
  // solely on users with a session established via the /login route but
  // could have additional authenticators here.
  // We are disabling anonymous access to these routes
  var defaultAuthMiddleware = authenticate([],
      sessionHandler: sessionHandler,
      allowHttp: true,
      allowAnonymousAccess: false);

  var rootRouter = router();

  // the route where the login form credentials are posted
  rootRouter.post(
      '/login',
          (Request request) => new Response.ok(
          "I'm now logged in as ${loggedInUsername(request)}\n"),
      middleware: loginMiddleware);

  // the routes which require an authenticated user
  rootRouter.child('/authenticated', middleware: defaultAuthMiddleware)
    ..get(
        '/foo',
            (Request request) =>
        new Response.ok("Doing foo as ${loggedInUsername(request)}\n"));

  printRoutes(rootRouter);

  var handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(exceptionHandler())
      .addMiddleware(cors.createCorsHeadersMiddleware(corsHeaders: corsHeaders))
      .addHandler(rootRouter.handler);

  io.serve(handler, 'localhost', 8080).then((server) {
    print('Serving at http://${server.address.host}:${server.port}');
  });
}

String loggedInUsername(Request request) => getAuthenticatedContext(request)
    .map((ac) => ac.principal.name)
    .getOrElse(() => 'guest');

class TestUserLookup {
  Future<Option<Principal>> lookupByUsernamePassword(
      String username, String password) {
    final validUser = username == 'fred';

    final Option<Principal> principalOpt =
    validUser ? new Some(new Principal(username)) : const None();

    return new Future.value(principalOpt);
  }

  Future<Option<Principal>> lookupByUsername(String username) {
    final validUser = username == 'fred';

    final Option<Principal> principalOpt =
    validUser ? new Some(new Principal(username)) : const None();

    return new Future.value(principalOpt);
  }
}