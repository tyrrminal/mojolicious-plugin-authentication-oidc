package Mojolicious::Plugin::Authentication::OIDC;
use v5.26;
use warnings;

# ABSTRACT: OpenID Connect implementation integrated into Mojolicious

=encoding UTF-8

=head1 NAME

Mojolicious::Plugin::Authentication::OIDC - OpenID Connect implementation 
integrated into Mojolicious

=head1 SYNOPSIS

=head1 DESCRIPTION

Mojolicious plugin for L<OpenID Connect|https://openid.net/developers/how-connect-works/>
authentication.

=cut

use Mojo::Base 'Mojolicious::Plugin';

use Mojo::UserAgent;
use Readonly;

use experimental qw(signatures);

Readonly::Array my @REQUIRED_PARAMS => qw(
  client_secret
  well_known_url 
  public_key
);
Readonly::Array my @ALLOWED_PARAMS => qw(
  client_id on_login on_activity
);
Readonly::Hash  my %DEFAULT_PARAMS  => (
  login_path    => '/auth/login',
  redirect_path => '/auth',
  make_routes   => 1,

  on_success    => sub ($c, $token) { $c->session(token => $token); $c->redirect_to('/login/success') },
  on_error      => sub ($c, $error) { $c->render(json => $error) },

  get_token     => sub ($c)            { $c->session('token') },
  get_user      => sub ($token)        { $token },
  get_roles     => sub ($user, $token) { $user ? [] : undef },
);
Readonly::Hash my %DEFAULT_CONSTANTS => (
  scope         => 'openid',
  response_type => 'code',
  grant_type    => 'authorization_code',
);

=head1 METHODS

L<Mojolicious::Plugin::Authentication::OIDC> inherits all methods from
L<Mojolicious::Plugin> and imeplements the following new ones

=head2 register( \%params )

Register plugin in L<Mojolicious> application.

=cut

sub register($self, $app, $params) {
  # Parameter handling
  my %conf = (%DEFAULT_CONSTANTS, %DEFAULT_PARAMS, client_id => lc($app->moniker));
  $conf{$_} = $params->{$_} foreach (grep {exists($params->{$_})} ( keys(%DEFAULT_PARAMS), @REQUIRED_PARAMS, @ALLOWED_PARAMS ));
  # die if required/conditionally required params aren't found
  foreach (@REQUIRED_PARAMS) { die("Required param '$_' not found") unless(defined($conf{$_})) }
  die("Required param 'redirect_path' not found") if($conf{make_routes} && !defined($conf{redirect_path}));

  # wrap success handler so that we can call login handler before finishing the req
  my $success_handler = $conf{on_success};
  $conf{on_success} = sub($c, $token) {
    my $token_data = $c->_oidc_token($token);
    my $user = $conf{get_user}->($c, $token_data);
    $conf{on_login}->($c, $user) if($conf{on_login});
    return $success_handler->($c, $token);
  };

  # Add our controller to the namespace for calling via routes or, e.g., OpenAPI
  push($app->routes->namespaces->@*, 'Mojolicious::Plugin::Authentication::OIDC::Controller');

  # Fetch actual endpoints from well-known URL
  my $resp = Mojo::UserAgent->new()->get($conf{well_known_url});
  die("Unable to determine OIDC endpoints (" . $resp->res->error->{message}.")\n") if($resp->res->is_error);
  @conf{qw(auth_endpoint token_endpoint)} = @{$resp->res->json}{qw(authorization_endpoint token_endpoint)};

  # internal helper for stored parameters (only to be used by OpenIDConnect controller)
  $app->helper(
    _oidc_params => sub {
      return {map { $_ => $conf{$_} } qw(auth_endpoint scope response_type login_path token_endpoint client_id client_secret grant_type on_error on_success)}
    }
  );

  # internal helper for decoded auth token. Pass the token in, or it'll be retrieved
  # via `get_token` handler
  $app->helper(
    _oidc_token => sub($c, $token = undef) {
      return decode_jwt(token => ($token // $conf{get_token}->($c)), key => \$conf{public_key});
    }
  );

  # public helper to access current user and OIDC roles
  $app->helper(
    current_user => sub($c) {
      return $conf{get_user}->($c->_oidc_token)
    }
  );
  $app->helper(
    current_user_roles => sub($c) {
      my ($user, $token);
      try {
        $token = $c->_oidc_token;
        $user = $c->current_user; 
      } catch($e) { return undef } 
      return $conf{get_roles}->($user, $token);
    }
  );

  # if `on_activity` handler exists, call it from a before_dispatch hook
  $app->hook(before_dispatch => sub($c) { my $u; try { $u = $c->current_user; } catch($e) {} $conf{on_activity}->($c, $u) if($u) }) if($conf{on_activity});
  # if `make_routes` is true, register our controller actions at the appropriate paths
  # otherwise, it's up to the downstream code to do this, e.g., via OpenAPI spec
  if($conf{make_routes}) {
    $app->routes->get($conf{redirect_path})->to("OpenIDConnect#redirect");
    $app->routes->get($conf{login_path})->to('OpenIDConnect#login');
  }
}

=head1 AUTHOR

Mark Tyrrell C<< <mark@tyrrminal.dev> >>

=head1 LICENSE

Copyright (c) 2024 Mark Tyrrell

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

=cut

1;

__END__
