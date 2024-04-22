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
  well_known_url public_key
  login_path success_path
);
Readonly::Hash  my %DEFAULT_PARAMS  => (
  scope         => 'openid',
  response_type => 'code',
  grant_type    => 'authentication_code',
  make_routes   => 1,
);
#params with runtime defaults: client_id
#conditionally optional params: redirect_path

=head1 METHODS

L<Mojolicious::Plugin::Authentication::OIDC> inherits all methods from
L<Mojolicious::Plugin> and imeplements the following new ones

=head2 register( \%params )

Register plugin in L<Mojolicious> application.

=cut

sub register($self, $app, $params) {
  my %conf = (
    %DEFAULT_PARAMS,
    client_id => lc($app->moniker)
  );
  $params = ref($params) eq 'HashRef' ? $params : {};
  foreach (@REQUIRED_PARAMS) {
    die("Param '$_' is required") unless(exists($params->{$_}));
    $conf{$_} = $params->{$_};
  }
  die("Param 'redirect_path' is required when 'make_routes' is enabled") if($conf{make_routes} && !exists($params->{redirect_path}));

  my $ua = Mojo::UserAgent->new();
  my $resp = $ua->get($conf{well_known_url});
  $conf{auth_endpoint} = $resp->res->json->{authorization_endpoint};
  $conf{token_endpoint} = $resp->res->json->{token_endpoint};

  $app->helper(
    _oidc_params => sub {
      return {%conf}
    }
  );

  push($app->routes->namespaces->@*, 'Mojolicious::Plugin::Authentication::OIDC::Controller');
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
