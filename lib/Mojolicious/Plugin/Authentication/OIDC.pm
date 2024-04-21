package Mojolicious::Plugin::Authentication::OIDC;
use v5.26;
use warnings;

# ABSTRACT: OpenID Connect implementation integrated into Mojolicious

use Mojo::Base 'Mojolicious::Plugin';

use experimental qw(signatures);

sub register($self, $app, $conf) {
  $conf = ref($conf) eq 'HashRef' ? $conf : {};
  my %conf = @{$conf}[qw(
    client_id client_secret scope response_type auth_endpoint token_endpoint grant_type public_key
    oidc_redirect_path oidc_login_path oidc_success_path
  )];

  push($app->routes->namespaces->@*, 'Mojolicious::Plugin::Authentication::OIDC::Controller');

  $app->helper(
    _oidc_params => sub {
      return {%conf}
    }
  );

  if($conf->{install_routes}) {
    $app->routes->get($conf->{oidc_redirect_path})->to("Auth#oidc_redirect");
    $app->routes->get($conf->{oidc_login_path})->to('Auth#oidc_login');
  }
}

1;
