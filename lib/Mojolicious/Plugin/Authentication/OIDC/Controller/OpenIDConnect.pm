package Mojolicious::Plugin::Authentication::OIDC::Controller::Auth;
use v5.38;

use Mojo::Base 'Mojolicious::Controller';

use Crypt::JWT qw(decode_jwt);
use Mojo::Parameters;
use Mojo::UserAgent;
use Data::Printer;

sub make_app_url($self, $path = '/') {
  my $url = $self->tx->req->url->to_abs->clone;
  $url->fragment(undef);
  $url->query(Mojo::Parameters->new);
  $url->path($path);
}

sub redirect($self) {
  my $idp_url = Mojo::URL->new($self->_oidc_params->{auth_endpoint});
  $idp_url->query({
    client_id     => $self->_oidc_params->{client_id},
    scope         => $self->_oidc_params->{scope},
    response_type => $self->_oidc_params->{response_type},
    redirect_uri  => $self->make_app_url($self->_oidc_params->{login_path}),
  });
  $self->redirect_to($idp_url)
}

sub login($self) {
  my $code = $self->param('code');
  my $ua   = Mojo::UserAgent->new();
  my $url  = Mojo::URL->new($self->_oidc_params->{token_endpoint})
    ->userinfo(join(':', $self->_oidc_params->{client_id}, $self->_oidc_params->{client_secret}(1)));
    
  my $resp = $ua->post(
    $url => form => {
      grant_type   => $self->_oidc_params->{grant_type},
      code         => $code,
      redirect_uri => $self->make_app_url($self->_oidc_params->{login_path}),
    }
  );

  if($resp->res->json->{error}) {
    p $resp->res->json;
    return $self->render(openapi => $resp->res->json)
  } else {
    my $token = $resp->res->json->{access_token};
    my $data  = decode_jwt(token => $token, key => \$self->_oidc_params->{public_key});
    p $data;
    my $success = Mojo::URL->new($self->_oidc_params->{success_path});
    $success->query(token => $token);
    $self->redirect_to($success);
  }
}
