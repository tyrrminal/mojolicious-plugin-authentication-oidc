package Mojolicious::Plugin::Authentication::OIDC::Controller::OpenIDConnect;
use v5.26;

use Mojo::Base 'Mojolicious::Controller';

use Mojo::Parameters;
use Mojo::UserAgent;
use Syntax::Keyword::Try;

use experimental qw(signatures);

my sub make_app_url($self, $path = '/') {
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
    redirect_uri  => make_app_url($self, $self->_oidc_params->{login_path}),
  });
  $self->redirect_to($idp_url)
}

sub login($self) {
  my $code = $self->param('code');
  my $ua   = Mojo::UserAgent->new();
  my $url  = Mojo::URL->new($self->_oidc_params->{token_endpoint})
    ->userinfo(join(':', $self->_oidc_params->{client_id}, $self->_oidc_params->{client_secret}));
    
  my $resp = $ua->post(
    $url => form => {
      grant_type   => $self->_oidc_params->{grant_type},
      code         => $code,
      redirect_uri => make_app_url($self, $self->_oidc_params->{login_path}),
    }
  );

  if($resp->res->json->{error}) {
    return $self->_oidc_params->{on_error}->($self, $resp->res->json);
  } else {
    try {
      my $token = $resp->res->json->{access_token};
      # Decode the token; if it fails, because the key is wrong, or the token
      # is invalid or has been re-encrypted, then we throw it away and call
      # error handler
      $self->_oidc_token($token);
      return $self->_oidc_params->{on_success}->($self, $token);
    } catch($e) {
      $self->log->error($e);
      $self->_oidc_params->{on_error}->($self, $resp->res->json);
    }
  }
}

