package Net::Facebook::Oauth2;

use strict;
use warnings;
use LWP::UserAgent;
use URI;
use URI::Escape;
use JSON::MaybeXS;
use Carp;

use constant ACCESS_TOKEN_URL => 'https://graph.facebook.com/oauth/access_token';
use constant AUTHORIZE_URL => 'https://www.facebook.com/dialog/oauth';

our $VERSION = '0.08';

sub new {
    my ($class,%options) = @_;
    my $self = {};
    $self->{options} = \%options;

    if (!$options{access_token}){
        croak "You must provide your application id in new()\nNet::Facebook::Oauth2->new( application_id => '...' )" unless defined $self->{options}->{application_id};
        croak "You must provide your application secret in new()\nNet::Facebook::Oauth2->new( application_secret => '...' )" unless defined $self->{options}->{application_secret};
    }

    $self->{browser}          = $options{browser} || LWP::UserAgent->new;
    $self->{access_token_url} = $options{access_token_url} || ACCESS_TOKEN_URL;
    $self->{authorize_url}    = $options{authorize_url} || AUTHORIZE_URL;
    $self->{access_token}     = $options{access_token};
    $self->{display}          = $options{display} || 'page'; ##other values popup and wab

    return bless($self, $class);
}

sub get_authorization_url {
    my ($self,%params) = @_;

    $params{callback} ||= $self->{options}->{callback};
    croak "You must pass a callback parameter with Oauth v2.0" unless defined $params{callback};

    $params{display} = $self->{display} unless defined $params{display};
    $self->{options}->{callback} = $params{callback};

    my $scope = join(",", @{$params{scope}}) if defined($params{scope});

    my $url = $self->{authorize_url}
    ."?client_id="
    .uri_escape($self->{options}->{application_id})
    ."&redirect_uri="
    .uri_escape($params{callback});

    $url .= "&scope=$scope" if $scope;
    $url .= "&display=".$params{display};

    return $url;
}


sub get_access_token {
    my ($self,%params) = @_;
    $params{callback} ||= $self->{options}->{callback};
    $params{code} ||= $self->{options}->{code};

    croak "You must pass a code parameter with Oauth v2.0" unless defined $params{code};
    croak "You must pass callback URL" unless defined $params{callback};
    $self->{options}->{code} = $params{code};

    ###generating access token URL
    my $getURL = $self->{access_token_url}
    ."?client_id="
    .uri_escape($self->{options}->{application_id})
    ."&redirect_uri="
    .uri_escape($params{callback})
    ."&client_secret="
    .uri_escape($self->{options}->{application_secret})
    ."&code=$params{code}";

    my $response = $self->{browser}->get($getURL);

    ##got an error response from facebook
    ##die and display error message
    if (!$response->is_success){
        my $error = decode_json($response->content());
        croak "'" .$error->{error}->{type}. "'" . " " .$error->{error}->{message};
    }

    ##everything is ok proccess response and extract access token
    my $file = $response->content();
    my ($access_token,$expires) = split(/&/, $file);
    my ($string,$token) = split(/=/, $access_token);

    ###save access token
    if ($token){
        $self->{access_token} = $token;
        return $token;
    }

    croak "can't get access token";
}

sub get {
    my ($self,$url,$params) = @_;
    unless ($self->_has_access_token($url)) {
        croak "You must pass access_token" unless defined $self->{access_token};
        $url .= $self->{_has_query} ? '&' : '?';
        $url .= "access_token=" . $self->{access_token};
    }

    ##construct the new url
    my @array;

    while ( my ($key, $value) = each(%{$params})){
        $value = uri_escape($value);
        push(@array, "$key=$value");
    }

    my $string = join('&', @array);
    $url .= "&".$string if $string;

    my $response = $self->{browser}->get($url);
    my $content = $response->content();
    return $self->_content($content);
}

sub post {
    my ($self,$url,$params) = @_;
    unless ($self->_has_access_token($url)) {
        croak "You must pass access_token" unless defined $self->{access_token};
        $params->{access_token} = $self->{access_token};
    }
    my $response = $self->{browser}->post($url,$params);
    my $content = $response->content();
    return $self->_content($content);
}

sub delete {
    my ($self,$url,$params) = @_;
    unless ($self->_has_access_token($url)) {
        croak "You must pass access_token" unless defined $self->{access_token};
        $params->{access_token} = $self->{access_token};
    }
    my $response = $self->{browser}->delete($url,$params);
    my $content = $response->content();
    return $self->_content($content);
}

sub as_hash {
    my ($self) = @_;
    return decode_json($self->{content});
}

sub as_json {
    my ($self) = @_;
    return $self->{content};
}

sub _content {
    my ($self,$content) = @_;
    $self->{content} = $content;
    return $self;
}

sub _has_access_token {
    my ($self, $url) = @_;
    my $uri = URI->new($url);
    my %q = $uri->query_form;
    #also check if we have a query and save result
    $self->{_has_query} = $uri->query();
    if (grep { $_ eq 'access_token' } keys %q) {
        return 1;
    }
    return;
}

1;
__END__
=head1 NAME

Net::Facebook::Oauth2 - a simple Perl wrapper around Facebook OAuth v2.0 protocol

=head1 SYNOPSIS

Somewhere in your application's login process:

    use Net::Facebook::Oauth2;

    my $fb = Net::Facebook::Oauth2->new(
        application_id     => 'your_application_id', 
        application_secret => 'your_application_secret',
        callback           => 'http://yourdomain.com/facebook/callback'
    );

    # get the authorization URL for your application
    my $url = $fb->get_authorization_url(
        scope   => [ 'public_profile', 'email', 'offline_access', 'publish_stream' ],
        display => 'page'
    );

Now redirect the user to this C<$url>.

Once the user authorizes your application, Facebook will send him/her back
to your application, on the C<callback> link provided above.

Inside that callback route, use the verifier code parameter that Facebook
sends to get the access token:

    # param() below is a bogus function. Use whatever your web framework
    # provides (e.g. $c->req->param('code'), $cgi->param('code'), etc)
    my $code = param('code');

    my $access_token = $fb->get_access_token(code => $code);

If you got so far, your user is logged! Save this access token in your
database or session.

Later on you can use it to communicate with Facebook on behalf of this user:

    my $fb = Net::Facebook::Oauth2->new(
        access_token => $access_token
    );

    my $info = $fb->get(
        'https://graph.facebook.com/v2.2/me'   # Facebook API URL
    );

    print $info->as_json;

=head1 DESCRIPTION

Net::Facebook::Oauth2 gives you a way to simply access FaceBook Oauth 2.0 protocol

For more information please see example folder shipped with this Module

=head1 SEE ALSO

For more information about Facebook Oauth 2.0 API

Please Check
L<http://developers.facebook.com/docs/>

get/post Facebook Graph API
L<http://developers.facebook.com/docs/api>

=head1 USAGE

=head2 C<Net::Facebook::Oauth-E<gt>new( %args )>

Pass args as hash. C<%args> are:

=over 4

=item * C<application_id >

Your application id as you get from facebook developers platform
when you register your application

=item * C<application_secret>

Your application secret id as you get from facebook developers platform
when you register your application

=back

=head2 C<$fb-E<gt>get_authorization_url( %args )>

Return an Authorization URL for your application, once you receive this
URL redirect user there in order to authorize your application

=over 4

=item * C<scope>

['offline_access','publish_stream',...]

Array of Extended permissions as described by facebook Oauth2.0 API
you can get more information about scope/Extended Permission from

L<http://developers.facebook.com/docs/authentication/permissions>

Please note that requesting information other than C<public_profile>,
C<email> and C<user_friends> B<will require your app to be reviewed by Facebook!>

=item * C<callback>

callback URL, where facebook will send users after they authorize
your application

=item * C<display>

How to display Facebook Authorization page

=over 4

=item * C<page>

This will display facebook authorization page as full page

=item * C<popup>

This option is useful if you want to popup authorization page
as this option tell facebook to reduce the size of the authorization page

=item * C<wab>

From the name, for wab and mobile applications this option is the best
facebook authorization page will fit there :)

=back

=back

=head2 C<$fb-E<gt>get_access_token( %args )>

Returns access_token string
One arg to pass

=over 4

=item * C<code>

This is the verifier code that facebook send back to your
callback URL once user authorize your app, you need to capture
this code and pass to this method in order to get access_token

Verifier code will be presented with your callback URL as code
parameter as the following

http://your-call-back-url.com?code=234er7y6fdgjdssgfsd...

When access token is returned you need to save it in a secure
place in order to use it later in your application

=back

=head2 C<$fb-E<gt>get( $url,$args )>

Send get request to facebook and returns response back from facebook

=over 4

=item * C<url>

Facebook Graph API URL as string

=item * C<$args>

hashref of parameters to be sent with graph API URL if required

=back

The response returned can be formatted as the following

=over 4

=item * C<$responseE<gt>as_json>

Returns response as json object

=item * C<$responseE<gt>as_hash>

Returns response as perl hashref

=back

For more information about facebook grapg API, please check
http://developers.facebook.com/docs/api

=head2 C<$fb-E<gt>post( $url,$args )>

Send post request to facebook API, usually to post something

=over 4

=item * C<url>

Facebook Graph API URL as string

=item * C<$args>

hashref of parameters to be sent with graph API URL

=back

For more information about facebook grapg API, please check
L<http://developers.facebook.com/docs/api>

=head1 AUTHOR

Mahmoud A. Mehyar, E<lt>mamod.mehyar@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012-2015 by Mahmoud A. Mehyar

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
