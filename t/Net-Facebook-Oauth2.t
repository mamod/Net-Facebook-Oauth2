use warnings;
use strict;
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-Facebook-Oauth2.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';
use Test::Exception;
use Test::MockObject;
use Test::MockModule;
use Test::More tests => 7;
BEGIN { use_ok('Net::Facebook::Oauth2') };

#########################
# Fixture Data
my $app_id       = 'testapp_id';
my $app_secret   = 'test_app_secret';
my $access_token = 'test_access_token';
my $url          = 'test.www.com';

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

my $class = 'Net::Facebook::Oauth2';

can_instantiate_class();
test_get_method_with_no_browser_parameter();
can_pass_browser_param();
can_do_delete_request();


sub can_instantiate_class {

    my $net_fb_oauth2 = $class->new(
        application_id     => $app_id,
        application_secret => $app_secret,
    );

    ok $net_fb_oauth2,
      'Can instantiate $class with application_id and application_secret';

    dies_ok { $class->new( application_id => $app_id ) }
     'Dies if no application_secret passed to constructor';

    dies_ok { $class->new( application_secret => $app_secret ) }
     'Dies if no application_id passed to constructor';
}

sub test_get_method_with_no_browser_parameter {

    # Test that browser attribute is LWP::UserAgent if no browser param passed

    my $test_json    = '{"data":"this is the get data"}';

    my $mock_get_response = _mock_object(
        {
            is_success => 1,
            content    => $test_json,
        }
    );

    # Mock LWP::UserAgent methods so can test offline
    my $mock_user_agent = _mock_object(
        {
            get => $mock_get_response,
        }
    );

    my $mock_user_agent_module = new Test::MockModule('LWP::UserAgent');
    $mock_user_agent_module->mock( 'new', sub {return $mock_user_agent;} );

    my $net_fb_oauth2 = $class->new(
        application_id     => $app_id,
        application_secret => $app_secret,
        access_token       => $access_token,
    );

    is $net_fb_oauth2->get( $url )->as_json, $test_json,
        'Passing no browser param will use LWP::UserAgent';
}

sub can_pass_browser_param {

    my $test_json    = '{"data":"this is the get data"}';

    my $mock_get_response = _mock_object(
        {
            is_success => 1,
            content    => $test_json,
        }
    );

    my $mock_browser = _mock_object( {
            get => $mock_get_response,
        }
    );

    my $net_fb_oauth2 = $class->new(
        application_id     => $app_id,
        application_secret => $app_secret,
        access_token       => $access_token,
        browser            => $mock_browser,
    );

    is $net_fb_oauth2->get( $url )->as_json, $test_json,
        'Can pass browser param';
}

sub can_do_delete_request {
    my $test_json    = '{"data":"this is the delete data"}';

    my $mock_delete_response = _mock_object(
        {
            is_success => 1,
            content    => $test_json,
        }
    );

    # Mock LWP::UserAgent methods so can test offline
    my $mock_user_agent = _mock_object(
        {
            delete => $mock_delete_response,
        }
    );

    my $mock_user_agent_module = new Test::MockModule('LWP::UserAgent');
    $mock_user_agent_module->mock( 'new', sub {return $mock_user_agent;} );

    my $net_fb_oauth2 = $class->new(
        application_id     => $app_id,
        application_secret => $app_secret,
        access_token       => $access_token,
    );

    is $net_fb_oauth2->delete( $url )->as_json, $test_json,
    'Delete request returns correct JSON';
}

sub _mock_object {
    my $mock_kv = shift;
    my $mock_object = Test::MockObject->new;
    while ( my($key, $value) = each %$mock_kv) {
        $mock_object->set_always($key, $value);
    }
    return $mock_object;
}
