use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::Facebook::Oauth2',
    VERSION_FROM      => 'lib/Net/Facebook/Oauth2.pm', # finds $VERSION
    PREREQ_PM         => {
        
        LWP::UserAgent => 0,
        URI::Escape => 0,
        JSON::Any => 0
        
    },
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Net/Facebook/Oauth2.pm', # retrieve abstract from module
       AUTHOR         => 'Mahmoud A. Mehyar <mamod.mehyar@gmail.com>') : ()),
);
