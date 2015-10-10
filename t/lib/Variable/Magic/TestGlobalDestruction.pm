package Variable::Magic::TestGlobalDestruction;

use strict;
use warnings;

# Silence possible 'used only once' warnings from Test::Builder
our $TODO;
local $TODO;

sub _diag {
 require Test::More;
 Test::More::diag(@_);
}

sub import {
 shift;
 my %args  = @_;
 my $level = $args{level} || 1;

 my $env_level = int($ENV{PERL_DESTRUCT_LEVEL} || 0);
 if ($env_level >= $level) {
  my $is_debugging = do {
   local $@;
   eval {
    require Config;
    grep /-DDEBUGGING\b/, @Config::Config{qw<ccflags cppflags optimize>};
   }
  };
  require Test::More;
  if ($is_debugging) {
   _diag("Global destruction level $env_level set by PERL_DESTRUCT_LEVEL (debugging perl)");
   return;
  } else {
   _diag("PERL_DESTRUCT_LEVEL is set to $env_level, but this perl doesn't seem to have debugging enabled");
  }
 }

 my $has_perl_destruct_level = do {
  local $@;
  eval {
   require Perl::Destruct::Level;
   Perl::Destruct::Level->import(level => $level);
   1;
  }
 };
 if ($has_perl_destruct_level) {
  _diag("Global destruction level $level set by Perl::Destruct::Level");
  return;
 }
}

1;
