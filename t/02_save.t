use strict;
use warnings;
use Test::More;
use HTTP::Cookies::Opera;

my $load_file = 't/cookies4.dat';
my $save_file = 't/cookies4_save.dat';

my $load_jar = HTTP::Cookies::Opera->new(file => $load_file);
$load_jar->save($save_file);

my $save_jar = HTTP::Cookies::Opera->new(file => $save_file);

# The cookie jars should be identical except for the different file names.
delete $_->{file} for ($load_jar, $save_jar);

is_deeply $save_jar, $load_jar, 'saved vs. loaded cookie_jar';

done_testing;

END { unlink $save_file }
