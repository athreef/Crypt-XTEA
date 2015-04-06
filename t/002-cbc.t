use strict;
use warnings;
use utf8;

use Test::More;

use_ok( 'Crypt::XTEA' );

SKIP: {
    eval { require Crypt::CBC; };

    skip 'Crypt::CBC not installed' if $@;

    my @tests = (
        {
            key           => 'qwertyuiopasdfgh',
            plain         => 'The quick brown fox jumps over the lazy dog.',
            cipher_length => 64,
        },
        {
            key           => 'asdfghjklzxcvbnm',
            plain         => q{O brave new world, That has such people in't.},
            cipher_length => 64,
        }
    );

    for my $test (@tests) {
        my $xtea = new_ok( 'Crypt::XTEA' => [ $test->{key} ] );
        my $cbc = new_ok( 'Crypt::CBC' => [ -cipher => $xtea ] );

        my $cipher = $cbc->encrypt($test->{plain});
        is( length( $cipher ), $test->{cipher_length}, 'cbc encryption test' );
        my $plain = $cbc->decrypt( $cipher );
        is( $plain, $test->{plain}, 'cbc decryption test' );
    }
}

done_testing;
