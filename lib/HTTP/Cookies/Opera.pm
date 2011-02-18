package HTTP::Cookies::Opera;

use strict;
use warnings;

use parent qw(HTTP::Cookies);
use Carp qw(carp croak);

our $VERSION = '0.02';
$VERSION = eval $VERSION;

use constant DEBUG    => 1;
use constant TAG_LEN  => 1;
use constant LEN_LEN  => 2;

sub load {
    my ($self, $file) = @_;
    $file ||= $self->{file} or return;

    open my $fh, '<', $file or die "$file: $!";
    binmode $fh;
    12 == read($fh, my $header, 12) or croak 'bad file header';
    my ($file_ver, $app_ver, $tag_len, $len_len) = unpack 'NNnn', $header;

    croak 'unexpected file format'
        unless 1 == $file_ver >> 12 and 2 == $app_ver >> 12
            and TAG_LEN == $tag_len and LEN_LEN == $len_len;

    my $now = time;
    my (@domain_components, @path_components, %cookie);

    while (TAG_LEN == read $fh, my $tag, TAG_LEN) {
        $tag = unpack 'C', $tag;
        DEBUG and printf "tag: %#x\n", $tag;

        # End of domain component.
        if (0x84 == $tag) {
            pop @domain_components;
        }
        # End of path component.
        elsif (0x85 == $tag) {
            pop @path_components;

            # Add last constructed cookie as this path will have no more.
            $self->_add_cookie(\%cookie);
        }
        elsif (0x99 == $tag) { $cookie{secure} = 1 }
        elsif (0x3 == $tag) {
            # Add previous cookie now that it is fully constructed.
            $self->_add_cookie(\%cookie);

            # Reset cookie for new record.
            %cookie = (
                domain => join('.', reverse @domain_components),
                path   => '/' . join('/', @path_components),
            );
        }

        # Record is a flag and contains no payload.
        next if 0x80 & $tag;

        LEN_LEN == read $fh, my $len, LEN_LEN or croak 'bad file';

        # Tags have unique ids among top-level domain/path/cookie records as
        # well as the payload records, so simplify parsing by treating the
        # payload records as top-level records during the next iteration.
        next if 0x3 >= $tag;

        $len = unpack 'n', $len;
        DEBUG and printf "  len: %d\n", $len;
        $len == read $fh, my $payload, $len or croak 'bad file';

        if    (0x1e == $tag) { push @domain_components, $payload }
        elsif (0x1d == $tag) { push @path_components, $payload }
        elsif (0x10 == $tag) { $cookie{key} = $payload }
        elsif (0x11 == $tag) { $cookie{val} = $payload }
        elsif (0x12 == $tag) {
            # Time is stored in 8 bytes for Opera >=10, 4 bytes for <10.
            $payload = unpack 8 == $len ? 'x[N]N' : 'N', $payload;
            $cookie{maxage} = $payload - $now;
        }
        elsif (0x1a == $tag) {
            # Version- not yet seen.
        }

        DEBUG and printf "  payload: %s\n", $payload;
    }

    close $fh;

    return 1;
}

sub _add_cookie {
    my ($self, $cookie) = @_;
    return unless exists $cookie->{key};
    $self->set_cookie(
        undef, @$cookie{qw(key val path domain)}, undef, undef,
        @$cookie{qw(secure maxage)}, undef, undef
    );
}

sub save {
    carp 'save method is not yet implemented';
    return;

    my ($self, $file) = @_;
    $file ||= $self->{file} or return;

    open my $fh, '>', $file or die "$file: $!";
    binmode $fh;

    $self->scan(sub {
        # ...
    });

    close $fh;

    return 1;
}


1;

__END__

=head1 NAME

HTTP::Cookies::Opera - Cookie storage and management for Opera

=head1 SYNOPSIS

    use HTTP::Cookies::Opera;
    $cookie_jar = HTTP::Cookies::Opera->new(file => $file);

=head1 DESCRIPTION

The C<HTTP::Cookies::Opera> module is a subclass of C<HTTP::Cookies> that
can C<load()> Opera cookie files.

=head1 SEE ALSO

L<HTTP::Cookies>

L<http://waybackmachine.org/http://www.opera.com/docs/fileformats/>

=head1 TODO

Implement C<save()>.

=head1 REQUESTS AND BUGS

Please report any bugs or feature requests to
L<http://rt.cpan.org/Public/Bug/Report.html?Queue=HTTP-Cookies-Opera>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc HTTP::Cookies::Opera

You can also look for information at:

=over

=item * GitHub Source Repository

L<http://github.com/gray/http-cookies-opera>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/HTTP-Cookies-Opera>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/HTTP-Cookies-Opera>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/Public/Dist/Display.html?Name=HTTP-Cookies-Opera>

=item * Search CPAN

L<http://search.cpan.org/dist/HTTP-Cookies-Opera/>

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 gray <gray at cpan.org>, all rights reserved.

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 AUTHOR

gray, <gray at cpan.org>

=cut
