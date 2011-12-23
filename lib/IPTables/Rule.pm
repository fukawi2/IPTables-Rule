package IPTables::Rule;

use 5.000000;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use IPTables::Rule ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';

###############################################################################
### PRECOMPILED REGEX
my $qr_fqdn	= qr/(([A-Z0-9]|[A-Z0-9][A-Z0-9\-]*[A-Z0-9])\.)*([A-Z]|[A-Z][A-Z0-9\-]*[A-Z0-9])/io;
my $qr_mac_addr	= qr/(([A-F0-9]{2}[:.-]?){6})/io;
my $qr_ip4_addr	= qr/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/o;
my $qr_ip4_cidr	= qr/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/([0-9]{1,2}))?/o;
my $qr_ip6_addr	= qr/s*((([0-9A-Fa-f]{1,4}:){7}(([0-9A-Fa-f]{1,4})|:))|(([0-9A-Fa-f]{1,4}:){6}(:|((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})|(:[0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:)(:[0-9A-Fa-f]{1,4}){0,4}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(:(:[0-9A-Fa-f]{1,4}){0,5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})))(%.+)?\s*/oi;	# holy batshit
my $qr_ip6_cidr	= qr/$qr_ip6_addr(\/[0-9]{1,3})?/io;

###############################################################################
### METHODS

sub new {
	my $self = {
		target	=> undef,
		ipver	=> 4,		# IPv4 by default
		src		=> undef,
		dst		=> undef,
		proto	=> undef,
		dpt		=> undef,
		spt		=> undef,
	};
	
	bless $self;
}

sub target {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		$self->{target} = $arg;
	}

	return $self->{target};
}

sub ipversion {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		# Valid arguments are 4 and 6
		return unless ( $arg =~ m/\A[46]\z/ );

		$self->{ipver} = $arg;
	}

	return $self->{ipver};
}

sub proto {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		return unless ( $arg =~ m/\A[a-z0-9]+\z/ );

		$self->{proto} = $arg;
	}

	return $self->{proto};
}

sub src {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		return unless ( &__is_valid_inet_host($arg) );

		$self->{src} = $arg;
	}

	return $self->{src};
}

sub dst {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		return unless ( &__is_valid_inet_host($arg) );

		$self->{dst} = $arg;
	}

	return $self->{dst};
}

sub dpt {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		return unless ( &__is_valid_inet_port($arg) );

		$self->{dpt} = $arg;
	}

	return $self->{dpt};
}

sub spt {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		return unless ( &__is_valid_inet_port($arg) );

		$self->{spt} = $arg;
	}

	return $self->{spt};
}

###############################################################################
### INTERNAL HELPERS
# These are subs that are NOT expected to be used outside this module itself.
# They are for internal code reuse only.
# All sub named should be prefixed with double underslash (__) to indicate they
# are internal use only.

sub __is_valid_inet_host() {
	my ( $arg ) = @_;
	chomp($arg);

	return unless ( $arg );

	# ipv4 address?
	if ( $arg =~ m/\A$qr_ip4_addr\z/ ) {
		return 1;
	}

	# ipv4 cidr?
	if ( $arg =~ m/\A$qr_ip4_cidr\z/ ) {
		# validate the cidr
		my ($host, $cidr) = split(/\//, $arg);
		return if ( $cidr < 0 );
		return if ( $cidr > 32 );

		return 1;
	}

	# ipv6 address?
	if ( $arg =~ m/\A$qr_ip6_addr\z/ ) {
		return 1;
	}

	# ipv6 cidr?
	if ( $arg =~ m/\A$qr_ip6_cidr\z/ ) {
		# validate the cidr
		my ($host, $cidr) = split(/\//, $arg);
		return if ( $cidr < 0 );
		return if ( $cidr > 128 );

		return 1;
		return 1;
	}

	# fqdn?
	if ( $arg =~ m/\A$qr_fqdn\z/ ) {
		return 1;
	}

	# fail by default
	return;
}

sub __is_valid_inet_port() {
	my ( $arg ) = @_;
	chomp($arg);

	return unless ( $arg );

	# just a numeric port?
	if ( &__is_a_number($arg) ) {
		return if ( $arg < 0 );
		return if ( $arg > 65535 );

		return 1;
	}

	# just a named port?
	if ( $arg =~ m/\A[a-z]+\z/i ) {
		return 1;
	}

	# numeric port range?
	if ( $arg =~ /\A\d+:\d+\z/ ) {
		my ( $lower, $upper) = split(/:/, $arg, 2);

		# recursive call to this sub to validate individal ports in multiport
		return unless ( &__is_valid_inet_port($lower) );
		return unless ( &__is_valid_inet_port($upper) );

		# lower is higher than upper?
		return if ( $upper < $lower );

		return 1;
	}

	# named port range?
	if ( $arg =~ /\A[a-z]+:[a-z]+\z/i ) {
		my ( $lower, $upper) = split(/:/, $arg, 2);

		# recursive call to this sub to validate individal ports in multiport
		return unless ( &__is_valid_inet_port($lower) );
		return unless ( &__is_valid_inet_port($upper) );

		return 1;
	}

	# numeric multiport?
	if ( $arg =~ /\A\d+(,\d+)+\z/ ) {
		my @ports = split(/,/, $arg);

		foreach my $port ( @ports ) {
			# recursive call to this sub to validate individal ports in multiport
			return unless ( &__is_valid_inet_port($port) );
		}

		return 1;
	}

	# named multiport?
	if ( $arg =~ /\A[a-z]+(,[a-z]+)+\z/i ) {
		my @ports = split(/,/, $arg);

		foreach my $port ( @ports ) {
			# recursive call to this sub to validate individal ports in multiport
			return unless ( &__is_valid_inet_port($port) );
		}

		return 1;
	}

	# fail by default
	return;
}

sub __is_a_number() {
	my ( $arg) = @_;
	return 1 if ( $arg =~ /\A-?\d+\z/);
	return;
}

1;
__END__

=head1 NAME

IPTables::Rule - Perl extension for holding iptables rule information in objects.

=head1 SYNOPSIS

  use IPTables::Rule;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for IPTables::Rule, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.


=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.23 with options

  -ACXn
	IPTables::Rule

=back



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Phillip Smith, E<lt>fukawi2@(none)E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Phillip Smith

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
