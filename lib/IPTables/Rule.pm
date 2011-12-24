package IPTables::Rule;

use 5.000000;
use strict;
use warnings;

our $VERSION = '0.01';

###############################################################################
### PRECOMPILED REGEX
my $qr_fqdn	= qr/(([A-Z0-9]|[A-Z0-9][A-Z0-9\-]*[A-Z0-9])\.)*([A-Z]|[A-Z][A-Z0-9\-]*[A-Z0-9])/io;
my $qr_mac_addr	= qr/(([A-F0-9]{2}[:.-]?){6})/io;

my $qr_ip4_addr = qr/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/o;
my $qr_ip6_addr;
{
	# This block courtesy of Regexp::IPv6 0.03 by Salvador Fandiño
	# http://search.cpan.org/~salva/Regexp-IPv6/
	# http://cpansearch.perl.org/src/SALVA/Regexp-IPv6-0.03/lib/Regexp/IPv6.pm
	my $IPv4 = "((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))";
	my $G = "[0-9a-fA-F]{1,4}";
	my @tail = ( ":",
		"(:($G)?|$IPv4)",
		":($IPv4|$G(:$G)?|)",
		"(:$IPv4|:$G(:$IPv4|(:$G){0,2})|:)",
		"((:$G){0,2}(:$IPv4|(:$G){1,2})|:)",
		"((:$G){0,3}(:$IPv4|(:$G){1,2})|:)",
		"((:$G){0,4}(:$IPv4|(:$G){1,2})|:)" );
	my $IPv6_re = $G;
	$IPv6_re = "$G:($IPv6_re|$_)" for @tail;
	$IPv6_re = qq/:(:$G){0,5}((:$G){1,2}|:$IPv4)|$IPv6_re/;
	$IPv6_re =~ s/\(/(?:/g;
	$qr_ip6_addr = qr/$IPv6_re/;
}
# and the CIDR versions of the above
my $qr_ip4_cidr	= qr/$qr_ip4_addr\/[0-9]{1,2}/o;
my $qr_ip6_cidr	= qr/$qr_ip6_addr\/[0-9]{1,3}/io;

###############################################################################
### METHODS

sub new {
	my $self = {
		iptbinary	=> 'iptables',
		iptaction	=> '-A',
		ipver		=> 4,		# IPv4 by default
		table		=> undef,
		chain		=> undef,
		target		=> undef,
		in			=> undef,
		out			=> undef,
		src			=> undef,
		dst			=> undef,
		proto		=> undef,
		dpt			=> undef,
		spt			=> undef,
		mac			=> undef,
		state		=> undef,
		comment		=> undef,
		logprefix	=> undef,
	};
	
	bless $self;
}

sub errstr() {
	my $self = shift;
	return $self->{errstr};
}

sub iptbinary() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		unless ( $arg =~ m|\A/.+\z| ) {
			&__errstr($self, 'invalid path: '.$arg);
			return;
		}
		$self->{iptbinary} = $arg;
	}

	return $self->{iptbinary};
}

sub iptaction() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		unless ( $arg =~ m/\A-[ADIRLSFZNXPE]\z/ ) {
			&__errstr($self, 'invalid action: '.$arg);
			return;
		}
		$self->{iptaction} = $arg;
	}

	return $self->{iptaction};
}

sub ipversion() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		# Valid arguments are 4 and 6
		unless ( $arg =~ m/\A[46]\z/ ) {
			&__errstr($self, 'invalid ip version: '.$arg);
			return;
		}

		$self->{ipver} = $arg;
	}

	return $self->{ipver};
}

sub table() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		my $need_to_barf;
		$need_to_barf = 1 if ( $self->{ipver} == '4' and $arg !~ m/\A(filter|nat|mangle|raw)\z/i );
		$need_to_barf = 1 if ( $self->{ipver} == '6' and $arg !~ m/\A(filter|mangle|raw)\z/i );
		if ( $need_to_barf ) {
			&__errstr($self, sprintf('invalid table "%s" for ip version: %s', $arg, $self->{ipver}));
			return;
		}

		$self->{table} = $arg;
	}

	return $self->{table};
}

sub chain() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		$self->{chain} = $arg;
	}

	return $self->{chain};
}

sub target() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		$self->{target} = $arg;
	}

	return $self->{target};
}

*protocol = \&proto;
sub proto() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		unless ( $arg =~ m/\A[a-z0-9]+\z/ ) {
			&__errstr($self, 'invalid protocol: '.$arg);
			return;
		}

		$self->{proto} = $arg;
	}

	return $self->{proto};
}

sub in() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		$self->{in} = $arg;
	}

	return $self->{in};
}

sub out() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		$self->{out} = $arg;
	}

	return $self->{out};
}

*source = \&src;
sub src() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		unless (
			&__is_valid_inet_host($arg) or
			&__is_valid_inet_cidr($arg) or
			&__is_valid_inet_range($arg)
		) {
			&__errstr($self, 'invalid source address: '.$arg);
			return;
		}

		$self->{src} = $arg;
	}

	return $self->{src};
}

*dest = \&dst;
*destination = \&dst;
sub dst() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		unless (
			&__is_valid_inet_host($arg) or
			&__is_valid_inet_cidr($arg) or
			&__is_valid_inet_range($arg)
		) {
			&__errstr($self, 'invalid destination address: '.$arg);
			return;
		}

		$self->{dst} = $arg;
	}

	return $self->{dst};
}

*port = \&dpt;
*dport = \&dpt;
sub dpt() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		unless ( &__is_valid_inet_port($arg) ) {
			&__errstr($self, 'invalid destination port: '.$arg);
			return;
		}

		$self->{dpt} = $arg;
	}

	return $self->{dpt};
}

*sport = \&spt;
sub spt() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		unless ( &__is_valid_inet_port($arg) ) {
			&__errstr($self, 'invalid source port: '.$arg);
			return;
		}

		$self->{spt} = $arg;
	}

	return $self->{spt};
}

sub mac() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		unless ( &__is_valid_mac_address($arg) ) {
			&__errstr($self, 'invalid mac address: '.$arg);
			return;
		}

		$self->{mac} = $arg;
	}

	return $self->{mac};
}

sub state() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		unless ( $arg =~ m/\A(NEW|ESTABLISHED|RELATED|INVALID|UNTRACKED)\z/i ) {
			&__errstr($self, 'invalid connection tracking state: '.$arg);
			return;
		}
		$self->{state} = $arg;
	}

	return $self->{state};
}

*rate_limit = \&limit;
sub limit() {
	my $self = shift;
	my ($arg) = @_;

	if ( $arg ) {
		# --limit rate[/second|/minute|/hour|/day]
		unless ( $arg =~ m/\A\d+\/(s(ec(ond)?)?|m(in(ute)?)?|h(our)?|d(ay)?)\z/i ) {
			&__errstr($self, 'invalid rate limit: '.$arg);
			return;
		}
		$self->{limit} = $arg;
	}

	return $self->{limit};
}

sub logprefix() {
	my $self = shift;
	my ($arg) = @_;

	my $max_length = 29;

	if ( $arg ) {
		if ( length($arg) > $max_length ) {
			&__errstr($self, 'log prefix too long (>'.$max_length.'): '.$arg);
			return;
		}
		if ( $arg =~ m/[\"\']/ ) {
			&__errstr($self, 'quotes not permitted: '.$arg);
			return;
		}

		$self->{logprefix} = $arg;
	}

	return $self->{logprefix};
}

sub comment() {
	my $self = shift;
	my ($arg) = @_;

	my $max_length = 256;

	if ( $arg ) {
		if ( length($arg) > $max_length ) {
			&__errstr($self, 'comment too long (>'.$max_length.'): '.$arg);
			return;
		}
		if ( $arg =~ m/[\"\']/ ) {
			&__errstr($self, 'quotes not permitted: '.$arg);
			return;
		}

		$self->{comment} = $arg;
	}

	return $self->{comment};
}

*compile = \&generate;
sub generate() {
	my $self = shift;

	# what is required?
	unless ( $self->{chain} ) {
		&__errstr($self, 'Chain must be specified');
		return;
	}
	# ports are only valid with protocol tcp and udp
	if ( defined($self->{spt}) and $self->{proto} !~ m/\A(tcp|udp)\z/i ) {
		&__errstr($self, 'Protocol must be TCP or UDP when specifying source port');
		return;
	}
	if ( defined($self->{dpt}) and $self->{proto} !~ m/\A(tcp|udp)\z/i ) {
		&__errstr($self, 'Protocol must be TCP or UDP when specifying destinatipn port');
		return;
	}
	# cant use 'logprefix' unless the target is 'log'
	if ( defined($self->{logprefix}) and $self->{target} !~ m/\Alog\z/i ) {
		&__errstr($self, 'Target must be LOG when specifying log prefix');
		return;
	}

	my $rule_prefix;
	my $rule_criteria;

	$rule_prefix = $self->{iptbinary};
	$rule_prefix .= ' -t '.$self->{table}
		if ( defined($self->{'table'}) );
	$rule_prefix .= ' '.$self->{iptaction};
	$rule_prefix .= ' '.$self->{chain};
	
	if ( defined($self->{src}) ) {
		if ( &__is_valid_inet_host($self->{src}) or &is_valid_inet_cidr($self->{src}) ) {
			$rule_criteria .= sprintf(' -s %s', $self->{src});
		}
		if ( &__is_valid_inet_range($self->{src}) ) {
			$rule_criteria .= sprintf(' -m iprange --src-range %s',	$self->{'src'});
		}
	}
	if ( defined($self->{dst}) ) {
		if ( &__is_valid_inet_host($self->{dst}) or &is_valid_inet_cidr($self->{dst}) ) {
			$rule_criteria .= sprintf(' -d %s', $self->{dst});
		}
		if ( &__is_valid_inet_range($self->{dst}) ) {
			$rule_criteria .= sprintf(' -m iprange --dst-range %s',	$self->{'dst'});
		}
	}
	
	$rule_criteria .= sprintf(' -i %s', $self->{in})	if ( defined($self->{in}) );
	$rule_criteria .= sprintf(' -o %s', $self->{out})	if ( defined($self->{out}) );
	$rule_criteria .= sprintf(' -p %s', $self->{proto})	if ( defined($self->{proto}) );

	if ( defined($self->{spt}) ) {
		if ( $self->{spt} =~ m/\A\w+\z/ ) {
			# just a single port
			$rule_criteria .= sprintf(' --sport %s', $self->{'spt'});
		}
		if ( $self->{spt} =~ m/\A\w+(:\w+)+\z/ ) {
			# port range
			$rule_criteria .= sprintf(' --sport %s', $self->{'spt'});
		}
		if ( $self->{spt} =~ m/\A\w+(:\w+)+\z/ ) {
			# multiport
			$rule_criteria .= sprintf(' -m multiport --sports %s', $self->{'spt'});
		}
	}
	if ( defined($self->{dpt}) ) {
		if ( $self->{dpt} =~ m/\A\w+\z/ ) {
			# just a single port
			$rule_criteria .= sprintf(' --dport %s', $self->{'dpt'});
		}
		if ( $self->{dpt} =~ m/\A\w+(:\w+)+\z/ ) {
			# port range
			$rule_criteria .= sprintf(' --dport %s', $self->{'dpt'});
		}
		if ( $self->{dpt} =~ m/\A\w+(:\w+)+\z/ ) {
			# multiport
			$rule_criteria .= sprintf(' -m multiport --dports %s', $self->{'dpt'});
		}
	}

	$rule_criteria .= sprintf(' -m mac --mac-source %s',	$self->{mac})		if ( defined($self->{mac}) );
	$rule_criteria .= sprintf(' -m conntrack --ctstate %s', $self->{state})		if ( defined($self->{state}) );
	$rule_criteria .= sprintf(' -m comment --comment "%s"', $self->{comment})	if ( defined($self->{comment}) );
	$rule_criteria .= sprintf(' -m limit --limit %s',		$self->{limit})		if ( defined($self->{limit}) );

	$rule_criteria .= sprintf(' -j %s', $self->{'target'})	if ( defined($self->{'target'}) );

	$rule_criteria .= sprintf(' --log-prefix "[%s] "',	$self->{logprefix})	if ( defined($self->{logprefix}) );

#	$ipt_rule .= sprintf(' -m statistic %s',			$criteria{'statistic'})	if (defined($criteria{'statistic'}));
#	$ipt_rule .= sprintf(' -m time %s',					$criteria{'time'})		if (defined($criteria{'time'}));

	my $full_cmd = $rule_prefix.$rule_criteria;
	return $full_cmd;
}

###############################################################################
### INTERNAL HELPERS
# These are subs that are NOT expected to be used outside this module itself.
# They are for internal code reuse only.
# All sub named should be prefixed with double underslash (__) to indicate they
# are internal use only.

sub __is_valid_mac_address() {
	my ( $arg ) = @_;
	chomp($arg);

	return unless ( $arg );

	if ( $arg =~ m/\A$qr_mac_addr\z/ ) {
		return 1;
	}

	# fail by default
	return;
}

sub __is_valid_inet_host() {
	my ( $arg ) = @_;
	chomp($arg);

	return unless ( $arg );

	# ipv4 address?
	return 1 if ( &__is_inet4_host($arg) );

	# ipv6 address?
	return 1 if ( &__is_inet6_host($arg) );

	# fqdn?
	return 1 if ( $arg =~ m/\A$qr_fqdn\z/ );

	# fail by default
	return;
}

sub __is_inet4_host() {
	my ( $arg ) = @_;
	chomp($arg);

	return unless ( $arg );

	# ipv4 address?
	return 1 if ( $arg =~ m/\A$qr_ip4_addr\z/ );

	# fail by default
	return;
}

sub __is_inet6_host() {
	my ( $arg ) = @_;
	chomp($arg);

	return unless ( $arg );

	# ipv6 address?
	return 1 if ( $arg =~ m/\A$qr_ip6_addr\z/ );

	# fail by default
	return;
}

sub __is_valid_inet_cidr() {
	my ( $arg ) = @_;
	chomp($arg);

	return unless ( $arg );

	# ipv4 cidr?
	return 1 if ( &__is_inet4_cidr($arg) );

	# ipv6 cidr?
	return 1 if ( &__is_inet6_cidr($arg) );

	# fail by default
	return;
}

sub __is_inet4_cidr() {
	my ( $arg ) = @_;
	chomp($arg);

	return unless ( $arg );

	# ipv4 cidr?
	if ( $arg =~ m/\A$qr_ip4_cidr\z/ ) {
		# validate the cidr
		my ($host, $cidr) = split(/\//, $arg);
		return if ( $cidr < 0 );
		return if ( $cidr > 32 );

		return 1;
	}

	# fail by default
	return;
}

sub __is_inet6_cidr() {
	my ( $arg ) = @_;
	chomp($arg);

	return unless ( $arg );

	# ipv6 cidr?
	if ( $arg =~ m/\A$qr_ip6_cidr\z/ ) {
		# validate the cidr
		my ($host, $cidr) = split(/\//, $arg);
		return if ( $cidr < 0 );
		return if ( $cidr > 128 );

		return 1;
	}

	# fail by default
	return;
}

sub __is_valid_inet_range() {
	my ( $arg ) = @_;
	chomp($arg);

	return unless ( $arg );

	# ipv4 address range?
	return 1 if ( &__is_inet4_range($arg) );

	# ipv6 address range?
	return 1 if ( &__is_inet6_range($arg) );

	# fail by default
	return;
}

sub __is_inet4_range() {
	my ( $arg ) = @_;
	chomp($arg);

	return unless ( $arg );

	# ipv4 address range?
	return 1 if (
		$arg =~ m/\A$qr_ip4_addr\-$qr_ip4_addr\z/
	);

	# fail by default
	return;
}

sub __is_inet6_range() {
	my ( $arg ) = @_;
	chomp($arg);

	return unless ( $arg );

	# ipv6 address range?
	return 1 if (
		$arg =~ m/\A$qr_ip6_addr\-$qr_ip6_addr\z/
	);

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

sub __errstr() {
	my $self = shift;
	my $errstr = shift;
	$self->{errstr} = $errstr;
	return 1;
}

1;
__END__

=head1 NAME

IPTables::Rule - Perl extension for holding iptables rule information in objects.

=head1 SYNOPSIS

  use IPTables::Rule;

  my $ipt_rule = new IPTables::Rule ;
  $ipt_rule->chain('INPUT');
  $ipt_rule->source('192.168.0.0/24');
  $ipt_rule->protocol('tcp');
  $ipt_rule->dport('22');
  $ipt_rule->target('ACCEPT');
  $ipt_rule->comment('accept ssh from lan');
  print $ipt_rule->generate;

=head1 DESCRIPTION

This package provides a way to build/store iptables rules in objects. It deals
with ONLY individual rules; no attention it given to the overall structure of
the ruleset (see L<IPTables::IPv4> or L<IPTables::IPv6> for that).

Once all your criteria has been set, you can call the C<generate> method to
convert the set criteria into an iptables command line string.

=head2 METHODS

Methods return a value for success, or undef for failure. Errors are availabe
using the C<errstr> method:

  $ipt_rule->chain('INPUT') or print $ipt_rule->errstr;

=head3 new

Create a new object to hold a rule.

=head3 iptbinary

blah blah blah

=head3 iptaction

blah blah blah

=head3 ipversion

blah blah blah

=head3 table

blah blah blah

=head3 chain

blah blah blah

=head3 target

blah blah blah

=head3 proto

blah blah blah

=head3 in

blah blah blah

=head3 out

blah blah blah

=head3 src

blah blah blah

=head3 dst

blah blah blah

=head3 dpt

blah blah blah

=head3 spt

blah blah blah

=head3 mac

blah blah blah

=head3 state

blah blah blah

=head3 limit

blah blah blah

=head3 logprefix

blah blah blah

=head3 comment

blah blah blah

=head3 generate

blah blah blah

=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.23

=back

=head1 SEE ALSO

L<iptables>

=head1 AUTHOR

Phillip Smith, E<lt>fukawi2@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Phillip Smith

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.

=cut
