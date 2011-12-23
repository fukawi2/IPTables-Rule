# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl IPTables-Rule.t'

#########################

use strict;
use warnings;

use Test::More tests => 80;
BEGIN {
	use_ok('IPTables::Rule')
};

#########################

# variables to use in tests
my $good_fqdn = 'www.google.com';
my $good_ipv4_addr = '192.168.100.100';
my $good_ipv4_cidr = '192.168.100.100/24';
my $good_ipv6_short_addr = '2a01:4f8:140:6224::abcd';
my $good_ipv6_short_cidr = '2a01:4f8:140:6224::abcd/64';
my $good_ipv6_full_addr = '2a01:04f8:0140:6224:0000:0000:0000:abcd';
my $good_ipv6_full_cidr = '2a01:04f8:0140:6224:0000:0000:0000:abcd/64';
my $bad_fqdn = 'www.google.com/notafqdn';	# fqdn can not have a path
my $bad_ipv4_addr = '192.168.100.299';		# 299 is invalid nibble
my $bad_ipv4_cidr = '192.168.100.100/48';	# 48 is invalid cidr
my $bad_ipv6_short_addr = '2a01:4f8:140:6224::wxyz';		# wxyz are invalid hex chars
my $bad_ipv6_short_cidr = '2a01:4f8:140:6224::abcd/129';	# 129 is invalid cidr
my $bad_ipv6_full_addr = '2a01:04f8:0140:6224:0000:0000:0000:wxyz';		# wxyz are invalid hex chars
my $bad_ipv6_full_cidr = '2a01:04f8:0140:6224:0000:0000:0000:abcd/129';	# 129 is invalid cidr
my $good_numeric_port		= '80';
my $good_numeric_port_range	= '80:88';
my $good_multiport			= '80,443';
my $good_named_port			= 'http';
my $good_named_multiport	= 'http,https';
my $bad_numeric_port		= '100000';		# too high
my $bad_numeric_port_range	= '80:40';		# min > max
my $bad_multiport			= '80;443';		# semicolon not a valid separator
my $bad_named_port			= 'tcp#$';		# bad characters
my $bad_named_multiport		= 'http/https';	# slash not a valid separator

my $ipt_rule = new_ok( 'IPTables::Rule' );

# test 'ipversion' method
{
	is( $ipt_rule->ipversion('4'),		'4',	'ipversion 4' );
	is( $ipt_rule->ipversion('6'),		'6',	'ipversion 6' );
	isnt( $ipt_rule->ipversion('x'),	'x',	'ipversion x' );
	isnt( $ipt_rule->ipversion('44'),	'44',	'ipversion 44' );
	isnt( $ipt_rule->ipversion('66'),	'66',	'ipversion 66' );
	isnt( $ipt_rule->ipversion('46'),	'46',	'ipversion 46' );
}

# test 'table' method
{
	$ipt_rule->ipversion(4);
	is( $ipt_rule->table('filter'),	'filter',	'ip4 table filter' );
	is( $ipt_rule->table('nat'),	'nat',		'ip4 table filter' );
	is( $ipt_rule->table('mangle'),	'mangle',	'ip4 table filter' );
	is( $ipt_rule->table('raw'),	'raw',		'ip4 table filter' );
	$ipt_rule->ipversion(6);
	is( $ipt_rule->table('filter'),	'filter',	'ip6 table filter' );
	is( $ipt_rule->table('mangle'),	'mangle',	'ip6 table filter' );
	is( $ipt_rule->table('raw'),	'raw',		'ip6 table filter' );
}

# test 'chain' method
{
	is( $ipt_rule->chain('INPUT'),	'INPUT',	'chain INPUT' );
	is( $ipt_rule->chain('FORWARD'),'FORWARD',	'chain FORWARD' );
	is( $ipt_rule->chain('OUTPUT'),	'OUTPUT',	'chain OUTPUT' );
}

# test 'target' method
{
	is( $ipt_rule->target('ACCEPT'),	'ACCEPT',	'target ACCEPT' );
	is( $ipt_rule->target('DROP'),		'DROP',		'target DROP' );
	is( $ipt_rule->target('REJECT'),	'REJECT',	'target REJECT' );
	is( $ipt_rule->target('LOG'),		'LOG',		'target LOG' );
}

# test src address methods
{
	# test valid arguments succeed
	is( $ipt_rule->src($good_fqdn),				$good_fqdn,				'src addr => valid FQDN' );
	is( $ipt_rule->src($good_ipv4_addr),		$good_ipv4_addr,		'src addr => valid IPv4' );
	is( $ipt_rule->src($good_ipv4_cidr),		$good_ipv4_cidr,		'src addr => valid IPv4+CIDR' );
	is( $ipt_rule->src($good_ipv6_short_addr),	$good_ipv6_short_addr,	'src addr => valid IPv6 shortened' );
	is( $ipt_rule->src($good_ipv6_short_cidr),	$good_ipv6_short_cidr,	'src addr => valid IPv6+CIDR shortened' );
	is( $ipt_rule->src($good_ipv6_full_addr),	$good_ipv6_full_addr,	'src addr => valid IPv6 full' );
	is( $ipt_rule->src($good_ipv6_full_cidr),	$good_ipv6_full_cidr,	'src addr => valid IPv6+CIDR full' );
	# test invalid arguments fail
	isnt( $ipt_rule->src($bad_fqdn),				$bad_fqdn,				'src addr => invalid FQDN' );
	isnt( $ipt_rule->src($bad_ipv4_addr),			$bad_ipv4_addr,			'src addr => invalid IPv4' );
	isnt( $ipt_rule->src($bad_ipv4_cidr),			$bad_ipv4_cidr,			'src addr => invalid IPv4+CIDR' );
	isnt( $ipt_rule->src($bad_ipv6_short_addr),	$bad_ipv6_short_addr,	'src addr => invalid IPv6 shortened' );
	isnt( $ipt_rule->src($bad_ipv6_short_cidr),	$bad_ipv6_short_cidr,	'src addr => invalid IPv6+CIDR shortened' );
	isnt( $ipt_rule->src($bad_ipv6_full_addr),	$bad_ipv6_full_addr,	'src addr => invalid IPv6 full' );
	isnt( $ipt_rule->src($bad_ipv6_full_cidr),	$bad_ipv6_full_cidr,	'src addr => invalid IPv6+CIDR full' );
}

# test dst address methods
{
	# test valid arguments succeed
	is( $ipt_rule->dst($good_fqdn),				$good_fqdn,				'dst addr => valid FQDN' );
	is( $ipt_rule->dst($good_ipv4_addr),		$good_ipv4_addr,		'dst addr => valid IPv4' );
	is( $ipt_rule->dst($good_ipv4_cidr),		$good_ipv4_cidr,		'dst addr => valid IPv4+CIDR' );
	is( $ipt_rule->dst($good_ipv6_short_addr),	$good_ipv6_short_addr,	'dst addr => valid IPv6 shortened' );
	is( $ipt_rule->dst($good_ipv6_short_cidr),	$good_ipv6_short_cidr,	'dst addr => valid IPv6+CIDR shortened' );
	is( $ipt_rule->dst($good_ipv6_full_addr),	$good_ipv6_full_addr,	'dst addr => valid IPv6 full' );
	is( $ipt_rule->dst($good_ipv6_full_cidr),	$good_ipv6_full_cidr,	'dst addr => valid IPv6+CIDR full' );
	# test invalid arguments fail
	isnt( $ipt_rule->dst($bad_fqdn),			$bad_fqdn,				'dst addr => invalid FQDN' );
	isnt( $ipt_rule->dst($bad_ipv4_addr),		$bad_ipv4_addr,			'dst addr => invalid IPv4' );
	isnt( $ipt_rule->dst($bad_ipv4_cidr),		$bad_ipv4_cidr,			'dst addr => invalid IPv4+CIDR' );
	isnt( $ipt_rule->dst($bad_ipv6_short_addr),	$bad_ipv6_short_addr,	'dst addr => invalid IPv6 shortened' );
	isnt( $ipt_rule->dst($bad_ipv6_short_cidr),	$bad_ipv6_short_cidr,	'dst addr => invalid IPv6+CIDR shortened' );
	isnt( $ipt_rule->dst($bad_ipv6_full_addr),	$bad_ipv6_full_addr,	'dst addr => invalid IPv6 full' );
	isnt( $ipt_rule->dst($bad_ipv6_full_cidr),	$bad_ipv6_full_cidr,	'dst addr => invalid IPv6+CIDR full' );
}

# test dst port methods
{
	is( $ipt_rule->dpt($good_numeric_port),			$good_numeric_port,			'dst port => valid numeric port' );
	is( $ipt_rule->dpt($good_numeric_port_range),	$good_numeric_port_range,	'dst port => valid numeric port range' );
	is( $ipt_rule->dpt($good_multiport),			$good_multiport,			'dst port => valid numeric multiport' );
	is( $ipt_rule->dpt($good_named_port),			$good_named_port,			'dst port => valid named port' );
	is( $ipt_rule->dpt($good_named_multiport),		$good_named_multiport,		'dst port => valid named multiport' );
	#
	isnt( $ipt_rule->dpt($bad_numeric_port),		$bad_numeric_port,			'dst port => invalid numeric port' );
	isnt( $ipt_rule->dpt($bad_numeric_port_range),	$bad_numeric_port_range,	'dst port => invalid numeric port range' );
	isnt( $ipt_rule->dpt($bad_multiport),			$bad_multiport,				'dst port => invalid numeric multiport' );
	isnt( $ipt_rule->dpt($bad_named_port),			$bad_named_port,			'dst port => invalid named port' );
	isnt( $ipt_rule->dpt($bad_named_multiport),		$bad_named_multiport,		'dst port => invalid named multiport' );
}

# test src port methods
{
	is( $ipt_rule->spt($good_numeric_port),			$good_numeric_port,			'src port => valid numeric port' );
	is( $ipt_rule->spt($good_numeric_port_range),	$good_numeric_port_range,	'src port => valid numeric port range' );
	is( $ipt_rule->spt($good_multiport),			$good_multiport,			'src port => valid numeric multiport' );
	is( $ipt_rule->spt($good_named_port),			$good_named_port,			'src port => valid named port' );
	is( $ipt_rule->spt($good_named_multiport),		$good_named_multiport,		'src port => valid named multiport' );
	#
	isnt( $ipt_rule->spt($bad_numeric_port),		$bad_numeric_port,			'src port => invalid numeric port' );
	isnt( $ipt_rule->spt($bad_numeric_port_range),	$bad_numeric_port_range,	'src port => invalid numeric port range' );
	isnt( $ipt_rule->spt($bad_multiport),			$bad_multiport,				'src port => invalid numeric multiport' );
	isnt( $ipt_rule->spt($bad_named_port),			$bad_named_port,			'src port => invalid named port' );
	isnt( $ipt_rule->spt($bad_named_multiport),		$bad_named_multiport,		'src port => invalid named multiport' );
}

# test 'protocol' method
{
	is( $ipt_rule->proto('tcp'),	'tcp',	'protocol; tcp' );
	is( $ipt_rule->proto('udp'),	'udp',	'protocol; udp' );
	is( $ipt_rule->proto('icmp'),	'icmp',	'protocol; icmp' );
	is( $ipt_rule->proto('47'),		'47',	'protocol; numeric)' );
}

# test some full rules
my $test_rule1 = '-t mangle -A cmn_SPOOF -i bond0.12 -m comment --comment "test rule 01" -j DROP';
my $test_rule2 = '-A FORWARD -i bond0 -o bond0.16 -m conntrack --ctstate NEW -j x_LEG_WLS';
my $test_rule3 = '-A tgt_SAMBA -p udp --dport 138 -m comment --comment "test rule 3" -j ACCEPT';
{
	my $rule1 = new_ok( 'IPTables::Rule' );
	$rule1->table('nat');
	$rule1->chain('cmn_SPOOF');
	$rule1->target('DROP');
	$rule1->in('bond0.12');
	$rule1->comment('test rule 01');
	is( $rule1->generate, $test_rule1, 'test rule 1' );
}
{
	my $rule2 = new_ok( 'IPTables::Rule' );
	$rule2->chain('FORWARD');
	$rule2->target('x_LEG_WLS');
	$rule2->in('bond0');
	$rule2->out('bond0.16');
	$rule2->state('NEW');
	is( $rule2->generate, $test_rule2, 'test rule 2' );
}
{
	my $rule3 = new_ok( 'IPTables::Rule' );
	$rule3->chain('tgt_SAMBA');
	$rule3->target('ACCEPT');
	$rule3->proto('udp');
	$rule3->dpt('138');
	$rule3->comment('test rule 3');
	is( $rule3->generate, $test_rule3, 'test rule 3' );
}
