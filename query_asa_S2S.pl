#!/usr/bin/perl -w
######
# LAN2LAN Traffic Perl Script for Cisco ASA/Pix/Concentrator VPN devices 
# Original script by Dan Brummer
# Updated for ASA by Sebastiaan Kortleven
# Updated for indexed Cacti queries by Brian Rudy (brudyNO@SPAMpraecogito.com)
# This script will walk the LAN2LAN sessions on a Cisco ASA and return RX/TX Octets
# based on an IKE peer IP index
#
# Usage: 
#   query_lan2lan_cisco.pl community host {ASA,CONCENTRATOR} index
#   query_lan2lan_cisco.pl community host {ASA,CONCENTRATOR} query (RX,TX)
#   query_lan2lan_cisco.pl community host {ASA,CONCENTRATOR} get (RX,TX) peer
#   
# Peer IP is the IP of the LAN2LAN IKE session
# 
#
########
# v0.07 6/1/2010
#	-Minor update to default to SNMP v2c.
#
# v0.06 3/10/2010
# 	-Additional OID handing tweaks to work with more stringent Net::SNMP versions.
#
# v0.05 3/5/2010 Brian Rudy
#	-Tweaks for cleaner OIDs
#
# v0.04 10/26/2009 Brian Rudy
#	-Update to add POSIX signal handling so things don't hang spine
#
# v0.03 5/2/2008 Brian Rudy
# 	-First version supporting indexed queries
#	-Updates to support Perl strict compliance
######

use strict;
use POSIX;
use Switch;
use Net::SNMP;

# To ensure we behave when we get an hangup signal
$SIG{HUP} = \&safe_shutdown;
alarm(250);


if (defined($ARGV[0]) && defined($ARGV[1]) && defined($ARGV[2]) && defined($ARGV[3])) {
	if (($ARGV[3] ne "query") && ($ARGV[3] ne "get") && ($ARGV[3] ne "index")) {
		print_usage();
	}
} else {
	print_usage();
}


# Set variables based on input parameters
my $community      = $ARGV[0];
my $host           = $ARGV[1];
my $device         = $ARGV[2];
my $type         = $ARGV[3];
#my $field	= $ARGV[4];
my $field;
my $snmpversion = 2; # Default to SNMP v2c
#my $sessionip      = $ARGV[5];
#my $sessionip;

# Set OID variables for ASA
my $cikeTunRemoteValue     = "1.3.6.1.4.1.9.9.171.1.2.3.1.7";
my $cipSecTunIkeTunnelIndex = "1.3.6.1.4.1.9.9.171.1.3.2.1.2";


my $cipSecTunInOctets              = "1.3.6.1.4.1.9.9.171.1.3.2.1.26";
my $cipSecTunOutOctets             = "1.3.6.1.4.1.9.9.171.1.3.2.1.39";

#$cipSecTunInOctets             = "1.3.6.1.4.1.9.9.171.1.3.2.1.27.";
#$cipSecTunOutOctets            = "1.3.6.1.4.1.9.9.171.1.3.2.1.43.";


# Set OID variables for CONCENTRATOR
my $alActiveSessionIpAddressOID    = "1.3.6.1.4.1.3076.2.1.2.17.2.1.4";
my $alActiveSessionOctetsRcvd              = "1.3.6.1.4.1.3076.2.1.2.17.2.1.10";
my $alActiveSessionOctetsSent              = "1.3.6.1.4.1.3076.2.1.2.17.2.1.9";


# Create SNMP Session

my ($session, $error) = Net::SNMP->session(-hostname=>$host,-community=>$community,-port=>161,-version=>$snmpversion);
die "session error: $error" unless ($session);

my @peers;

if ($type eq "index") {
	if ($device eq "ASA") {
		@peers = list_peers($cikeTunRemoteValue);
	} else {
		@peers = list_peers($alActiveSessionIpAddressOID);
	}

	foreach my $peer (@peers) {
		print "$peer\n"; 
	}
	# Close SNMP session
	$session->close;
	exit;
} else {
	unless (defined($ARGV[4]) && (($ARGV[4] eq "TX") || ($ARGV[4] eq "RX") || ($ARGV[4] eq "index"))) {
		print_usage();
	}
	my $field	= $ARGV[4];

	if (($type eq "query") && ($field eq "index")) {
		if ($device eq "ASA") {
                	@peers = list_peers($cikeTunRemoteValue);
        	} else {
                	@peers = list_peers($alActiveSessionIpAddressOID);
        	}
		foreach my $peer (@peers) {
                	print "$peer:$peer\n";
        	}
        	# Close SNMP session
        	$session->close;
        	exit;
	}
	
	if (($type eq "get") && defined($ARGV[5])) {
		my $sessionip   = $ARGV[5];
		#print "Getting IO for $sessionip\n"; 
		my($tx,$rx) = get_io($sessionip);
		if ($field eq "TX") {
			print $tx;
		} elsif ($field eq "RX") {
			print $rx;
		} 
	}
	else {
		if ($device eq "ASA") {
			@peers = list_peers($cikeTunRemoteValue);
		} else {
			@peers = list_peers($alActiveSessionIpAddressOID);
		}
		foreach my $peer (@peers) {
			#print "Getting IO for $peer\n";
			my($tx,$rx) = get_io($peer);
                	if ($field eq "TX") {
	                        print "$peer:$tx\n";
                	} elsif ($field eq "RX") {
                        	print "$peer:$rx\n";
                	} 
        	}
	
	}
	# Close SNMP session
	$session->close;
	exit;
}

sub get_io {
	my ($sessionip) = @_;

my (@ips,$rcOid,$txOid,$ipOid);

switch ($device){

	case ('ASA'){
        	@ips = get_index_for_value($cikeTunRemoteValue,$sessionip);
        	$rcOid = $cipSecTunInOctets;
        	$txOid = $cipSecTunOutOctets;
        	$ipOid = $cipSecTunIkeTunnelIndex;
	}else{
        	push (@ips,$sessionip);
        	$rcOid = $alActiveSessionOctetsRcvd;
        	$txOid = $alActiveSessionOctetsSent;
        	$ipOid = $alActiveSessionIpAddressOID;

	}
}

#print "Found value ".$ips[0]."\n";

my @keys = get_index_for_value($ipOid,\@ips);

#print "Found key ".@keys."\n";

# We now have an index of a matching session ip, lets grab the data
# Get session traffic octect based on index and flow (tx or rx)


# Sum the RX and TX for each IPSec session in the IKE tunnel
my $rx = 0;
foreach my $k (@keys){
        my $indata = $session->get_request($rcOid.$k);
        $rx = $rx + $indata->{$rcOid.$k};
	#print "For $rcOid$k Adding RX=" . $indata->{$rcOid.$k} . ", total=$rx\n";
}


my $tx = 0;
foreach my $k (@keys){
        my $outdata = $session->get_request($txOid.$k);
        $tx = $tx + $outdata->{$txOid.$k};
	#print "Adding TX=" . $outdata->{$txOid.$k} . ", total=$tx\n";
}


#print "getting ".$key." ".$outdata." for ".$rcOid.$key ."\n";

#$outdata = $session->get_request($txOid.$key);
#$tx = $outdata->{$txOid.$key};
#print "getting ".$key." ".$outdata." for ".$txOid.$key."\n";


# Output data cleanly

chomp($tx);
chomp($rx);
return($tx,$rx);

}

sub safe_shutdown {
  # We had an alarm timeout, shut down
  exit(0);
}


sub print_usage {
	print "usage:\n\n./query_lan2lan_cisco.pl community host {ASA,CONCENTRATOR} index\n./query_lan2lan_cisco.pl community host {ASA,CONCENTRATOR} query {RX,TX}\n./query_lan2lan_cisco.pl community host {ASA,CONCENTRATOR} get {RX,TX} DEVICE\n";
	exit;
}

sub list_peers {
	my ($peertableoid) = @_;
	my $result = $session->get_table($peertableoid);
                die "request error: ".$session->error unless $result;
	my @indexoids = $session->var_bind_names;
	my @answer;
	foreach my $oid (@indexoids){
		my @splits = split($peertableoid,$oid);
		my $dataindex = $splits[1];
		# Grab a hash of the value from the OID
		my $getdata = $session->get_request($oid);
		push(@answer,$getdata->{$oid});		
	}
	return @answer;
}

sub get_index_for_value{
        my ($parentoid,$value) = @_; #the OID to check for the key value, the value we need the index for
        my @index;
        my $result = $session->get_table($parentoid);
                die "request error: ".$session->error unless $result;
        my @indexoids = $session->var_bind_names;
        foreach my $oid (@indexoids){
                #sprint "Checking ".$oid."\n";
                # Split the full OID to get the index
                my @splits = split($parentoid,$oid);
		my %datatable;
                # Set index var
                my $dataindex = $splits[1];
                #print "Index value ".$dataindex."\n";
                # Grab a hash of the value from the OID
                my $getdata = $session->get_request($oid);
                $datatable{$dataindex} = $getdata->{$oid};
                #if the returned data equals the value, return the key
		#print $value."\n";
                if (ref($value) eq 'ARRAY'){
			#print "\$value is an array\n";
                        foreach my $v (@$value){
                               #print "checking $v against " . $datatable{$dataindex} . "\n";
                                if ($v eq ("." . $datatable{$dataindex})){
                                        push(@index,$dataindex);
                                        #print "Found match for ".$v.", result ".$dataindex."\n";
                                }
                        }
                }else{
			if (defined $value) {
                        	if ($datatable{$dataindex} eq $value){
                                	push(@index,$dataindex);
                               		#print "Found match 2 for ".$value.", result ".$dataindex."\n";
                        	}
			}
                }
        }
        return @index
}
