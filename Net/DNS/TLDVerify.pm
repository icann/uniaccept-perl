package Net::DNS::TLDVerify;
#
# Universal Acceptance of TLDs
#
# Copyright (c) 2006 ICANN. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of ICANN nor the names of its contributors may be
#       used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY ICANN AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL ICANN OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


use strict;
use Net::DNS;
use Digest::MD5 qw(md5_hex);
use LWP::Simple;

sub verifytld {

    my ($self, $domain) = @_;

    $domain = striptld($domain);

    my $resolver = Net::DNS::Resolver->new();
    my($answer) = $resolver->query($domain.".", "SOA");
    if (defined($answer) and ($answer->header->rcode ne 'NXDOMAIN')) {
        return 1;
    }
    return 0;

}

sub striptld {

    my ($domain) = @_;

    # strip trailing dot if exists
    #
    $domain =~ s/\.$//;

    $domain =~ s/.*\.//;

    return $domain;

}

sub readfile {

    my ($filename) = @_;

    my $content;
    open(F, $filename);
    {
        local($/) = undef;
        $content = <F>;
    }
    close(F);
    return $content;

}

sub verifytldoffline {

    my ($self, $domain, $dbfile) = @_;

    if (length($dbfile) < 1) {
        $dbfile = "/tmp/tlds-alpha-by-domain.txt";
    }

    my $tldlist = readfile($dbfile);
    my @validtlds = split(/\n/, $tldlist);
    shift(@validtlds); # Throw away first line
    pop(@validtlds); # Throw away last line

    my($tld) = striptld($domain);

    for my $v (@validtlds) {
        if (uc($v) eq uc($tld)) {
            return 1;
        }
    }
    return 0;

}

sub refreshtlddb {

    my ($self, $dbfile) = @_;

    if (!defined($dbfile)) {
        $dbfile = "/tmp/tlds-alpha-by-domain.txt";
    }

    my $tldlist = get("http://data.iana.org/TLD/tlds-alpha-by-domain.txt");
    my $tldmd5 = get("http://data.iana.org/TLD/tlds-alpha-by-domain.txt.md5");
    $tldmd5 = substr($tldmd5, 0, 32);

    # Verify the file was pulled correctly -- MD5 hash must match
    #
    if ($tldmd5 ne md5_hex($tldlist)) {
        return undef;
    }

    open(T, ">$dbfile.tmp");
    print T $tldlist;
    close(T);

    my $fc = readfile($dbfile.".tmp");

    if ($tldmd5 ne md5_hex($fc)) {
        return undef;
    }

    rename($dbfile.".tmp", $dbfile);

}

1;
