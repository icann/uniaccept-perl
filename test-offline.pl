#!/usr/bin/perl

use Net::DNS::TLDVerify;

sub main {

    #
    #  NOTE! This is for demonstration purposes. You should not fetch this
    #  file every time you want to do a test -- instead it should be cached
    #  locally and not redownloaded more often than once every 24 hours.
    #

    my $tmpfile = "/tmp/tld-list.txt";
    Net::DNS::TLDVerify->refreshtlddb($tmpfile);

    if ($#ARGV < 0) {
        print "Usage: $0 [domain]\n";
        exit(2);
    } else {
        my $domain = $ARGV[0];
        $result = Net::DNS::TLDVerify->verifytldoffline($domain, $tmpfile);
        if ($result == 1) {
            print "$domain contains a valid TLD\n";
            exit(0);
        } else {
            print "$domain does NOT contain a valid TLD\n";
            exit(1);
        }
    }
}

main()
