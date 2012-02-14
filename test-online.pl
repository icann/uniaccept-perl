#!/usr/bin/perl


use Net::DNS::TLDVerify;

sub main {

    if ($#ARGV < 0) {
        print "Usage: $0 [domain]\n";
        exit(2);
    } else {
        my $domain = $ARGV[0];
        $result = Net::DNS::TLDVerify->verifytld($domain);
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
