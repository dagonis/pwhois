pwhois
======

A python library that allows communication with pwhois servers.

Usage
---------------------
Use this to communicate with pwhois servers.

Some examples of usage:
    from pwhois import pwhois <br />

    test1 = pwhois.lookup("4.2.2.2") <br />
    print(test1) <br />
    IP: 4.2.2.2 <br />
    Origin-AS: 3356 <br />
    Prefix: 4.0.0.0/9 <br />
    AS-Path: 701 3356 <br />
    AS-Org-Name: Level 3 Communications, Inc. <br />
    Org-Name: Level 3 Communications, Inc. <br />
    Net-Name: LVLT-ORG-4-8 <br />
    Cache-Date: 1403520300 <br />
    Latitude: 39.882822 <br />
    Longitude: -105.106477 <br />
    City: BROOMFIELD <br />
    Region: COLORADO <br />
    Country: UNITED STATES <br />
    Country-Code: US <br />
 
    test1_bad = pwhois.lookup("3.3.3.3") <br />
    print(test1_bad) <br />
    Could not retrieve information about 3.3.3.3 <br />
 
Note: The bulk lookup returns a dictionary of results. The IP is the key, with the pwhois object being returned
as the value.<br />

    test2 = pwhois.bulk_lookup(['4.4.4.4', "8.8.8.8"]) <br />
    print(test2) <br />
    {'4.4.4.4': \<pwhois.pwhois object at 0x10fb850d0\>, '8.8.8.8': \<pwhois.pwhois object at 0x10fb7bd90\>} <br />

Note: You can set verbosity to true to return a list of failed results <br />

    test3_good, test3_bad = pwhois.bulk_lookup(['4.2.2.2', '256.1.1', 'cat'], verbosity=True) <br />
    print(test3_good) <br />
    {'4.2.2.2': \<pwhois.pwhois object at 0x10fb85190\>} <br />
    
    print(test3_bad) <br />
    ['256.1.1', 'cat'] <br />

I have tested the bulk function with 25,000 IPs, but I have no reason to believe it won't work with more. The default
pwhois server likely has rate limiting in place so don't abuse the bulk feature.