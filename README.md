# site-checker
A script to check in on various URLs.

Populate a `sites` file in the same directory with one hostname per line.  Then run it!

This will:
- ping the site and check for a `200` status
- get the SSL certificate and check that it is active (`notBefore` and `notAfter` dates OK)
