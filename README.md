# auto-spf-flattener
Given a desired SPF record, flatten it and push it to your DNS provider (so far just cloudflare)

This chaching is intended to solve the two problems of SPF:
- You can't have more than 10 cascaded DNS lookups
- Each lookup's response must fit in a single UDP packet (512 octets)

See http://www.openspf.org/RFC_4408

```
Usage: ./bin/auto-spf-flattener -f spf-file [-p subdomain-prefix] domain

Use the SPF record you would have put in your DNS if you weren't worried about too many lookups or too large a response
Environment variables CF_API_EMAIL and CF_API_KEY are required

  -f, --spf-file string     File that contains a valid spf format TXT record (required)
  -p, --spf-prefix string   Prefix for subdomains when multiple are needed. (default "_spf")
```
  
## Example
```
env - CF_API_KEY=<cloudflare-key> CF_API_EMAIL=<cloudflare-email> ./bin/auto-spf-flattener -f ideal envoy.wtf
```

In this example, `envoy.wtf` is the domain to work on and the file `ideal` looks like:

```
v=spf1 include:mail.zendesk.com include:_spf.google.com include:spf.mail.intercom.io include:servers.mcsv.net ~all
```

The result is the resolution of ~55 ip4 and ip6 addresses, which are pushed to Cloudflare in 3 blocks, along with a master spf record which points to them.
