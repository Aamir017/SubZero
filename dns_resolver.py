import dns.resolver
import dns.exception

def resolve_dns(subdomain):
    """
    Resolve DNS records for a subdomain
    Returns a dictionary with DNS information
    """
    result = {
        'cname': None,
        'a_records': [],
        'vulnerable_dns': False
    }
    
    try:
        # Try to resolve CNAME records
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            result['cname'] = str(rdata.target).rstrip('.')
        
        # Check if CNAME exists but doesn't resolve (dangling CNAME)
        if result['cname']:
            try:
                dns.resolver.resolve(result['cname'], 'A')
            except dns.exception.DNSException:
                result['vulnerable_dns'] = True
                
    except dns.resolver.NXDOMAIN:
        # NXDOMAIN means the domain doesn't exist
        result['vulnerable_dns'] = True
    except dns.resolver.NoAnswer:
        # No CNAME record, try A record
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            for rdata in answers:
                result['a_records'].append(str(rdata))
        except dns.exception.DNSException:
            result['vulnerable_dns'] = True
    except dns.exception.DNSException:
        # Other DNS exceptions
        result['vulnerable_dns'] = True
    
    return result