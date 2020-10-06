def to_qname(domain):
    parts = domain.split('.')
    retval = []
    for word in parts:
        retval.append(len(word))
        retval.extend(ord(c) for c in word)
    retval.append(0)
    return retval


def from_qname(qname):
    count = -1
    s = ""
    while count != 0:
        count = qname[0]
        qname = qname[1:]
        s += ''.join(chr(c) for c in qname[:count])
        s += '.'
        qname = qname[count:]
    return s


# to_qname("google.com")
