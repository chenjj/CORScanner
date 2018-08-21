import linecache


def normalize_url(i):
    if '://' in i:
        return [i]
    else:
        return ["http://" + i, "https://" + i]

def parse_headers(headers):
    if headers == None:
        return None
    else:
        parsedheaders = {}
    
        for header in headers:
            index = header.find(":")
            if index == -1:
                return None
            parsedheaders[header[0:index].strip()] = header[index+1:].strip()
        return parsedheaders

def read_file(input_file):
    lines = linecache.getlines(input_file)
    return lines


def read_urls(test_url, input_file, queue):
    if test_url:
        for u in normalize_url(test_url):
            queue.put(u)
    if input_file:
        lines = read_file(input_file)
        for i in lines:
            for u in normalize_url(i.strip()):
                queue.put(u)
