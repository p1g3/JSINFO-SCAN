import requests,re
import sys,os
from urllib.parse import urlparse
import chardet
import time
import argparse

domain_list = list()
requests.packages.urllib3.disable_warnings()
js_list = list()
api_url = list()
sys.setrecursionlimit(10000000)
def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample:\npython ' + sys.argv[0] + " -d www.baidu.com --keyword baidu")
    parser.add_argument("-d", "--domain", help="Site you want to scarpy")
    parser.add_argument("-f", "--file", help="File of domain or target")
    parser.add_argument("--keyword", help="Keywords of domain regexp",required=True)
    parser.add_argument("-o","--output", help="Save domains file")
    parser.add_argument("--save", help="Save apis file",required=True)
    return parser.parse_args()

def send_requests(target):
	headers = {'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36'} #Headers
	r = requests.session() # create requests_session()
	r.headers = headers 
	try:
		resp = r.get(target,timeout=(5,20),verify=False,allow_redirects=True)
		if 'charset' not in resp.headers.get('Content-Type', " "):
			resp.encoding = chardet.detect(resp.content).get('encoding') #content_encoding
		return resp.text
	except requests.exceptions.ConnectTimeout: # process except
		print('[-]{} Fail to send_requests to {}：{}'.format(time.strftime('%H:%M:%S'),target,'timeout'))
		return
	except requests.exceptions.Timeout:
		print('[-]{} Fail to send_requests to {}：{}'.format(time.strftime('%H:%M:%S'),target,'timeout'))
		return
	except Exception as e:
		print('[-]{} Fail to send_requests to {}：'.format(time.strftime('%H:%M:%S'),target) + '\n' + str(e))
		return

def process_url(link):
	#process url 
	if not(link.startswith('http://') or link.startswith('https://')):
		link = 'http://' + link
		return link
	else:
		return link
def process_js_url(link,target):
	if link.startswith('//'):
			link = 'http:' + link.strip()
	elif link.startswith('/'):
		link = target + link.strip()
	elif link.startswith('./') or link.startswith('../'):
		link = target + '/' + link.replace('./','').replace('../','').strip()
	elif link.startswith('http://') or link.startswith('https://'):
		link = link.strip()
	else:
		link = target + '/' + link.strip()
	if link.split('?')[0][-3:] == 'jpg' or link.split('?')[0][-3:] == 'gif' or link.split('?')[0][-3:] == 'png' or link.split('?')[0][-3:] == 'css':
		return None
	else:
		return link

def process_api(link,target):
	try:
		netloc = urlparse(link).netloc
	except:
		netloc = None
	if netloc:
		if link.startswith('//'):
			link = 'http:' + link
		elif link.startswith('http://') or link.startswith('https://'):
			link = link
	else:
		link = target + '/' + link
	if link[-1:] == '\\':
		link = link[:-1]
	if link.split('?')[0][-3:] == 'jpg' or link.split('?')[0][-3:] == 'gif' or link.split('?')[0][-3:] == 'png' or link.split('?')[0][-3:] == 'css':
		return None
	else:
		return link

def process_link(link,target):
	if link.startswith('//'):
		link = 'http:' + link.strip()
	elif link.startswith('/'):
		link = target + '/' + link.strip()
	elif link.startswith('./') or link.startswith('../'):
		link = target + '/' + link.replace('./','').replace('../','').strip()
	elif link.startswith('http://') or link.startswith('https://'):
		link = link.strip()
	else:
		link = target + '/' + link.strip()
	return link


def find_links(array_domain): 
	pattern = re.compile('href=["|\'](.*?)["\']',re.S) #pattern
	func_domain_list = list() 
	wait_process_domain_list = list()
	for _ in array_domain:
		target = process_url(_)
		try:
			root_domain = urlparse(target).netloc # find netloc
		except:
			root_domain = None
		if root_domain:
			if root_domain not in domain_list:
				domain_list.append(root_domain) #global domain_list add root_domain
				wait_process_domain_list.append(root_domain) # func_js_list add root_domain(netloc)
				wait_process_domain_list.append(target) # func_js_list add target(add target to find_js)
				with open(output_domains,'a+',encoding='utf-8-sig') as f:
					f.write(root_domain+'\n')
		target = target.replace(' ：','')
		html = send_requests(target)
		if html:
			links = re.findall(pattern,html)
		else:
			print('[-]{} Fail to get html：{}'.format(time.strftime('%H:%M:%S'),target))
			continue
		for link in links: #href links
			link = process_link(link,target)
			#print(link)
			if link:
				try:
					netloc = urlparse(link.strip()).netloc
				except:
					netloc = None
				if netloc:
					for keyword in keywords:
						if keyword in netloc:
							if netloc not in domain_list:
								print('[+]{} new domain find in {}：{}'.format(time.strftime('%H:%M:%S'),root_domain,netloc))
								domain_list.append(netloc)
								func_domain_list.append(netloc)
								wait_process_domain_list.append(netloc)
								with open(output_domains,'a+',encoding='utf-8-sig') as f:
									f.write(netloc + '\n')
			else:
				continue
	if func_domain_list:
		find_links(func_domain_list)
	elif wait_process_domain_list:
		#print(func_list)
		findjs_links(wait_process_domain_list)
		#print(js_list)

def findjs_links(array_domain):
	netloc_list = list()
	link_pattern = re.compile('src=["\'](.*?)["\']',re.S)
	text_pattern = re.compile('<script.*?>(.*?)</script>',re.S)
	for _ in array_domain:
		target = process_url(_)
		#print(target)
		target = target.replace(' ：','')
		html = send_requests(target)
		if html:
			js_links = re.findall(link_pattern,html)
			js_texts = re.findall(text_pattern,html)
		else:
			continue
		if js_texts:
			extract_URL(js_texts,target)
		for link in js_links:
			link = process_js_url(link,target)
			if link:
				try:
					netloc = urlparse(link).netloc
				except:
					netloc =None
				if link not in js_list:
					js_list.append(link)
					extract_URL(link,target)
			else:
				continue
			if netloc:
				for keyword in keywords:
					if keyword in netloc:
						if netloc not in domain_list:
							domain_list.append(netloc)
							netloc_list.append(netloc)
							print('[+]{} new domain find in js {}：{}'.format(time.strftime('%H:%M:%S'),_,netloc))
							with open(output_domains,'a+',encoding='utf-8-sig') as f:
								f.write(netloc.encode('utf-8').decode('gbk') + '\n')
	#print(js_list)
	if netloc_list:
		#print(1)
		#print(netloc_list)
		find_links(netloc_list)

def extract_URL(js_link_or_text,target):
	func_js_list = list()
	func_domain_list = list()
	pattern_raw = r"""
	  (?:"|')                               # Start newline delimiter
	  (
	    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
	    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
	    [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
	    |
	    ((?:/|\.\./|\./)                    # Start with /,../,./
	    [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
	    [^"'><,;|()]{1,})                   # Rest of the characters can't be
	    |
	    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
	    [a-zA-Z0-9_\-/]{1,}                 # Resource name
	    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
	    (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
	    |
	    ([a-zA-Z0-9_\-]{1,}                 # filename
	    \.(?:php|asp|aspx|jsp|json|
	         action|html|js|txt|xml)             # . + extension
	    (?:\?[^"|']{0,}|))                  # ? mark with parameters
	  )
	  (?:"|')                               # End newline delimiter
	"""
	pattern = re.compile(pattern_raw, re.VERBOSE)
	try:
		netloc = urlparse(js_link_or_text).netloc
	except:
		netloc = None
	if netloc:
		html = send_requests(js_link_or_text)
		result = re.finditer(pattern, str(html))
	else:
		result = re.finditer(pattern, str(js_link_or_text))
	if result == None:
		return None
	for match in result:
		api =  match.group().strip('"').strip("'")
		#print(api)
		if api:
			if api not in api_url:
				api = process_api(api,target)
			else:
				continue
			if api:
				if api[-1:] == '\\':
					api = api[:-1]
				if len(api)>7000:
					continue
				api_url.append(api)
				with open(output_apis,'a+',encoding='utf-8-sig') as f:
					f.write(api.strip()+"\n")
				try:
					netloc = urlparse(api).netloc
				except:
					netloc = None
				if api.split('?')[0][-2:] =='js':
					func_js_list.append(api)
				if netloc:
					for keyword in keywords:
						if keyword in netloc:
							if netloc not in domain_list:
								domain_list.append(netloc)
								func_domain_list.append(netloc)
								print('[+]{} new domain find in extract_js {}：{}'.format(time.strftime('%H:%M:%S'),target.replace('http://','').replace('https://',''),netloc))
								with open(output_domains,'a+',encoding='utf-8-sig') as f:
									f.write(netloc + '\n')
		else:
			continue
	if func_domain_list:
		#print('func_domain_list：')
		#print(func_domain_list)
		find_links(func_domain_list)
	if func_js_list:
		#print('func_js_list：')
		#print(func_js_list)
		extract_URL(func_js_list,target)
					



if __name__ == '__main__':
	args = parse_args()
	output_domains = args.output
	output_apis = args.save
	keywords = args.keyword.split(',')
	if args.domain and args.file:
		print('Usage：python3 {} -d www.baidu.com'.format(sys.argv[0]))
		os._exit(0)
	elif args.domain:
		find_links([args.domain])
	elif args.file:
		all_url = []
		with open(args.file,'r+',encoding='utf-8-sig') as f:
			for _ in f:
				_ = _.strip()
				all_url.append(_)
			find_links(set(all_url))
	print('一共爬取了{}条域名'.format(str(len(set(domain_list)))))
	print('一共爬取了{}条api'.format(str(len(set(api_url)))))