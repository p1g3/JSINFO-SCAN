import requests,re
from threading import Thread,activeCount,Lock
from html import unescape
from queue import Queue
from urllib.parse import urlparse
from html import unescape
import sys,os,chardet
import argparse

domains = list()
wait_verify_domains = list()
js_list = list()
api_list = list()
lock = Lock()

requests.packages.urllib3.disable_warnings()
def parse_args():
	parser = argparse.ArgumentParser(epilog='\tUsage:\npython ' + sys.argv[0] + " -d www.baidu.com --keyword baidu")
	parser.add_argument("-d", "--domain", help="Site you want to scrapy")
	parser.add_argument("-f", "--file", help="File of domain or target you want to scrapy")
	parser.add_argument("--keyword", help="Keywords of domain regexp")
	parser.add_argument("--save", help="Saving apis file.")
	parser.add_argument("--savedomain", help="Saving domains file.")
	parser.add_argument("--batch", help="Don\'t need to enter the keywords")
	return parser.parse_args()

def send_request(url):
#	if not url.startswith(('http://','https://')):
	#	url = 'http://' + url
	headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36'}
	session =  requests.session()
	session.headers = headers
	try:
		resp = session.get(url,timeout=(5,20),verify=False)
	except Exception as e:
		print('[Error]Can\'t access to {}'.format(url.strip()))
		return
	try:
		encoding = resp.encoding
		if encoding in [None,'ISO-8859-1']:
			encodings = requests.utils.get_encodings_from_content(resp.text)
			if encodings:
				encoding = encodings[0]
			else:
				encoding = resp.apparent_encoding
		return resp.content.decode(encoding)
	except:
		if 'charset' not in resp.headers.get('Content-Type', " "):
			resp.encoding = chardet.detect(resp.content).get('encoding')  # 解决网页编码问题
		return resp.text

def parse_href(href,url_parse):
	if 'javascript' in href:return
	href = unescape(href)
	black_list = ['jpg','png','css','apk','ico','js','jpeg','exe','gif']
	for bk in black_list:
		if (href[-len(bk):] or href.split('?')[0][-len(bk):]) == bk:return
	if href.startswith(('http://','https://')):return href
	elif href.startswith('////'):
		href = url_parse.scheme + ':' + href[2:]
		return href
	elif href.startswith('///'):
		href = url_parse.scheme + ':' + href[1:]
		return href
	elif href.startswith('//'):
		href = url_parse.scheme  + ':' +  href
		return href
	elif href.startswith('/'):
		href = url_parse.scheme + '://' + url_parse.netloc + href
		return href
	else:
		return url_parse.scheme + '://' + url_parse.netloc + url_parse.path + '/' + href

def parse_script(script,url_parse):
	if 'javascript' in script:return
	script = unescape(script)
	black_list = ['jpg','png','css','apk','ico','jpeg','exe','gif']
	for bk in black_list:
		if (script[-len(bk):] or script.split('?')[0][-len(bk):]) == bk:return
	if script.startswith(('http://','https://')):return script
	elif script.startswith('////'):
		script = url_parse.scheme + ':' + script[2:]
		return script
	elif script.startswith('///'):
		script = url_parse.scheme + ':' + script[1:]
		return script
	elif script.startswith('//'):
		script = url_parse.scheme + ':' + script
		return script
	elif script.startswith('/'):
		script = url_parse.scheme + '://' + url_parse.netloc + script
		return script
	else:
		return url_parse.scheme + '://' + url_parse.netloc + url_parse.path + '/' + script


def find_href(url):
	href_pattern = re.compile('href=["|\'](.*?)["|\']',re.S)
	resp = send_request(url)
	if resp:
		url_parse = urlparse(url)
		href_result = re.findall(href_pattern,resp)
		for _ in href_result:
			href = parse_href(_,url_parse)
			if href:
				href_parse = urlparse(href)
				href_domain = href_parse.netloc
				if lock.acquire():
					if href_domain not in domains:
						for keyword in keywords:
							if keyword in href_domain:
								#print(href_domain)
								domains.append(href_domain)
								print('[{}]{}'.format(len(domains),href_domain))
								wait_verify_domains.append(href_domain)
								break
					lock.release()
		find_js(url,resp)

def find_js(url,resp):
	#queue_script = Queue()
	script_dict = {}
	url_parse = urlparse(url)
	script_pattern = re.compile('src=["|\'](.*?)["|\']',re.S)
	script_text_pattern = re.compile('<script>(.*?)</script>',re.S)
	script_result = re.findall(script_pattern,resp)
	if script_result:
		for _ in script_result:
			_ = parse_script(_,url_parse)
			if _:
				if lock.acquire():
					if _ not in js_list:
						#	print(_)
							script_parse = urlparse(_)
							script_root_domain = script_parse.netloc
							if script_root_domain not in domains:
							#	print(script_root_domain)
								for keyword in keywords:
									if keyword in script_root_domain:
										domains.append(script_root_domain)
										print('[{}]{}'.format(len(domains),script_root_domain))
										wait_verify_domains.append(script_root_domain)
										break
							js_list.append(_)
							resp = send_request(_)
							if resp:
								script_dict[script_parse] = resp
					lock.release()

	script_text_result = re.findall(script_text_pattern,resp)
	if script_text_result:
		for _ in script_text_result:
			script_dict[url_parse] = script_text_result
	#print(script_dict)
	if script_dict:
		find_api(script_dict)

def find_api(script_dict):
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
	for script_parse,script_text in script_dict.items():
		print('[Working]Logging in scrapy {} api.'.format(script_parse.netloc))
		result = re.finditer(pattern, str(script_text))
		if result == None:
			continue
		for match in result:
			match = match.group().strip('"').strip("'")
			match = parse_href(match,script_parse)
			if match:
				if lock.acquire():
					if match not in api_list:
						for keyword in keywords:
							if keyword in match:
								api_list.append(match.strip())
								if api_file:
									with open(api_file,'a+',encoding='utf-8') as f:
										f.write(match.strip() + '\n')
								else:
									print('[Find]{}'.format(match.strip()))
								break
						api_netloc = urlparse(match).netloc.strip()
						if api_netloc not in domains:
							for keyword in keywords:
								if keyword in api_netloc:
									if api_netloc.endswith('\\'):
										api_netloc = api_netloc[:-1]
									domains.append(api_netloc)
									print('[{}]{}'.format(len(domains),api_netloc))
									wait_verify_domains.append(api_netloc)
									break
					lock.release()

def main(domain):
#	global keywords
	find_href(domain)
	queue = Queue()
	lock = Lock()
	num = 0
	while len(wait_verify_domains)>0:
		num = num+1
		print('------------------------------------------------------第{}次轮询开始'.format(num))
	#	domain = wait_verify_domains.pop()
	#	if not domain.startswith(('http://','https://')):
	#		domain = 'http://' + domain
		#print(domain)
		for domain in wait_verify_domains:
			wait_verify_domains.remove(domain)
			if not domain.startswith(('http://','https://')):
				domain = 'http://' + domain
			queue.put(domain)
		while queue.qsize()>0:
			if activeCount()<=20:
				href_thread = Thread(target=find_href,args=(queue.get(),))
				href_thread.start()
				href_thread.join()
	print('Working done！All find {} api and {} domain'.format(len(api_list),len(domains)))
	with open(save_domainfile,'a+',encoding='utf-8') as f:
		for _ in domains:
			f.write(_.strip()+'\n')

	#	find_href(domain)

if __name__ == '__main__':
	args = parse_args()
	domain = args.domain
	domain_file = args.file
	api_file = args.save
	save_domainfile = args.savedomain
	if domain:
	#domain_netloc = urlparse(domain).netloc
		if not domain.startswith(('http://','https://')):
			domain = 'http://' + domain
		try:
			domain_netloc = urlparse(domain).netloc
			domains.append(domain_netloc)
		except:
			print('[Error!]Can\'t access to domain：{}'.format(domain))
		if args.keyword:
			keywords = args.keyword.split(',')
		else:
			keywords = None
		if keywords is None:
			if len(domain_netloc.split('.'))>=3:
				keywords = domain_netloc.split('.')[1:2]
				#print(domain_netloc.split('.'))
			elif len(domain_netloc.split('.'))<3:
				keywords = domain_netloc.split('.')[0:1]
			keyword_check = input('由于未指定关键字，程序选取关键字为{}，若不正确，请输入你的关键字：'.format(keywords))
			if  keyword_check :
				keywords = keyword_check.split(',')
		#	print(keyword_check)
		#print(keywords)
		#return
		domains.append(domain_netloc)
		main(domain)
	elif domain_file:
		queue_file = Queue()
		with open(domain_file,'r+') as f:
			for _ in f:
				domains.append(_)
				if not _.startswith(('http://','https://')):
					_ = 'http://' + _
				queue_file.put(_.strip())
		while queue_file.qsize()>0:
			if activeCount()<=10:
				domain = queue_file.get()
				try:
					domain_netloc = urlparse(domain).netloc
				except:
					print('[Error!]Can\'t access to domain：{}'.format(domain))
				if args.keyword:
					keywords = args.keyword.split(',')
				else:
					keywords = None
				if keywords is None:
					if len(domain_netloc.split('.'))>=3:
						keywords = domain_netloc.split('.')[1:2]
						#print(domain_netloc.split('.'))
					elif len(domain_netloc.split('.'))<3:
						keywords = domain_netloc.split('.')[0:1]
					if not args.batch:
						keyword_check = input('由于未指定关键字，程序选取关键字为{}，若不正确，请输入你的关键字：'.format(keywords))
					if keyword_check:
						keywords = keyword_check.split(',')
				#print(keywords)
				domain_thread = Thread(target=main,args=(domain,))
				domain_thread.start()
				domain_thread.join()

