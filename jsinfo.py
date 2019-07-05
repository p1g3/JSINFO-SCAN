import requests,re
import os,sys
import argparse
import chardet
import time
from threading import Thread,activeCount,Lock
from queue import Queue
from html import unescape
from urllib.parse import urlparse,unquote
#import urllib

requests.packages.urllib3.disable_warnings()

def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample:\npython ' + sys.argv[0] + " -d www.baidu.com --keyword baidu")
    parser.add_argument("-d", "--domain", help="Site you want to scarpy")
    parser.add_argument("-f", "--file", help="File of domain or target")
    parser.add_argument("--keyword", help="Keywords of domain regexp",required=True)
    parser.add_argument("-o","--output", help="Save domains file")
    parser.add_argument("--max",help='max scarpy deepth')
    parser.add_argument("--url",help="if you need max 2,input the saving url file")
    parser.add_argument("--save", help="Save apis file")
    return parser.parse_args()


class JSINFO():
	def __init__(self,domains,keywords,output_apis,output_urls,output_domains=None,max=1):
		self.keywords = keywords.split(',')
		if not output_apis:
			self.output_apis = 'output_apis.txt'
		else:
			self.output_apis = output_apis
		self.domains = domains
		self.output_urls = output_urls
		if not self.output_urls:
			self.output_urls = 'output_urls.txt'
		self.urls = list()
		self.apis = list()
		self.finded_urls = list()
		self.finded_js = list()
		self.output_domains = output_domains
		if max:
			if max in ['1','2']:
				self.max = int(max)
			else:
				print('max scrapy deepth in 1~2')
				os._exit(0)
		else:
			self.max = 1

	def scrapy_links(self,target_list):
		func_list = list()
		link_pattern = re.compile('href=["|\'](.*?)["|\']',re.S)
		for target in target_list:
			if target not in self.finded_urls:
				self.finded_urls.append(target)
				func_list.append(target)
			target = self.process_target(target)
			target_parse = urlparse(target)
			if urlparse(target).netloc not in self.finded_js:
				self.finded_js.append(urlparse(target).netloc)
				self.find_js_raw(target_parse,target.replace('http://','').replace('https://',''))
				self.find_js_raw(target_parse,target_parse.netloc)
			if target:
				#print(target)
				text = self.send_requests(target)
			else:
				continue
			#print(target)
			if text:
				links = re.findall(link_pattern,text)
				if links:
					for link in links:
						if not link:continue
						link = self.process_link(target_parse,link)
						if link:
							if link not in self.finded_urls:
								self.finded_urls.append(link)
								if self.max == 2:
									for keyword in self.keywords:
										if keyword in link:
											self.urls.append(link)
											self.finded_urls.append(link)
											func_list.append(link)
											if self.output_urls:
												with open(self.output_urls,'a+',encoding='utf-8') as f:
													f.write(link + '\n')
											print('[+]{} Find new link by scrapy_links in {}：{}'.format(time.strftime('%H:%M:%S'),target_parse.netloc,link))
										if not (urlparse(link).netloc == link.replace('https://','').replace('http://','')[:-1] or urlparse(link).netloc == link.replace('https://','').replace('http://','')):
											if urlparse(link).netloc:
												if keyword in urlparse(link).netloc:
													if urlparse(link).netloc not in self.domains and urlparse(link).netloc.replace('www.','') not in self.domains:
														if self.output_domains:
															with open(self.output_domains,'a+',encoding='utf-8') as f:
																f.write(urlparse(link).netloc + '\n')
														print('[+]{} Find new netloc by scrapy_links in {}：{}'.format(time.strftime('%H:%M:%S'),target_parse.netloc,urlparse(link).netloc))
														self.domains.append(urlparse(link).netloc)
														func_list.append(urlparse(link).netloc)
														self.finded_urls.append(urlparse(link).netloc)
								elif self.max == 1:
									if urlparse(link).netloc:
										for keyword in self.keywords:
											if keyword in urlparse(link).netloc:
												if urlparse(link).netloc not in self.domains and urlparse(link).netloc.replace('www.','') not in self.domains:
													if self.output_domains:
														with open(self.output_domains,'a+',encoding='utf-8') as f:
															f.write(urlparse(link).netloc + '\n')
													print('[+]{} Find new netloc by scrapy_links in {}：{}'.format(time.strftime('%H:%M:%S'),target_parse.netloc,urlparse(link).netloc))
													self.domains.append(urlparse(link).netloc)
													func_list.append(urlparse(link).netloc)
													self.finded_urls.append(urlparse(link).netloc)
		if func_list:
			#print(func_list)
			#print(self.domains)
			self.scrapy_links(func_list)

	def send_requests(self,target):
		headers = {'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36',
		'cookie':r'o2Control=webp; shshshfpa=b4b40f28-27e8-970e-c22e-1fd52cf3e4c3-1561051162; shshshfpb=moqXy%2FqosMI73X4YrJvo4Pg%3D%3D; _tp=z18dhXDHoUPtjjGXWKWB2BOMGaV7%2FrPT1iyxGUs9syA%3D; _pst=jd_4a28f039b8865; user-key=7d15fb39-62d8-4086-b9bc-24a3ca1430ab; unick=jd_166895qpw; o2State={%22webp%22:true}; areaId=22; ipLoc-djd=22-1930-4284-0; pinId=xSNzjumtpYzakNtnEi1DpLV9-x-f3wj7; pin=jd_4a28f039b8865; unpl=V2_ZzNtbUcHEBYmDhNULEsOVmIFRVUSBBQUcQ5OUyseDlBgUBVZclRCFX0UR1JnGFkUZAMZXEpcRhFFCEVkexhdBWMAGlxKVXNFGwtCOngYbDVkAyJccldHEnUJQlR7Hl0GZAQVWUtWShJ9DUdkSxlUAlczyuv%2bg8iioaXHgPWripPH1Knslfr7zd2pkuDmzeKMVwQRVEdecxRFCXYfFRgRBWMEElxGV0MSdAtFU3wdVQRuBBpYQ2dCJXY%3d; __jdv=122270672|kong|t_1001529093_a_25_20|jingfen|4ab2b7d1fccb47f9abf05796a6cd6b65|1562245787968; __jdu=1561051160226658086940; TrackID=11vMJ7ONs0xS5oqXK7Il505he_413Dl8geAQ3OWLbb2gg9zdxRIf6NtNxVd8Jma6l7Fh6NCMmXlgKN46KZpmBYVWnal5fKnGZhE1iw2AAAEY; shshshfp=0f99aa3bd48949c0f3d2e736620919a4; cn=16; __jdc=122270672; __jda=122270672.1561051160226658086940.1561051160.1562256944.1562310002.34'}
		session = requests.session()
		session.headers = headers
		if len(target)>400:
			return None
		try:
			resp = session.get(target,verify=False,timeout=(5,20))
			encoding = resp.encoding
			if encoding in [None, 'ISO-8859-1']:
				encodings = requests.utils.get_encodings_from_content(resp.text)
				if encodings:
					encoding = encodings[0]
				else:
					encoding = resp.apparent_encoding
				if not encoding:
					return None
			return resp.content.decode(encoding)
		except Exception as e:
			print('[-]{} Fail to send_requests：{} {}'.format(time.strftime('%H:%M:%S'),target,e))
			return None

	def process_target(self,target):
		if not target.startswith(('http://','https://')):
			target = 'http://' + target
		return target
	def process_link(self,parse_result,link):
		link = unescape(link).strip()
		if link:
			if link.startswith(('http://','https://')):return link
			if link.split('?')[0][-2:] == 'js' or link.split('?')[0][-3:] == 'css' or link.split('?')[0][-3:] == 'jpg' or link.split('?')[0][-3:] == 'gif' or link.split('?')[0][-3:] == 'png' or link.split('?')[0][-3:] == 'ico' or link.split('?')[0][-3:] == 'apk': return None
			if link[-2:] == 'js' or link[-3:] == 'css' or link[-3:] == 'jpg' or link[-3:] == 'png' or link[-3:] == 'gif' or link[-3:] == 'ico' or link[-3:] == 'apk': return None
			if 'javascript' in link: return None
			if link.startswith('./'):
				link = parse_result.scheme + '://' + parse_result.netloc + parse_result.path + link[1:]
				return link
			elif link.startswith('////'):
				link = 'http://' + link[4:]
				return link
			elif link.startswith('//'):
				link = 'http:' + link
				return link
			elif link.startswith('/'):
				link = parse_result.scheme + '://' + parse_result.netloc + link
				return link
			elif link.startswith('../'):
				link = parse_result.scheme + '://' + parse_result.netloc + parse_result.path + link
				return link
			testing_link = 'http://' + link
			if not (re.findall('[a-zA-Z0-9]',testing_link[7:8])):
				return None

	def process_js_link(self,parse_result,link):
		link = unescape(link).strip()
		if link:
			try:
				if link[-1:] == '\\':link = link[:-1]
				if  link.split('?')[0][-3:] == 'css' or link.split('?')[0][-3:] == 'jpg' or link.split('?')[0][-3:] == 'gif' or link.split('?')[0][-3:] == 'png' or link.split('?')[0][-3:] == 'ico' or link.split('?')[0][-3:] == 'apk': return None
				if  link[-3:] == 'css' or link[-3:] == 'jpg' or link[-3:] == 'png' or link[-3:] == 'gif' or link[-3:] == 'ico' or link[-3:] == 'apk': return None
				if 'javascript' in link: return None
				if link.startswith(('http://','https://')):return link
				if link.startswith('./'):
					link = parse_result.scheme + '://' + parse_result.netloc + parse_result.path + link[1:]
					return link
				elif link.startswith('////'):
					link = 'http://' + link[4:]
					return link
				elif link.startswith('//'):
					link = 'http:' + link
					return link
				elif link.startswith('/'):
					link = parse_result.scheme + '://' + parse_result.netloc + link
					return link
				elif link.startswith('../'):
					link = parse_result.scheme + '://' + parse_result.netloc + parse_result.path + link
					return link
				testing_link = 'http://' + link
				if not (re.findall('[a-zA-Z0-9]',testing_link[7:8])):
					return None
			except:
				return None

	def find_js_raw(self,parse_result,netloc):
		js_link_pattern = re.compile('src=["|\'](.*?)["|\']',re.S) # /xx.js
		js_raw_pattern = re.compile('<script.*?>(.*?)</script>',re.S) #<script>javascript_codes</script>
		#print('http://' + netloc)
		text = self.send_requests('http://' + netloc)
		if text:
			result_link = re.findall(js_link_pattern,text)
			result_raw = re.findall(js_raw_pattern,text)
			#print(result_raw)
			if result_raw:
				self.extract_URL(parse_result,result_raw)
			if result_link:
				for js_link in result_link:
					js_link = self.process_js_link(parse_result,js_link)
					if js_link:
						js_text = self.send_requests(js_link)
					else:
						continue
					if js_text:
						self.extract_URL(parse_result,js_text)

	def extract_URL(self,parse_result,js_text):
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
		func_list = list()
		func_js_list = list()
		pattern = re.compile(pattern_raw, re.VERBOSE)
		result = re.finditer(pattern, str(js_text))
		if result == None:
			return None
		for match in result:
			match = match.group().strip('"').strip("'")
			match = self.process_link(parse_result,match)
			if match:
				match = self.process_js_link(parse_result,match)
				if match:
					if match.split('?')[0][-2:] == 'js' or match[-2:] == 'js':
						if match not in self.finded_js:
							self.finded_js.append(match)
							func_js_list.append(match)
							continue
				if match not in self.apis:
					if match:
						for keyword in self.keywords:
							if keyword in match:
								with open(self.output_apis,'a+',encoding='utf-8') as f:
									f.write(match + '\n')
								print('[+]{} new api find in js_file {}：{}'.format(time.strftime('%H:%M:%S'),parse_result.netloc,match))
								self.apis.append(match)
							try:
								if urlparse(match).netloc not in self.domains:
									for keyword in self.keywords:
										if keyword in urlparse(match).netloc:
											self.domains.append(urlparse(match).netloc)
											func_list.append(urlparse(match).netloc)
											if self.output_domains:
												with open(output_domains,'a+',encoding='utf-8') as f:
													f.write(urlparse(match).netloc+'\n')
											print('[+]{} net netloc find in js_file {}：{}'.format(time.strftime('%H:%M:%S'),parse_result.netloc,urlparse(match).netloc))
							except:
								continue
		if func_js_list:
			for _ in func_js_list:
				text_js = self.send_requests(_)
				if text_js:
					self.extract_URL(parse_result,text_js)
	def result(self):
		print('[+]{} find {} netloc'.format(time.strftime('%H:%M:%S'),len(self.domains)))
		print('[+]{} find {} api'.format(time.strftime('%H:%M:%S'),len(self.apis)))
		print('[+]{} find {} link'.format(time.strftime('%H:%M:%S'),len(self.urls)))


if __name__ == '__main__':
	args = parse_args()
	domain = args.domain
	domain_file = args.file
	keywords = args.keyword
	output = args.output
	max_scrapt = args.max
	url_file = args.url
	api_file = args.save
	if domain and domain_file:
		print('Usage：python3 {} -d baidu.com --keyword baidu'.format(sys.argv[0]))
		os._exit(0)
	if domain:
		if not domain.startswith(('http://','https://')):
			domain = 'http://' + domain
		jsinfo = JSINFO([urlparse(domain).netloc],keywords,api_file,url_file,output,max_scrapt)
		jsinfo.scrapy_links([domain])
		jsinfo.result()
	if domain_file:
		domain_list = list()
		netloc_list = list()
		with open(domain_file,'r+') as f:
			for _ in f:
				if not _.startswith(('http://','https://')):
					domain = 'http://' + _
				if domain not in domain_list:
					domain_netloc = urlparse(domain).netloc
					netloc_list.append(domain_netloc)
					domain_list.append(domain)
			jsinfo = JSINFO(netloc_list,keywords,api_file,url_file,output,max_scrapt)
			jsinfo.scrapy_links(domain_list)
			jsinfo.result