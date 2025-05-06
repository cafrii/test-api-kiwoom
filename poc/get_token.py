
import requests
import json

# this module cannot use imports.py
import os, dotenv
from utils_exception import *
from logging import debug,info,warning,error
from config import KIWOOM_API_HOST


KIWOOM_TOKEN_ENV = "/tmp/.kiwoom_env"



# 접근토큰 발급
def fn_au10001(data:dict = None) -> dict:
	# returns python dict-like object.

	dotenv.load_dotenv()
	KIWOOM_API_APPKEY = os.getenv("KIWOOM_API_APPKEY")
	KIWOOM_API_SECRET = os.getenv("KIWOOM_API_SECRET")
	if not (KIWOOM_API_APPKEY and KIWOOM_API_SECRET):
		error('no api appkey or secret!')
		raise ConfigError('no api appkey or secret!')
		# return None

	# 1. 요청할 API URL
	host = KIWOOM_API_HOST
	endpoint = '/oauth2/token'
	url =  host + endpoint

	# 2. header 데이터
	headers = {
		'Content-Type': 'application/json;charset=UTF-8', # 컨텐츠타입
	}
	# 요청 바디 데이터
	if data is None:
		data = {
			'grant_type': 'client_credentials',  # grant_type
			'appkey': KIWOOM_API_APPKEY,  # 앱키
			'secretkey': KIWOOM_API_SECRET,  # 시크릿키
		}

	# 3. http POST 요청
	resp = requests.post(url, headers=headers, json=data)

	# 4. 응답 상태 코드와 데이터 출력
	debug('Code: %d', resp.status_code)
	debug('Header: %s', resp.headers)
	debug('Body: %s', resp.json())
	# json.dumps(resp.json(), indent=4, ensure_ascii=False)

	if resp.status_code != 200:
		error("status code %d", 200)
		raise AuthenticationError(f'wrong status_code {resp.status_code}')

	return resp.json()



def load_token() -> str:
	'''
	Returns: token string from stored data
		or None if no valid stored token
	'''
	token = None

	# check if file KIWOOM_TOKEN_ENV is really exist and readable
	if os.path.isfile(KIWOOM_TOKEN_ENV) and \
			os.access(KIWOOM_TOKEN_ENV, os.R_OK):
		debug('loading global env..')
		dotenv.load_dotenv(KIWOOM_TOKEN_ENV, verbose=True, override=True)

		token = os.getenv('KIWOOM_API_TOKEN')
		expire_at = os.getenv('KIWOOM_API_EXPIRE_AT')
		debug('token: %s.., expire:%s', token[:8], expire_at)

	if token is None or expire_at is None:
		info('no stored token info')
		return None

	import time
	now = time.strftime('%Y%m%d%H%M%S')
	if expire_at < now:
		info('stored token expired at %s', expire_at)
		return None

	debug('valid stored token exist')
	return token


# export
def GetToken(force_query = False) -> str:
	'''
	Query token and stores them in global env file.

	Args:
		force_query: if True, request token again regardless stored token
		data: optional request data.

	Returns:
		token string, or None if something wrong.

	Raises:
		ConfigError:
		AuthenticationError:

	'''

	if not force_query:
		token = load_token()
		if token:
			return token

	jr = fn_au10001() # python dict-like object

	tt = jr.get('token_type')
	if  not tt or tt != 'Bearer':
		error("wrong token_type: %s", tt)
		raise AuthenticationError(f'wrong token_type {tt}')
		# return None

	with open(KIWOOM_TOKEN_ENV, "w") as f:
		f.write(f'KIWOOM_API_TOKEN = {jr.get('token')}\n')
		f.write(f'KIWOOM_API_EXPIRE_AT = {jr.get('expires_dt')}\n')
		debug('token saved.')

	with open(KIWOOM_TOKEN_ENV, "r") as f:
		debug('verify:')
		for line in f:
			debug('%s', line.rstrip())

	return jr.get('token')



# 실행 구간
if __name__ == '__main__':
	from utils_log import LogInit
	LogInit()
	try:
		token = GetToken()
		info('token: %s', token)
	except Exception as e:
		error('%s %s', e.__class__, e)




'''
Code: 200
Header: {
    "next-key": null,
    "cont-yn": null,
    "api-id": null
}
Body: {
    "expires_dt": "20250504211039",
    "return_msg": "정상적으로 처리되었습니다",
    "token_type": "Bearer",
    "return_code": 0,
    "token": "<token-data>"
}
'''


