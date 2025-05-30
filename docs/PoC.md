
# Proof Of Concept

현재 이 API 들을 활용하여 무슨 일을 진행할 것인지는 뚜렷하게 정해진 목적이 없습니다. (어쩌면 마지막까지 결정이 안될 수도 있습니다.)

기본 REST API 동작 확인을 위해서 여러가지 방법들이 있겠지만, 코드 연습도 할 겸 해서 Python 코드로 샘플 코드를 작성하여 실행해 보는 방식으로 진행 중입니다.

이 단계를 PoC 라고 부를 수도 있고, 그냥 단위 시험 작성 단계라고 불러도 좋습니다.

어쨌든 이러한 정식 개발 이전의 간단한 작업들이라도, 이력 관리는 필요합니다.
PoC 전용 리포지토리를 생성하는 대신, 정식 리포지토리로 발전할 것을 염두해 두고 폴더 구조를 관리하고 있습니다.

현재 단계에서 모든 시험 관련 코드는 /poc/ 아래에서 진행하고 있습니다.

<br>

# PoC 순서 계획

PoC 의 대략적인 주제는 다음과 같습니다.
- 1: 인증 동작
  - 제공 받은 APPKEY 및 SECRET 동작 확인 -> 완료
  - 토큰 생성 확인 -> 완료
- 가장 기본적인 아무 기능 하나를 선택한 후 API 쿼리 및 응답 확인
- 그 다음 관심 있는 일부 기능 확인
  - 2: 잔고 (예수금 및 주식 잔고)
  - 3: 과거 주가 정보
  - ...

## 1. 인증
```
python3 get_token.py
```

<br>



## 2. 예수금 정보 확인
<br>

## 3. 과거 시세

- 삼성전자 일봉 그래프에 필요한 정보를 쿼리
  - 과거 데이터 기반의 전략 검증 (백테스팅) 의 사전 기능 확인용

- 키움 API 문서에서, '차트' 또는 '시세' 그룹에서 관련 API를 찾아야 함
  - 예: 일/주/월/분/틱 데이터 조회

- **고려사항**
  - 날짜 범위 지정, 데이터 형식(캔들스틱: 시고저종, 거래량), 대량 데이터 처리(연속 조회 필요 가능성) 등을 확인해야 함.

- 테스트
```
# 삼성전자 주식 일봉 차트 정보. 오늘 날짜 기준 과거 600일의 정보. 기본 1회 요청
python3 query_chart_day.py 005930

# 특정 일 기준 조회. 과거 600일, 1회 요청
python3 query_chart_day.py 005930 20250501

# 2025.5.1 기준으로 과거 2000 일 분량의 정보 조회
python3 query_chart_day.py 005930 20250501 days=2000

# 2020년 1월 1일 까지의 데이터
python3 query_chart_day.py 005930 20250501 to_date=20200101
```

- 분봉 차트 시험
```
# 현재 기준으로 과거 900개 항목, 1분 단위
python3 query_chart_minute.py 005930
# 결과 범위: 20250430 130500 ~ 20250507 153000

# 5분 단위
python3 query_chart_minute.py 005930 5
# 결과 범위: 20250417 115500 ~ 20250507 153000

# 3000 개 항목
python3 query_chart_minute.py 005930 1 items=3000
# 20250423 095500 ~ 20250507 153000

# 지정 날짜 까지
python3 query_chart_minute.py 005930 1 to_time=20250425000000
# 20250425 090000 ~ 20250507 153000
```

- 틱 차트
```
# 현재 기준, 과거 900 항목 데이터. 기본 30 틱 단위
python3 query_chart_tick.py 005930
# 20250507 134637 ~ 20250507 151955

# 1 틱 단위. 기본 900 항목
python3 query_chart_tick.py 005930 1
# 20250507 151754 ~ 20250507 153011

# 1 틱 단위, 2000 항목
python3 query_chart_tick.py 005930 1 2000
# 20250507 151358 ~ 20250507 153011

# 30 틱 단위로 지정 시간까지
python3 query_chart_tick.py 005930 30 to_time=20250507000000
# 20250507 090019 ~ 20250507 151955,  총 3845
```

<br>

## 4. DataFrame 변환 및 가공, 저장
- 5/6~
- 추가 래퍼 함수 작성. Pandas DataFrame 으로 변환 후 데이터 유효성 검사
- 추후 재활용할 수 있도록 Parquet 포맷으로 저장
-