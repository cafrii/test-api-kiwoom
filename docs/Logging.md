


# 디버그 로깅

현재 PoC 단계에서 각각의 단위 시험용 모듈을 실행 시 각 `__main__` 시작점에서 `LogInit()` 호출로 커스텀 로깅이 활성화 됩니다.

다음과 같이 실행하여 원하는 수준의 로그를 켤 수 있습니다.

```
$ dbg=root:debug python <모듈>.py
```
