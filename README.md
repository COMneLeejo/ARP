# 컴퓨터 네트워크 1차 팀 프로젝트 : ARP

## 1. 역할

- shellboy : app layer
- Fortune00 : tcp & ip layer
- moonDD99 : arp layer
- Gye Young, Jung : arp layer + 중간 보고서
- woocheol Kwon : ether & ni layer


## 2. 진행 일정 계획

- 미팅 : 26일, 3일, 10일, 17일(최종)
- 제출 : 보고서 21일, 데모 22일

  - 10일 : 1차 완성 > 현재 코딩 진행 상황 리뷰 + 코멘트 > 보완
  - 17일 : 최종 완성 > 최종 보고서 (+각자 맡은 레이어에 대한 설명)


## 3. 그라운드 규칙

1. Base Layer
- base layer 기반 오버라이딩

2. Naming
- 함수는 camelCase
- 변수는 snake_case

3. Style
- 15-20줄의 코드는 함수화
- 매개변수 최소화하여 사용

4. Comment
- 주석은 최대한 한글
- @param 명시

5. Project
- 각자 맡은 레이어(클래스) 이름의 branch를 생성하여 구현
- 잘 모르겠으면 issue 등록
- chat app, file tranfer, simplest dlg은 건들지 않음


## 4. 커밋 규칙
- ex. [feat] 이슈 컴포넌트 추가
  - 다다음줄 세부내용
- 말머리
  - feat: 새로운 기능 추가
  - refactor: 코드 리팩토링
  - fix: 버그 수정
  - test: 테스트 코드 작성
  - docs: 문서
  - chore: 환경설정 파일
  - style: 코드 형식, 정렬, 린트 등의 변경


## 5. 버전

- jdk version : jdk 1.8.0_301
- wincap : 4.1.3
- vmware workstation


## 6. 프로젝트 설계

- header = inner class
- layer 연결 = arraylist
- arp layer 케시 테이블 = hashmap
