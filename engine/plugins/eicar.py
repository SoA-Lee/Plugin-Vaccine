# -*- coding:utf-8 -*-

import os
import cryptolib

class CLBMain:
    # 플러그인 엔진 초기화
    # 입력값 : plugins_path - 플러그인 엔진의 위치, 리턴값 : 0 - 성공
    def init(self, plugins_path, verbose=False):  # 플러그인 엔진 초기화
        return 0  # 플러그인 엔진 초기화 성공

    # 플러그인 엔진을 종료 (리턴값 0이면 성공)
    def uninit(self):  # 플러그인 엔진 종료
        return 0  # 플러그인 엔진 종료 성공

    # 악성코드를 검사
    # 입력값 : filehandle  - 파일 핸들, filename    - 파일 이름
    # 리턴값 : (악성코드 발견 여부, 악성코드 이름, 악성코드 ID) 등등
    def detect(self, filehandle, filename):  # 악성코드 검사
        try:
            fh = filehandle
            size = os.path.getsize(filename)  # 검사 대상 파일 크기를 구하기

            if size == 66:  # EICAR Test 악성코드의 크기와 일치하는가?
                # 크기가 일치한다면 MD5 해시 계산
                fmd5 = cryptolib.md5(fh[:68])

                # 파일에서 얻은 해시 값과 EICAR Test 악성코드의 해시 값이 일치하는가?
                if fmd5 == '7472f5fddfd0d4218ec5d57aa39c9b19':
                    return True, 'EICAR-Test-File', 0
        except IOError:
            pass

        # 악성코드를 발견하지 못했음을 리턴하도록
        return False, '', -1

    # 악성코드를 치료
    def treat(self, filename, virus_id):  # 악성코드 치료
        try:
            # 악성코드 진단 결과에서 받은 ID 값이 0인가?
            if virus_id == 0:
                os.remove(filename)  # 파일 삭제
                return True  # 치료 완료 리턴
        except IOError:
            pass

        return False  # 치료 실패 리턴

    def virus_list(self):  # 진단 가능한 악성코드 리스트
        list_view = list()  # 리스트형 변수 선언

        list_view.append('EICAR-Test-File')  # 진단/치료하는 악성코드 이름 등록

        return list_view

    # getinfo(self)
    def getinfo(self):
        info = dict()

        info['author'] = 'Cloudbread'  #구름빵 제작자
        info['version'] = '0,0'  # 첫번째 버전
        info['engine_info'] = 'EICAR Scan Engine'  # 엔진 설명
        info['engine_name'] = 'eicar'  # 엔진 파일 이름
        info['virus_num'] = 1  # 진단/치료 가능한 악성코드 수

        return info