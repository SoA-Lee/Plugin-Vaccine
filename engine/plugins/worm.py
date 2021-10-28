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
            mm = filehandle
            size = os.path.getsize(filename)  # 검사 대상 파일 크기를 구한다.

            if size == 12288:  # worm 악성코드의 크기와 일치하는가?
                # 크기가 일치한다면 MD5 해시 계산
                fmd5 = cryptolib.md5(mm[:12288])
                if fmd5 == '68eaaa29813d706f4024af83cf3b88dc':
                    return True, 'WORM-File (include virus)', 0

            elif size == 212992:
                fmd5 = cryptolib.md5(mm[:212992])
                if fmd5 == '6cd64807c0da88b56f0558969f2109ae':
                    return True, 'WORM-File (include virus)', 0
                elif fmd5 == '72a8d65d890c33b6d818cbf037efe7e5':
                    return True, 'WORM-File (include virus)', 0
                elif fmd5 == '815d1984d5805aa5aa432c537028b217':
                    return True, 'WORM-File (include virus)', 0
                elif fmd5 == 'fad07f2010b70dfbe3f3dd146bad21c0':
                    return True, 'WORM-File (include virus)', 0

            elif size == 225280:
                fmd5 = cryptolib.md5(mm[:225280])
                if fmd5 == '879b59f09f034a9dd566bf9bd7129ae2':
                    return True, 'WORM-File (include virus)', 0

            elif size == 229376:
                fmd5 = cryptolib.md5(mm[:229376])
                if fmd5 == '80aa688bc950084b0b97719c089dc331':
                    return True, 'WORM-File (include virus)', 0
                elif fmd5 == '1b7f0ec2a284e4e8a050bb6f3cd1b6fe':
                    return True, 'WORM-File (include virus)', 0

            elif size == 32768:
                fmd5 = cryptolib.md5(mm[:32768])
                if fmd5 == '66c1e0d5415296e7f4e6db253f881cb9':
                    return True, 'WORM-File (include virus)', 0

            elif size == 73728:
                fmd5 = cryptolib.md5(mm[:73728])
                if fmd5 == '0bd29c711f3ec44f297a9bce03a0acd9':
                    return True, 'WORM-File (include virus)', 0
                elif fmd5 == '1af1ca9b7c47e20d8e1688ae25ed236e':
                    return True, 'WORM-File (include virus)', 0
                elif fmd5 == '2d9ce0fcd930b533d51c13e7416c1b6a':
                    return True, 'WORM-File (include virus)', 0
                elif fmd5 == 'eff70ce17295e5478a1685f7a4131f4d':
                    return True, 'WORM-File (include virus)', 0

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

        list_view.append('WORM-File (include virus)')  # 진단/치료하는 악성코드 이름 등록

        return list_view

    # getinfo(self)
    def getinfo(self):
        info = dict()

        info['author'] = 'Cloudbread'  #구름빵 제작자
        info['version'] = '0,0'  # 첫번째 버전
        info['engine_info'] = 'Worm Scan Engine'  # 엔진 설명
        info['engine_name'] = 'worm'  # 엔진 파일 이름
        info['virus_num'] = 1  # 진단/치료 가능한 악성코드 수

        return info