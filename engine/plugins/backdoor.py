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

            if size == 7168:  # 각각 backdoor 악성코드의 크기와 일치하는가?
                # 크기가 일치한다면 MD5 해시 계산
                fmd5 = cryptolib.md5(mm[:7168])
                if fmd5 == 'd537acb8f56a1ce206bc35cf8ff959c0':
                    return True, 'BACKDOOR-File (include virus)', 0

            elif size == 134085:
                fmd5 = cryptolib.md5(mm[:134085])
                if fmd5 == '1a9fd80174aafecd9a52fd908cb82637':
                    return True, 'BACKDOOR-File (include virus)', 0 #13

            elif size == 100352:
                fmd5 = cryptolib.md5(mm[:100352])
                if fmd5 == '46c8a7e3b93e8b1e362bbab119c95ed1':
                    return True, 'BACKDOOR-File (include virus)', 0
                elif fmd5 == 'b044089d514ee658dfb938c1c77bd1e0':
                    return True, 'BACKDOOR-File (include virus)', 0

            elif size == 134160:
                fmd5 = cryptolib.md5(mm[:134160])
                if fmd5 == 'd98b63a319ad92b6c3a8347ade5a351a':
                    return True, 'BACKDOOR-File (include virus)', 0 #34

            elif size == 17220:
                fmd5 = cryptolib.md5(mm[:17220])
                if fmd5 == '444313c2fa923927a1b9120ffe690501':
                    return True, 'BACKDOOR-File (include virus)', 0

            elif size == 114688:
                fmd5 = cryptolib.md5(mm[:114688])
                if fmd5 == 'e6b9780aa0076e7b5c589a421590f780':
                    return True, 'BACKDOOR-File (include virus)', 0

            elif size == 12288:
                fmd5 = cryptolib.md5(mm[:12288])
                if fmd5 == '9d80a9cd90fd9e2597737c2914fce4c3':
                    return True, 'BACKDOOR-File (include virus)', 0

            elif size == 163328:
                fmd5 = cryptolib.md5(mm[:163328])
                if fmd5 == '941a4af08696e12d1428f572db3805b9':
                    return True, 'BACKDOOR-File (include virus)', 0

            elif size == 29385:
                fmd5 = cryptolib.md5(mm[:29385])
                if fmd5 == 'c972940fd75736d4c58c87c7a32fec6c':
                    return True, 'BACKDOOR-File (include virus)', 0

            elif size == 8582:
                fmd5 = cryptolib.md5(mm[:8582])
                if fmd5 == '8621eee262a53875551947fd692573ae':
                    return True, 'BACKDOOR-File (include virus)', 0

            elif size == 32472:
                fmd5 = cryptolib.md5(mm[:32472])
                if fmd5 == 'd87e582cb137040b19b42f1af1a57c0a':
                    return True, 'BACKDOOR-File (include virus)', 0

            elif size == 3850:
                fmd5 = cryptolib.md5(mm[:3850])
                if fmd5 == '0a0ff8caa49a727f54c01ed8a471d155':
                    return True, 'BACKDOOR-File (include virus)', 0

            elif size == 49424:
                fmd5 = cryptolib.md5(mm[:49424])
                if fmd5 == '10c16804ece2fc3d5bbc773b4d8c23bb':
                    return True, 'BACKDOOR-File (include virus)', 0

            elif size == 59384:
                fmd5 = cryptolib.md5(mm[:59384])
                if fmd5 == 'f8e7c3f2269f859afd3efe6dd53219d6':
                    return True, 'BACKDOOR-File (include virus)', 0

            elif size == 63370:
                fmd5 = cryptolib.md5(mm[:63370])
                if fmd5 == '8af74607bf2cd75c6f1563d0cdd65375':
                    return True, 'BACKDOOR-File (include virus)', 0 # 69

            elif size == 45072:
                fmd5 = cryptolib.md5(mm[:45072])
                if fmd5 == '10b0a636676a64c463c155c13872a532':
                    return True, 'BACKDOOR-File (include virus)', 0 # 70

            elif size == 663552:
                fmd5 = cryptolib.md5(mm[:663552])
                if fmd5 == '62527b8acdd31b362830516e7ac5eeb6':
                    return True, 'BACKDOOR-File (include virus)', 0

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

        list_view.append('BACKDOOR-File (include virus)')  # 진단/치료하는 악성코드 이름 등록

        return list_view

    # getinfo(self)
    def getinfo(self):
        info = dict()

        info['author'] = 'Cloudbread'  #구름빵 제작자
        info['version'] = '0,0'  # 첫번째 버전
        info['engine_info'] = 'BACKDOOR Scan Engine'  # 엔진 설명
        info['engine_name'] = 'backdoor'  # 엔진 파일 이름
        info['virus_num'] = 1  # 진단/치료 가능한 악성코드 수

        return info