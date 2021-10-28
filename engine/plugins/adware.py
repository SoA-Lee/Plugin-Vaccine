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

            if size == 45439:  # 각각의 ADWARE 악성코드의 크기와 일치하는가?
                # 크기가 일치한다면 MD5 해시 계산
                fmd5 = cryptolib.md5(mm[:45439])
                if fmd5 == '7fb1ecf58d513b2ff055473b0140d25d':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 35926:
                fmd5 = cryptolib.md5(mm[:35926])
                if fmd5 == '568caef19cc4c09d3f329c079c6d3d04':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 40544:
                fmd5 = cryptolib.md5(mm[:40544])
                if fmd5 == '609eebbb9a4ef06212ffb542fc845470':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 11114:
                fmd5 = cryptolib.md5(mm[:11114])
                if fmd5 == '6a2b6376739275f247865e7dcd023b9d':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 46405:
                fmd5 = cryptolib.md5(mm[:46405])
                if fmd5 == '45b597226f041a9cf907e8c9c9f31130':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 8701:
                fmd5 = cryptolib.md5(mm[:8701])
                if fmd5 == 'fd21217fb0a3319e7da21dcb9140a42e':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 26295:
                fmd5 = cryptolib.md5(mm[:26295])
                if fmd5 == 'b76686c7ddb01600687703e62bf6ab2c':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 45896:
                fmd5 = cryptolib.md5(mm[:45896])
                if fmd5 == '48b3281ea7708e4c3c20c2e1dd644816':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 60491:
                fmd5 = cryptolib.md5(mm[:60491])
                if fmd5 == '4bece35da4f67b5e2e04e683d24286a6':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 54714:
                fmd5 = cryptolib.md5(mm[:54714])
                if fmd5 == 'bad5b9be331763129ff50c72d884c18e':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 52678:
                fmd5 = cryptolib.md5(mm[:52678])
                if fmd5 == 'c6cd9dbfc20f70f02f4b9b688a5618dc':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 26817:
                fmd5 = cryptolib.md5(mm[:26817])
                if fmd5 == 'c1685ab953a5d7c1ccc153b3d212737b':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 14134:
                fmd5 = cryptolib.md5(mm[:14134])
                if fmd5 == '36376f330e4c61554ad10d1d7100fb93':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 54729:
                fmd5 = cryptolib.md5(mm[:54729])
                if fmd5 == 'c9d5fd4ef5749d6f560afc8324df182e':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 23454:
                fmd5 = cryptolib.md5(mm[:23454])
                if fmd5 == '9e5ba86eb2fe1fff6883cf5b543fdcf9':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 48922:
                fmd5 = cryptolib.md5(mm[:48922])
                if fmd5 == '1abfa64915c7db20a04a1a525df85faa':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 11160:
                fmd5 = cryptolib.md5(mm[:11160])
                if fmd5 == '982be29451bc996fa3078a18732890be':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 52586:
                fmd5 = cryptolib.md5(mm[:52586])
                if fmd5 == '6acdd5dc002dff544a6c8437bcd641b3':
                    return True, 'ADWARE-File (include virus)', 0

            elif size == 43290:
                fmd5 = cryptolib.md5(mm[:43290])
                if fmd5 == '1aa9bdb1d3b47f7e64081f927ae36201':
                    return True, 'ADWARE-File (include virus)', 0  # 71

            elif size == 49392:
                fmd5 = cryptolib.md5(mm[:49392])
                if fmd5 == 'f0c057bfa735defed741530f232e699b':
                    return True, 'ADWARE-File (include virus)', 0  # 73

            elif size == 24576:
                fmd5 = cryptolib.md5(mm[:24576])
                if fmd5 == '22bc4edc448dd7e6f0e0ded095b44287':
                    return True, 'ADWARE-File (include virus)', 0

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

        list_view.append('ADWARE-File (include virus)')  # 진단/치료하는 악성코드 이름 등록

        return list_view

    # getinfo(self)
    def getinfo(self):
        info = dict()

        info['author'] = 'Cloudbread'  #구름빵 제작자
        info['version'] = '0,0'  # 첫번째 버전
        info['engine_info'] = 'ADWARE Scan Engine'  # 엔진 설명
        info['engine_name'] = 'adware'  # 엔진 파일 이름
        info['virus_num'] = 1  # 진단/치료 가능한 악성코드 수

        return info