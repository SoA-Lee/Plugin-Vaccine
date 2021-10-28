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

            if size == 49152:
                fmd5 = cryptolib.md5(mm[:49152])
                if fmd5 == '1f9775ed5d105b4d86b67deed9c5cf62':
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 16384:
                fmd5 = cryptolib.md5(mm[:16384])
                if fmd5 == '7bbc691f7e87f0986a1030785268f190':  # 19
                    return True, 'TROJAN-CLICKER-File (include virus)', 0
                elif fmd5 == 'bd62dab79881bc6ec0f6be4eef1075bc':  # 17
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '5004fee79f03df0d1d8f3ac527a5c046':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == 'bfadb08f07304b6b293707e4f9c9f1a9':
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 4752:  # trojan 악성코드의 크기와 일치하는가?
                # 크기가 일치한다면 MD5 해시 계산
                fmd5 = cryptolib.md5(mm[:4752])
                if fmd5 == '9c5c27494c28ed0b14853b346b113145':
                    return True, 'TROJAN-CLICKER-File (include virus)', 0

            elif size == 36864:
                fmd5 = cryptolib.md5(mm[:36864])
                if fmd5 == '625ac05fd47adc3c63700c3b30de79ab':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == 'a90b5a068ef610c44f07abeddab37d2a':  # 27
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '3612702fb6e5c1f756c116d9fce34677':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '6bdc203bdfbb3fd263dadf1653d52039':
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 24065:
                fmd5 = cryptolib.md5(mm[:24065])
                if fmd5 == '84882c9d43e23d63b82004fae74ebb61':
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 53248:
                fmd5 = cryptolib.md5(mm[:53248])
                if fmd5 == 'e2bf42217a67e46433da8b6f4507219e':
                    return True, 'TROJAN-HIJACK-File (include virus)', 0

            elif size == 61440:
                fmd5 = cryptolib.md5(mm[:61440])
                if fmd5 == 'b94af4a4d4af6eac81fc135abda1c40c':  # 12
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '7faafc7e4a5c736ebfee6abbbc812d80':  # 30
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 40960:
                fmd5 = cryptolib.md5(mm[:40960])
                if fmd5 == '6abde2f83015f066385d27cff6143c44':  # 14
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == 'c0b54534e188e1392f28d17faff3d454':  # 15
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '3f8e2b945deba235fa4888682bd0d640':  # 16
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '21be74dfafdacaaab1c8d836e2186a69':  # 17
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '88abae59e3b1cf07bef2feb1efee0324':  # 41
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 24576:
                fmd5 = cryptolib.md5(mm[:24576])
                if fmd5 == 'c04fd8d9198095192e7d55345966da2e':  # 12
                    return True, 'TROJAN-CLICKER-File (include virus)', 0
                elif fmd5 == '251f4d0caf6eadae453488f9c9c0ea95':  # 17
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == 'af748b94356437b111636000698b47cc':  # 45
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 163840:
                fmd5 = cryptolib.md5(mm[:163840])
                if fmd5 == '290934c61de9176ad682ffdd65f0a669':  # 19
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 31744:
                fmd5 = cryptolib.md5(mm[:31744])
                if fmd5 == '04d8d045f2f6abf974f3531e5345ab5d':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '40e796fc762638e35e7e7f9f9a1693a2':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '5afceb121e7d0d67f0dc31e672548343':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '63d13a51b8708d6b0f5957cf901fb698':
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 49152:
                fmd5 = cryptolib.md5(mm[:49152])
                if fmd5 == '1f9775ed5d105b4d86b67deed9c5cf62':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '7c1390fa90437c0274e91926e349005d':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == 'c92179f08502f24ad383efd41c16ff6c':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '95e15c04a8448a11490a4c02ca975acd':
                    return True, 'TROJAN-RISKWARE-File (include virus)', 0

            elif size == 238592:
                fmd5 = cryptolib.md5(mm[:238592])
                if fmd5 == '14e09dd02d9c3ce15fa98e8099f9bde5':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '353540c8ca92a659cbc687f387c798d9':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '35754a1ff82e3732dd4b44cfac07685c':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '39b2606db1c39ecabe1c3b8f7dafbaff':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '3b00555eeb97a042f892f3ed61ac874a':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '558d9fb1ee8a1fa0049a6c16dd4ff7da':
                    return True, 'TROJAN-File (include virus)', 0
                elif fmd5 == '695f1ddb808093b910453cc6327f5c87':
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 45056:
                fmd5 = cryptolib.md5(mm[:45056])
                if fmd5 == '7a2e485d1bea00ee5907e4cc02cb2552':  # 32
                    return True, 'TROJAN-SPY-File (include virus)', 0

            elif size == 8240:
                fmd5 = cryptolib.md5(mm[:8240])
                if fmd5 == '6ecdc18c99934b6185088a07319eeec9':  # 36
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 13824:
                fmd5 = cryptolib.md5(mm[:13824])
                if fmd5 == '9035bed8ee6dc82b04ab1119a221974d':  # 37
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 30720:
                fmd5 = cryptolib.md5(mm[:30720])
                if fmd5 == '1f92cb5516616e8db3777e7a0458f3d1':
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 50690:
                fmd5 = cryptolib.md5(mm[:50690])
                if fmd5 == 'dfefb413804000372dcda10bc0e07965':
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 802:
                fmd5 = cryptolib.md5(mm[:802])
                if fmd5 == 'bce75b4f91ef780c1629371e3334505e':
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 32768:
                fmd5 = cryptolib.md5(mm[:32768])
                if fmd5 == 'c277798eb447730580ad21ea647b9d36':
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 176128:
                fmd5 = cryptolib.md5(mm[:176128])
                if fmd5 == '986c463587ff681a30d7c75256745e99':  # 47
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 25918:
                fmd5 = cryptolib.md5(mm[:176128])
                if fmd5 == '3e65adad852b52427ab1dae5c058d3a3':
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 61070:
                fmd5 = cryptolib.md5(mm[:61070])
                if fmd5 == '3e65adad852b52427ab1dae5c058d3a3':
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 61536:
                fmd5 = cryptolib.md5(mm[:61536])
                if fmd5 == '60f073f64c635bb6f56015175e087518':  # 67
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 10838:
                fmd5 = cryptolib.md5(mm[:10838])
                if fmd5 == '562ae1f4c72690a48bb6d28fb5e100ea':  # 68
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 47370:
                fmd5 = cryptolib.md5(mm[:47370])
                if fmd5 == '0ab97bd0b6dcefda7d0b380c60867f0f':  # 72
                    return True, 'TROJAN-File (include virus)', 0

            elif size == 52892:
                fmd5 = cryptolib.md5(mm[:52892])
                if fmd5 == '9cce4f94b7bcd53682a4c29f1420f49':  # 74
                    return True, 'TROJAN-File (include virus)', 0

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

        list_view.append('TROJAN-File (include virus)')  # 진단/치료하는 악성코드 이름 등록

        return list_view

    # getinfo(self)
    def getinfo(self):
        info = dict()

        info['author'] = 'Cloudbread'  #구름빵 제작자
        info['version'] = '0,0'  # 첫번째 버전
        info['engine_info'] = 'TROJAN Scan Engine'  # 엔진 설명
        info['engine_name'] = 'trojan'  # 엔진 파일 이름
        info['virus_num'] = 1  # 진단/치료 가능한 악성코드 수

        return info