#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from os import walk
import yara

def yara_match_from_file(fileyara, filename):
# 파일에서 yara 인지 확인하는 함수
# matches 딕셔러니
	matches = []
	rules = yara.compile(fileyara)
	# fileyara ==  /home/test/peframe/peframe/signatures/yara_plugins/pe/antidebug_antivm.yar
	# fileyara ==  /home/test/peframe/peframe/modules/../signatures/yara_plugins/pe/peid.yara
	# fileyara ==  /home/test/peframe/peframe/modules/../signatures/yara_plugins/pe/crypto_signatures.yar

	# serialize matches
# rules.match(filename)안에 match 만큼 반복실행하여 예외 발생시 처리하지않고 회피 matches 반환
# matches에 문자열 match 객체 추가
# return matches, type : str
# filename == /home/test/peframe/akrien.bin
	try:
		for match in rules.match(filename):
			matches.append(str(match))
	except: # fix yara.Error: internal error: 30
		pass

	return matches
'''
matches == 
['Xor', 'disable_dep', 'keylogger']
['Microsoft_Visual_Studio_NET', 
'Microsoft_Visual_C_v70_Basic_NET_additional',
'Microsoft_Visual_C_Basic_NET', 'Microsoft_Visual_Studio_NET_additional',
'Microsoft_Visual_C_v70_Basic_NET', 'NET_executable_', 'NET_executable']
,['Big_Numbers1']
'''

def yara_match_from_folder(folder_yara, filename, exclude=[]):
	matches = []
	# 파일에서 yara인지 확인하는 함수
	# matches 딕셔너리
	#foler_yara ==  /home/test/peframe/peframe/signatures/yara_plugins/pe
	#for fileyara in yara_files:
	for (dirpath, dirnames, filenames) in walk(folder_yara): 
		for f in filenames: 
			if str(f).endswith('.yar') and str(f) not in exclude: # 문자열f.yar 확장자이고 
				path_to_file_yara = str(dirpath)+os.sep+str(f) 

				try: 
					rules = yara.compile(path_to_file_yara)
					
					# serialize matches
					#filename ==  /home/test/peframe/akrien.bin
					# rules.match안에 match 만큼 반복실행하는데 60초이상 침묵하는 작업은 종료
					# 예외 발생시 처리하지 않고 회피 matches 반환
					# matches에 문자열f안에 문자열match 객체를 추가
					# return matches, type : str
					for match in rules.match(filename, timeout=60):
						matches.append({f: str(match)}) 
				except: 
					pass 


	return matches
'''
matches == 
[{'crypto_signatures.yar': 'Big_Numbers1'}, 
{'packer.yar': 'NETexecutableMicrosoft'}, 
{'packer_compiler_signatures.yar': 'IsPE32'}, 
{'packer_compiler_signatures.yar': 'IsNET_EXE'}, 
{'packer_compiler_signatures.yar': 'IsWindowsGUI'}]
'''
