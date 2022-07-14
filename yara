#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from os import walk
import yara

def yara_match_from_file(fileyara, filename): # yara_match_from_file함수 매개변수 (fileyara, filename)
	matches = []  # 리스트
	rules = yara.compile(fileyara) # rules 파일 컴파일

	# serialize matches ,예외 처리
	try:
		for match in rules.match(filename): # rules.match(filename) 요소들 match에 대입
			matches.append(str(match)) # matches에 문자열 match 객체로 추가
	except: # fix yara.Error: internal error: 30 ,오류 종류 상관없이 오류가 발생하면 수행
		pass # 예외 처리하지않고 회피

	return matches # matches로 반환

def yara_match_from_folder(folder_yara, filename, exclude=[]): # yara_match_from_folder 함수 매개변수 (folder_yara, filename, exclude=[])
	matches = [] # 리스트
	#for fileyara in yara_files:
	for (dirpath, dirnames, filenames) in walk(folder_yara): # walk(folder_yara) 요소들 (dirpath, dirnames, filenames)에 대입
		for f in filenames: # filenames 요소들 f에 대입
			if str(f).endswith('.yar') and str(f) not in exclude: # 문자열(f).yar 확장자이고 exclude안에 없을때
				path_to_file_yara = str(dirpath)+os.sep+str(f) # path_to_file_yara = 문자열(dirpath)\\문자열(f)

				try: # 예외처리
					rules = yara.compile(path_to_file_yara) # rules 파일 컴파일
					
					# serialize matches
					for match in rules.match(filename, timeout=60): # rules.match(filename) 요소들 match에 대입, 60초 이상 침묵하는 작업자는 종료후 다시 시작
						matches.append({f: str(match)}) # matches 에 f안에 문자열(match) 객체로 추가
				except: # 오류 종류 상관없이 오류가 발생하면 수행
					pass # 예외로 처리하지 않고 회피


	return matches # matches로 변환
