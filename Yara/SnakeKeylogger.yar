rule Snake_MS_Timestamp {
   meta:
      description = "Detects Snake Keylogger"
      author = "modernathena"
      reference = "https://github.com/modernathena/malpedia"
      date = "2022-03-26"
   strings:
       $timestamp = "20210703003832Z"
   condition:
      any of them
}

rule Snake_Token {
   meta:
      description = "Detects Snake Keylogger"
      author = "modernathena"
      reference = "https://github.com/modernathena/malpedia"
      date = "2022-03-26"
   strings:
       $token1 = "b03f5f7f11d50a3a"
       $token2 = "b77a5c561934e089"
   condition:
      any of them
}

rule Snake_Filename {
   meta:
      description = "Detects Snake Keylogger"
      author = "modernathena"
      reference = "https://github.com/modernathena/malpedia"
      date = "2022-03-26"
   strings:
       $file1 = "RYJGJHJDGHR.pdb"
       $file2 = "RYJGJHJDGHR.exe"
   condition:
      any of them
}

rule Snake_CompilationDate {
   meta:
      description = "Detects Snake Keylogger"
      author = "modernathena"
      reference = "https://github.com/modernathena/malpedia"
      date = "2022-03-26"
   strings:
       $date = "2082-Jun-13 01:31:14"
   condition:
      any of them
}