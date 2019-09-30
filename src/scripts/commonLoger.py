
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# (c) 2018, Huawei.
# Author: xueweihong
# Date: 20180417
# This file is 
# part of Ansible
import logging
import logging.handlers as handlers

def ansibleGetLoger(logFile,reportFile,loggerName):

    LOG_FILE = logFile
    REPORT_FILE = reportFile

    log_hander = handlers.RotatingFileHandler(LOG_FILE,maxBytes = 1024*1024,backupCount = 5)
    fmt = logging.Formatter("[%(asctime)s %(levelname)s ] (%(filename)s:%(lineno)d)- %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
    log_hander.setFormatter(fmt)
    log = logging.getLogger(loggerName)
    log.addHandler(log_hander)
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("[%(asctime)s %(levelname)s ] (%(filename)s:%(lineno)d)- %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
    report_hander = handlers.RotatingFileHandler(REPORT_FILE,maxBytes = 1024*1024,backupCount = 5)
    report_hander.setFormatter(fmt)
    report = logging.getLogger(loggerName+"reprot")
    report.addHandler(report_hander)
    report.setLevel(logging.INFO)
    return log, report 
