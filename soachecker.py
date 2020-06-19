# rschmutz@netlabs.ch
# -*- coding: utf-8 -*-

import dns.resolver
import time
import sys
from pygtail import Pygtail
import ipaddress
import re

import configparser
import logging
import logging.handlers
import json

import threading
import queue
import time

import sysconfig

###
# CONFIG

config = configparser.ConfigParser()
config.read("soachecker.conf")

local_nets = [ ipaddress.ip_network(x) for x in json.loads(config["soachecker"]["local_nets"]) ]
stop_list = [ re.compile(x) for x in json.loads(config["soachecker"]["stop_list"]) ]
cache_clean_interval = int(config["soachecker"]["cache_clean_interval"])
resolver_timeout = float(config["soachecker"]["resolver_timeout"])
resolver_lifetime = float(config["soachecker"]["resolver_lifetime"])
input_log_file = config["soachecker"]["input_log_file"] 
input_type = config["soachecker"]["input_type"]
num_workers = int(config["soachecker"]["num_workers"])

trigger_query_types = json.loads(config["soachecker"]["trigger_query_types"])

maxlines = int(config["soachecker"]["maxlines"])
input_skip_re = re.compile(config["soachecker"]["input_skip_re"])

pygtail_offset_file = config["soachecker"]["pygtail_offset_file"]


###
# LOGGING

logger = logging.getLogger('soachecker')
logger.setLevel(logging.INFO)

os = sysconfig.get_platform()
log_device = '/dev/log'
if re.match('^macosx', os):
    log_device = '/var/run/syslog'
elif re.match('^freebsd', os):
    log_device = '/var/run/log'
elif re.match('^linux', os):
    log_device = '/dev/log'
   
handler = logging.handlers.SysLogHandler(address = log_device)
logger.addHandler(handler)



###
# Threading Definitions

class WorkerPool:
    def __init__(self, worker_func=None, collector_func=None, report_func=None, report_interval=2, numworkers=10):
        self.numworkers = numworkers
        self.worker_func = worker_func
        self.collector_func = collector_func
        self.report_func = report_func
        self.report_interval = report_interval
        self.request_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.exit_flag = False
        self.exit_flag_collector = False
        self.workers = []
    
    def status_timer(self):
        if self.report_interval != None:
            if not self.exit_flag:
                self.report()
                self.timer = threading.Timer(self.report_interval, self.status_timer)
                self.timer.start()
            else:
                self.timer.cancel()
    
    def collector(self):
        while not self.exit_flag_collector:
            try:
                element = self.result_queue.get(timeout=1)
            except:
                element = None
            if element != None:
                self.collector_func(element)
    
    def report(self):
        logger.info("request_qsize=%d, result_qsize=%d, workers=%d \n", self.request_queue.qsize(), self.result_queue.qsize(), threading.active_count())
        if self.report_func != None:
            report = self.report_func()
            print(report)
            logger.info(report)

    def start(self):
        self.status_timer()
        if self.collector_func != None:
            self.collector = threading.Thread(target=self.collector)
            self.collector.start()
        for worker in range(self.numworkers):
            wt = threading.Thread(target=self.run)
            self.workers.append(wt)
            wt.start()
    
    def run(self):
        while not self.exit_flag:
            try:
                element = self.request_queue.get(timeout=1)
            except:
                element = None
            if element != None:
                self.result_queue.put(self.worker_func(element))
                self.request_queue.task_done()
    
    def stop(self):
        self.exit_flag = True
        for worker in self.workers:
            worker.join(10)
        print("all workers stopped, request_qsize={}, result_qsize={}".format(self.request_queue.qsize(), self.result_queue.qsize()))
        if self.collector_func != None:
            for i in range(30):
                print("wait for collector to process result_queue size={}".format(self.result_queue.qsize()))
                time.sleep(1)
                if self.result_queue.empty():
                    break
            if not self.result_queue.empty():
                print("kill collector anyway, result_queue size={}".format(self.result_queue.qsize()))
                while not self.result_queue.empty():
                    self.result_queue.get(block=False)
            self.collector.join(10)
        print("all threads stopped, done")
    
    def put_task(self, element):
        self.request_queue.put(element)


###
# State/Counters

counter = { 'processed':0, 'requests':0, 'reqfails':0, 'cachesize':0, 'cachehits':0, 'cachemisses':0, 'cacheexpires':0 }
cache = {}
answers = []
resolver = dns.resolver.Resolver()
resolver.timeout = resolver_timeout
resolver.lifetime = resolver_lifetime

cache_lock = threading.Lock()



###
# Callbacks

def manage_cache(element):
    (key, ttl) = element
    cache_lock.acquire()
    cache[key] = ttl
    cache_lock.release()


def fetch_soa(query):
   query = query.lower()

   for rex in stop_list:
      if rex.search(query):
         return None

   if query in cache:
      counter['cachehits'] = counter['cachehits']+1
      if time.time() < cache[key]:
         return None
      else:
         counter['cacheexpires'] = counter['cacheexpires']+1
         counter['cachesize'] = counter['cachesize']-1
         # TODO: in manage_cache(): del cache[key]
         #print("   {} in cache (expired), deleting from cache".format(key))
   else:
      counter['cachemisses'] = counter['cachemisses']+1
   counter['requests'] = counter['requests']+1
   try:
      zone = dns.resolver.zone_for_name(query)
      soa = (dns.resolver.query(zone, rdtype="SOA"))[0]
      logger.debug(soa.to_text())

      # cache[query] = answers.rrset.ttl + time.time()
      counter['cachesize'] = counter['cachesize']+1
      return (query, soa.ttl + time.time())
   except:
      counter['reqfails'] = counter['reqfails']+1
   return None

def cleanup_cache():
   now = time.time()
   cache =  { key:expires for key,expires in cache.items() if expires<now }

def report_stats():
    return str(counter)


###
# Helpers

def is_local_ip(ip):
   if type(ip)==str:
      ip = ipaddress.ip_address(ip)
   local_ip = False
   for src_net in local_nets:
      if ip in src_net:
         local_ip = True
         break
   return local_ip



###################
# MAIN
# __main__
linecount = 0

wp = WorkerPool(worker_func=fetch_soa, collector_func=manage_cache, report_func=report_stats, numworkers=num_workers)
wp.start()

for line in Pygtail(input_log_file, offset_file=pygtail_offset_file):
   if input_skip_re.match(line):
       continue
   if input_type == "passivedns":
      # 1591308018.468719||194.41.152.136||144.76.2.9||IN||mail.putar.ch.||A||85.10.194.107||600||1
      (ts, client_ip, server_ip, qclass, query, qtype, answer, ttl, whut) = line.split("||")
   elif (input_type == "bro") or (input_type == "zeek"):
      #fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   trans_id        rtt     query   qclass  qclass_name     qtype   qtype_name      rcode   rcode_name      AA      TC      RD      RA      Z       answers TTLs    rejected
      #types  time    string  addr    port    addr    port    enum    count   interval        string  count   string  count   string  count   string  bool    bool    bool    bool    count   vector[string]  vector[interval]        bool
      (ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto, trans_id, rtt, query, qclass, qclass_name, qtype, qtype_name, rcode, rcode_name, AA, TC, RD, RA, Z, answers, TTLs, rejected) = line.split("\t")
      (qtype, client_ip, query) = (qtype_name, id_orig_h, query)
   else:
       raise NotImplementedError("input_type \"{}\" not supported in conf".format(input_type))
   if qtype in trigger_query_types:
      if is_local_ip(client_ip):
         linecount = linecount+1
         if linecount > maxlines:
            break
         wp.put_task(query)
         counter['processed'] = counter['processed']+1
time.sleep(30)

wp.stop()


