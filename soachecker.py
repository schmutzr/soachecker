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

# CONFIG
config = configparser.ConfigParser()
config.read("soachecker.conf")

local_nets = [ ipaddress.ip_network(x) for x in json.loads(config["soachecker"]["local_nets"]) ]
stop_list = [ re.compile(x) for x in json.loads(config["soachecker"]["stop_list"]) ]
cache_clean_interval = config["soachecker"]["cache_clean_interval"]
resolver_timeout = config["soachecker"]["resolver_timeout"]
resolver_lifetime = config["soachecker"]["resolver_lifetime"]
passivedns_log_file = config["soachecker"]["passivedns_log_file"] 
passivedns_separator = config["soachecker"]["passivedns_separator"]
passivedns_separator = "\t"

trigger_query_types = json.loads(config["soachecker"]["trigger_query_types"])

maxlines = int(config["soachecker"]["maxlines"])
passivedns_skip_re = re.compile(config["soachecker"]["passivedns_skip_re"])


# LOGGING
logger = logging.getLogger('soachecker')
logger.setLevel(logging.INFO)
handler = logging.handlers.SysLogHandler(address = '/var/run/syslog')
logger.addHandler(handler)



## for testing only
#import random

#def worker_func(element):
#    time.sleep(random.random()) # Testing only
#    return(element)
#    
#def collector_func(element):
#    time.sleep(random.random()/2) # Testing only
#    print(element)
    
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
        print("request_qsize={}, result_qsize={}, workers={} \n".format(self.request_queue.qsize(), self.result_queue.qsize(), threading.active_count()))
        logger.info("request_qsize=%d, result_qsize=%d, workers=%d \n", self.request_queue.qsize(), self.result_queue.qsize(), threading.active_count())
        if self.report_func != None:
            self.report_func()

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
        


# 1591349380.347551||2001:1700:a02:8::12||2a00:17c8::200||IN||aUToDisCovER.PoSt.ch.||CNAME||outlook.post.ch.||3600||1

counter = { 'processed':0, 'requests':0, 'reqfails':0, 'cachesize':0, 'cachehits':0, 'cachemisses':0, 'cacheexpires':0 }
cache = {}
answers = []
resolver = dns.resolver.Resolver()
resolver.timeout = resolver_timeout
resolver.lifetime = resolver_lifetime

cache_lock = threading.Lock()

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

   query = query.split(".")
   while len(query)>1 :
      try:
         key = ".".join(query)
         if key in cache:
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
         answers = resolver.query(key, "SOA")
         # cache[key] = answers.rrset.ttl + time.time()
         counter['cachesize'] = counter['cachesize']+1
         return (key, answers.rrset.ttl + time.time())
      except:
         counter['reqfails'] = counter['reqfails']+1
      query.pop(0)
   return None





def is_local_ip(ip):
   if type(ip)==str:
      ip = ipaddress.ip_address(ip)
   local_ip = False
   for src_net in local_nets:
      if ip in src_net:
         local_ip = True
         break
   return local_ip


def cleanup_cache():
   now = time.time()
   cache =  { key:expires for key,expires in cache.items() if expires<now }

def report_stats():
    print(counter)
#    for key in counter:
#       print("\t{}:\t{}".format(key, counter[key]))

# __main__
linecount = 0

wp = WorkerPool(worker_func=fetch_soa, collector_func=manage_cache, report_func=report_stats, numworkers=300)
wp.start()

# bro/zeek dns.log format:
#fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   trans_id        rtt     query   qclass  qclass_name     qtype   qtype_name      rcode   rcode_name      AA      TC      RD      RA      Z       answers TTLs    rejected
#types  time    string  addr    port    addr    port    enum    count   interval        string  count   string  count   string  count   string  bool    bool    bool    bool    count   vector[string]  vector[interval]        bool

for line in Pygtail(passivedns_log_file, offset_file="pygtail.offset"):
   if passivedns_skip_re.match(line):
       continue
   #(timestamp, client_ip, server_ip, qclass, query, qtype, answer, ttl, whut) = line.split(passivedns_separator)
   (ts, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto, trans_id, rtt, query, qclass, qclass_name, qtype, qtype_name, rcode, rcode_name, AA, TC, RD, RA, Z, answers, TTLs, rejected) = line.split(passivedns_separator)
   (qtype, client_ip, query) = (qtype_name, id_orig_h, query)
   if qtype in trigger_query_types:
      if is_local_ip(client_ip):
         linecount = linecount+1
         if linecount > maxlines:
            break
         wp.put_task(query)
         counter['processed'] = counter['processed']+1
time.sleep(30)

wp.stop()


