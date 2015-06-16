#Versione OpenState che sfrutta la tecnica del Fast Failover al posto dei Global States
from webob import Response
from ryu.app import wsgi as app_wsgi
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
import fault_tolerance_ff_demo_probing as fault_tolerance
import os

class NetworkController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(NetworkController, self).__init__(req, link, data, **config)
        self.fault_tolerance = data['fault_tolerance']
        self.f_t_parser = data['f_t_parser']

    def body_top(self):
        body='<html><head><script src="/js/jquery.min.js"></script><script>$(document).ready(function(){$("#openxterm").click(function(){'
        body+='$.post("/osfaulttolerance/maketerm/"+$("#hostname option:selected").text());});'
        body+='$("#pingall").click(function(){$.post("/osfaulttolerance/pingall");});$("#killping").click(function(){'
        body+='$.post("/osfaulttolerance/killping");});});</script>'
        body+='</head><body>'
        body+='<select id="hostname">'
        for i in range(len(self.f_t_parser.net.hosts)):
            host_name = str(self.f_t_parser.net.hosts[i])
            body+='<option value="'+host_name+'">'+host_name+'</option>'
        body+='</select><button id="openxterm">Open xterm</button> | <button id="pingall">Ping All</button><button id="killping">Kill Ping</button>'
        body+='<br><hr>'
        return body

    def index(self,req,**_kwargs):
        body=self.body_top()
        body+='<div style="text-align:center"><title>Failure Recovery App</title><h1>Failure Recovery</h1>'
        body+='<img src="../figs/network.png" alt="network">'
        body+='<br><select onchange="this.options[this.selectedIndex].value && (window.location = this.options[this.selectedIndex].value);">'
        body+='<option value="">Select a Request</option>'
        for req in sorted(self.f_t_parser.requests.keys()):
            body+='<option value="../osfaulttolerance/req/'+str(req[0])+'_'+str(req[1])+'">('+str(req[0])+','+str(req[1])+')</option>'
        body+='</select>'
        return Response(status=200,content_type='text/html',body=body)

    def image(self,req,img,**_kwargs):
        f = open('figs/'+img,'r')
        body=f.read()
        return Response(status=200,content_type='image/png',body=body)

    def js(self,req,js_file,**_kwargs):
        f = open('js/'+js_file,'r')
        body=f.read()
        return Response(status=200,content_type='application/javascript',body=body)    

    def maketerm(self,req,hostname,**_kwargs):
        print "here, make term"
        self.f_t_parser.openXterm(hostname)

    def pingall(self,req,**_kwargs):
        self.f_t_parser.pingAll()

    def killping(self,req,**_kwargs):
        os.system("kill -9 `pidof ping`")

    def request(self, req, req1, req2, **_kwargs):
        body=self.body_top()

        if not (int(req1),int(req2)) in self.f_t_parser.requests.keys() and not (int(req2),int(req1)) in self.f_t_parser.requests.keys():
           body+='<div style="text-align:center"><title>Failure Recovery App</title><h1>Failure Recovery</h1>'
           body+='<font color="red"><h1>Request ('+req1+','+req2+') does not exist</h1></font></div>'
           return Response(status=400,content_type='text/html',body=body)

        if not os.path.isfile("figs/r-"+str(req1)+"-"+str(req2)+".png"):
           self.f_t_parser.draw_requests((int(req1),int(req2)))

        body+='<div style="text-align:center"><title>Failure Recovery App</title><h1>Failure Recovery</h1>'
        body+='<h1>Request ('+req1+','+req2+')</h1>'
        body+='<img src="/figs/r-'+str(req1)+'-'+str(req2)+'.png" alt="network">'
        request=(int(req1),int(req2))
        for link_fault in self.f_t_parser.requests[request]['faults'].keys():
           body+='<h3><a href="../req/'+str(req1)+'_'+str(req2)+'/down/'+str(link_fault[0])+'_'+str(link_fault[1])+'">SetLinkDown('+str(link_fault[0])+','+str(link_fault[1])+')</a></h3>'
        body+='<h3><a href="/osfaulttolerance">Return to the Home Page</a></h3>'
        body += '</div>'
        return Response(status=200,content_type='text/html',body=body)

    def setlinkup(self, req, req1, req2, node1, node2, **_kwargs):
        body=self.body_top()

        if not (int(req1),int(req2)) in self.f_t_parser.requests.keys() and not (int(req2),int(req1)) in self.f_t_parser.requests.keys():
           body+='<div style="text-align:center"><title>Failure Recovery App</title><h1>Failure Recovery</h1>'
           body+='<font color="red"><h1>Request ('+req1+','+req2+') does not exist</h1></font></div>'
           return Response(status=400,content_type='text/html',body=body)
        
        if not (int(node1),int(node2)) in self.f_t_parser.G.edges() and not (int(node2),int(node1)) in self.f_t_parser.G.edges():
           body+='<div style="text-align:center"><title>Failure Recovery App</title><h1>Failure Recovery</h1>'
           body+='<font color="red"><h1>Set Link Up Function - Link ('+node1+','+node2+') does not exist</h1></font></div>'
           return Response(status=400,content_type='text/html',body=body)
        
        self.fault_tolerance.set_link_up(int(node1),int(node2))
        if not os.path.isfile("figs/r-"+str(req1)+"-"+str(req2)+".png"):
           self.f_t_parser.draw_requests((int(req1),int(req2)))
        body+='<div style="text-align:center"><title>Failure Recovery App</title><h1>Failure Recovery</h1>'
        body+='<h1>Set link ('+node1+','+node2+') Up</h1>'
        body+='<img src="/figs/r-'+str(req1)+'-'+str(req2)+'.png" alt="network">'
        request=(int(req1),int(req2))
        for link_fault in self.f_t_parser.requests[request]['faults'].keys():
           body+='<h3><a href="../down/'+str(link_fault[0])+'_'+str(link_fault[1])+'">SetLinkDown('+str(link_fault[0])+','+str(link_fault[1])+')</a></h3>'
        body+='<h3><a href="/osfaulttolerance">Return to the Home Page</a></h3>'
        body += '</div>'
        return Response(status=200,content_type='text/html',body=body)
        
    def setlinkdown(self, req, req1, req2, node1, node2, **_kwargs):
        body=self.body_top()

        if not (int(req1),int(req2)) in self.f_t_parser.requests.keys() and not (int(req2),int(req1)) in self.f_t_parser.requests.keys():
           body+='<div style="text-align:center"><title>Failure Recovery App</title><h1>Failure Recovery</h1>'
           body+='<font color="red"><h1>Request ('+req1+','+req2+') does not exist</h1></font></div>'
           return Response(status=400,content_type='text/html',body=body)
        
        if not (int(node1),int(node2)) in self.f_t_parser.G.edges() and not (int(node2),int(node1)) in self.f_t_parser.G.edges():
           body+='<div style="text-align:center"><title>Failure Recovery App</title><h1>Failure Recovery</h1>'
           body+='<font color="red"><h1>Set Link Down Function - Link ('+node1+','+node2+') does not exist</h1></font></div>'
           return Response(status=400,content_type='text/html',body=body)
        
        self.fault_tolerance.set_link_down(int(node1),int(node2))
        if not os.path.isfile("figs/r-"+str(req1)+"-"+str(req2)+".png"):
           self.f_t_parser.draw_requests((int(req1),int(req2)))
        body+='<div style="text-align:center"><title>Failure Recovery App</title><h1>Failure Recovery</h1>'
        body+='<h1>Set link ('+node1+','+node2+') Down</h1>'
        body+='<img src="/figs/r-'+str(req1)+'-'+str(req2)+'-f-'+str(node1)+'-'+str(node2)+'.png" alt="network">'
        body+='<h3><a href="../up/'+str(node1)+'_'+str(node2)+'">SetLinkUp('+str(node1)+','+str(node2)+')</a></h3>'
        body+='</div>'
        return Response(status=200,content_type='text/html',body=body)

class OSFaultToleranceRestAPI(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'fault_tolerance' : fault_tolerance.OSFaultTolerance
    }
    
    def __init__(self, *args, **kwargs):
        super(OSFaultToleranceRestAPI, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        fault_tolerance = kwargs['fault_tolerance']
        mapper = wsgi.mapper
        wsgi.register(NetworkController,{'fault_tolerance' : fault_tolerance, 'f_t_parser': fault_tolerance.f_t_parser})
        route_name = 'osfaulttolerance'


        uri = '/osfaulttolerance'
        s = mapper.submapper(controller=NetworkController)
        s.connect(route_name, uri, action='index',
                  conditions=dict(method=['GET']))

        uri = '/osfaulttolerance/maketerm'
        uri+='/{hostname}'
        s = mapper.submapper(controller=NetworkController)
        s.connect(route_name, uri, action='maketerm',
                  conditions=dict(method=['POST']))

        uri = '/osfaulttolerance/pingall'
        s = mapper.submapper(controller=NetworkController)
        s.connect(route_name, uri, action='pingall',
                  conditions=dict(method=['POST']))

        uri = '/osfaulttolerance/killping'
        s = mapper.submapper(controller=NetworkController)
        s.connect(route_name, uri, action='killping',
                  conditions=dict(method=['POST']))

        uri = '/js'
        uri+='/{js_file}'
        s = mapper.submapper(controller=NetworkController)
        s.connect(route_name, uri, action='js',
                  conditions=dict(method=['GET']))

        uri = '/figs'
        uri += '/{img}'
        s = mapper.submapper(controller=NetworkController)
        s.connect(route_name, uri, action='image',
                  conditions=dict(method=['GET']))

        uri = '/osfaulttolerance/req'
        uri += '/{req1}_{req2}'
        requirements = {'req1': app_wsgi.DIGIT_PATTERN,
                        'req2': app_wsgi.DIGIT_PATTERN}
        
        s = mapper.submapper(controller=NetworkController,
                             requirements=requirements)
        s.connect(route_name, uri, action='request',
                  conditions=dict(method=['GET']))

        uri = '/osfaulttolerance/req'
        uri += '/{req1}_{req2}'
        uri += '/up'
        uri += '/{node1}_{node2}'
        requirements = {'req1': app_wsgi.DIGIT_PATTERN,
                        'req2': app_wsgi.DIGIT_PATTERN,
                        'node1': app_wsgi.DIGIT_PATTERN,
                        'node2': app_wsgi.DIGIT_PATTERN}       
        s = mapper.submapper(controller=NetworkController,
                             requirements=requirements)
        s.connect(route_name, uri, action='setlinkup',
                  conditions=dict(method=['GET']))

        uri = '/osfaulttolerance/req'
        uri += '/{req1}_{req2}'
        uri += '/down'
        uri += '/{node1}_{node2}'
        requirements = {'req1': app_wsgi.DIGIT_PATTERN,
                        'req2': app_wsgi.DIGIT_PATTERN,
                        'node1': app_wsgi.DIGIT_PATTERN,
                        'node2': app_wsgi.DIGIT_PATTERN}
        s = mapper.submapper(controller=NetworkController,
                             requirements=requirements)
        s.connect(route_name, uri, action='setlinkdown',
                  conditions=dict(method=['GET']))
