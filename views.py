from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from .models import Rule
import requests
import json
from .anomaly_detector import RULE, AnomalyDetector
# Create your views here.
def save(request):
    types = request.GET.get('type', '')
    nw_src = request.GET.get('nw_src','')
    nw_dst = request.GET.get('nw_dst','')
    priority = request.GET.get('priority','')
    action = request.GET.get('action','')
    if types=="GetRules":
        GetRules()
        return HttpResponseRedirect('/firewall')
    elif types=="Enable":
        url = 'http://127.0.0.1:8080/firewall/module/enable/0000000000000001'
        myResponse = requests.put(url)
        if(myResponse.ok):
            jData = json.loads(myResponse.content)
            
        return HttpResponseRedirect('/firewall')
    elif types=="PostRule":
        url = 'http://127.0.0.1:8080/firewall/rules/0000000000000001'
        datas = '{'
        if nw_src != '':
            datas = datas + '"nw_src":"' + nw_src + '",'
        if nw_dst != '':
            datas = datas + '"nw_dst":"' + nw_dst + '",'
        if priority != '':
            datas = datas + '"priority":"' + priority + '",'
        if action != '':
            datas = datas + '"actions":"' + action + '",'
        if (nw_src =='')&(nw_dst ==''):
            print 'bad'
            return HttpResponseRedirect('/firewall')
        if datas[-1] == ',':
            datas = datas[:-1] + '}'
        
        print datas

        myResponse = requests.post(url,data = datas)
        GetRules()
        return HttpResponseRedirect('/firewall')
    elif types=="AnomalyDetect":
        AnoDet()
    rules = Rule.objects.all()
    response = HttpResponse()
    context = {'rules':rules}
    return render(request, "firewall.html", context)
def AnoDet():
    old_rules_list = list()
    for obj in Rule.objects.all():
        string = 'nw_src = "' + str(obj.nw_src) + '",nw_dst = "' + str(obj.nw_dst) + '",priority = "' + str(obj.priority) + '", actions = "' + str(obj.action) + '"' 
        old_rules_list.append(RULE(string))
        print old_rules_list

def GetRules():
    url = 'http://127.0.0.1:8080/firewall/rules/0000000000000001'
    myResponse = requests.get(url)
    if(myResponse.ok):
        jData = json.loads(myResponse.content)
        jData = jData[0]
        if jData['access_control_list']==[]:
           print "no rules"
           for obj in Rule.objects.all():
               obj.delete()
        else:
            if Rule.objects.count()==0:
                for rule in jData['access_control_list'][0]['rules']:
                    _newRule = Rule()
                    if 'nw_src' in rule:
                        _newRule.nw_src = rule['nw_src']
                    else:
                        _newRule.nw_src = '*'
                    if 'nw_dst' in rule:
                        _newRule.nw_dst = rule['nw_dst']
                    else:
                        _newRule.nw_dst = '*'
                    _newRule.priority = rule['priority']
                    _newRule.rule_id = rule['rule_id']
                    _newRule.action = rule['actions']
                    _newRule.save()
            else:
                for rule in jData['access_control_list'][0]['rules']:
                    print rule
                    counter = 0
                    tag = 0
                    for obj in Rule.objects.all():
                        if 'nw_src' in rule:
                            if rule['nw_src'] == obj.nw_src:
                                counter = counter + 1
                        else:
                            if obj.nw_src=='*':
                                counter = counter + 1
                        if 'nw_dst' in rule:
                            if rule['nw_dst'] == obj.nw_dst:
                                counter = counter + 1
                        else:
                            if obj.nw_dst=='*':
                                counter = counter + 1
                        if rule['priority'] == obj.priority:
                            counter = counter + 1
                        if rule['actions'] == obj.action:
                            counter = counter + 1
                        if counter == 4:
                            tag = 1
                            if rule['rule_id'] != obj.rule_id:
                                obj.delete()
                                _newRule = Rule()
                                if 'nw_src' in rule:
                                    _newRule.nw_src = rule['nw_src']
                                else:
                                    _newRule.nw_src = '*'
                                if 'nw_dst' in rule:
                                    _newRule.nw_dst = rule['nw_dst']
                                else:
                                    _newRule.nw_dst = '*'
                                _newRule.priority = rule['priority']
                                _newRule.rule_id = rule['rule_id']
                                _newRule.action = rule['actions']
                                _newRule.save()
                        counter = 0
                    if tag == 0:
                        _newRule = Rule()
                        if 'nw_src' in rule:
                            _newRule.nw_src = rule['nw_src']
                        else:
                            _newRule.nw_src = '*'
                        if 'nw_dst' in rule:
                            _newRule.nw_dst = rule['nw_dst']
                        else:
                            _newRule.nw_dst = '*'
                        _newRule.priority = rule['priority']
                        _newRule.rule_id = rule['rule_id']
                        _newRule.action = rule['actions']
                        _newRule.save()
                    else:
                        tag = 0
                for obj in Rule.objects.all():
                    counter = 0
                    tag = 0
                    for rule in jData['access_control_list'][0]['rules']:
                        if 'nw_src' in rule:
                            if rule['nw_src'] == obj.nw_src:
                                counter = counter + 1
                        else:
                            if obj.nw_src=='*':
                                counter = counter + 1
                        if 'nw_dst' in rule:
                            if rule['nw_dst'] == obj.nw_dst:
                                counter = counter + 1
                        else:
                            if obj.nw_dst=='*':
                                counter = counter + 1
                        if rule['priority'] == obj.priority:
                            counter = counter + 1
                        if rule['actions'] == obj.action:
                            counter = counter + 1
                        if counter == 4 :
                            tag = 1
                    if tag == 0:
                        obj.delete()
                    else:
                        tag = 0
