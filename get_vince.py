#!/usr/bin/python3
import requests,json,sys,getpass

def error_exit(reason):
    print(json.dumps({"error":reason}))
    sys.exit(1)

def fatal_exit(ex_cls, ex, tb):
    #Send all locals into a error array back to exit
    #errors = map(str,locals())
    errors = {}
    for t,l in locals:
        errors[t] = str(l)
    print(json.dumps({"errors":"Program error","info":errors}))
    sys.exit(2)
    

def safe_print(st):
    print(json.dumps(st))


def create_response(key,turl):
    r =  requests.get(turl, headers=auth_header, stream=True)
    result["debug_"+key] = {"ok":str(r.ok),"headers":dict(r.headers),
                            "status_code": str(r.status_code)}
    result[key] = json.loads(str(r.text))
    
    
api_base = "https://kb.cert.org/vince/comm/api"
url_map = { "get_cases": api_base+'/cases/',
            "get_case": api_base+"/case/$case/",
            "get_posts": api_base+"/case/posts/$case/",
            "get_original_report": api_base+"/case/report/$case/",
            "get_vendors": api_base+"/case/vendors/$case/",
            "get_vuls": api_base+"/case/vuls/$case/"}


if __name__ == '__main__':
    token = getpass.getpass("Enter API Token:")
    auth_header = {"Authorization": "Token {}".format(token)}
    result = {}
    sys.excepthook = fatal_exit    

    if len(sys.argv) > 1:
        result["query_info"] = "Getting specified case data"
        result["case"] = sys.argv[1]
        del url_map['get_cases']
        for k,url in url_map.items():
            url = url.replace("$case",result["case"])
            create_response(k,url)
    else:
        result["query_info"] ="Getting all cases "
        create_response("get_cases",url_map["get_cases"])
    safe_print(result)
    sys.exit(0)


