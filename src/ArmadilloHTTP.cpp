#include<H4Tools.h>
#include<ArmadilloHTTP.h>

// ArmadilloHTTP::ArmadilloHTTP(): _Client(nullptr){ 
    
// }

void ArmadilloHTTP::_appendHeaders(std::string* p){ 
    for(auto const& r:requestHeaders) *p+=r.first+": "+r.second+"\r\n";
    *p+="\r\n";
}

bool ArmadilloHTTP::_compareHeader(const std::string& h,const std::string& v){
    if(_response.responseHeaders.count(uppercase(h)) && uppercase(_response.responseHeaders[uppercase(h)])==uppercase(v)) return true;
    return false;
}

void ArmadilloHTTP::_execute(const uint8_t* d,size_t s){
    _response.data=d;
    _response.length=s;
    _userfn(_response);
    _inflight=false;
    if(_compareHeader("Connection","close")) _destroyClient(true);
}

size_t ArmadilloHTTP::_getContentLength(){
    size_t  len=0;
    if(_response.responseHeaders.count(contentLengthTag())) len=atoi(_response.responseHeaders[contentLengthTag()].c_str());
    return len;
}

void ArmadilloHTTP::_getMethods(const std::string& hdr){
   ARMA_PRINT4("_getMethods %s (already have %d)\n",hdr.c_str(),_response.allowedMethods.size());
   if(!_response.allowedMethods.size()){
        if(_response.responseHeaders.count(hdr)){
            ARMA_PRINT4("ALLOWING: %s\n",_response.responseHeaders[hdr].c_str());
            std::vector<std::string> aloud=split(_response.responseHeaders[hdr],",");
            for(auto const& a:aloud) _response.allowedMethods.insert(trim(a));
        }
    }
}

void ArmadilloHTTP::_measure(const uint8_t* d,size_t s){
    size_t len=_getContentLength();
    if(len){
        if(len < getMaxPayloadSize()) _sendRequest(ARMA_PHASE_EXECUTE);
        else _error(ARMA_ERROR_TOO_BIG,len);
    }
}

void ArmadilloHTTP::_preflight(const uint8_t* d,size_t s){
    _getMethods("ALLOW");
    _getMethods("ACCESS-CONTROL-ALLOW-METHODS");
    if(_response.allowedMethods.count(_phaseVerb[ARMA_PHASE_EXECUTE])) _sendRequest(ARMA_PHASE_MEASURE);
    else _error(ARMA_ERROR_VERB_PROHIBITED);
}

void ArmadilloHTTP::_prepare(uint32_t phase,const std::string& verb,const std::string& url,ARMA_FN_HTTP f,const H4AT_NVP_MAP& fields){
    if (_h4atClient == nullptr)
    {
        _h4atClient = new H4AsyncClient();
        _h4atClient->onDisconnect([=](){ ARMA_PRINT1("onDisconnect\n"); _scavenge(); });
        _h4atClient->onRX([=](const uint8_t* d,size_t s){ _rx(d,s); });
        _h4atClient->onError([=](int e, int i){ _error(e,i); return true; });
        _h4atClient->onConnect([=](){_sendRequest(phase); });
        _h4atClient->onConnectFail([=](){ _destroyClient(true); });
        _h4atClient->onDelete([=](){ _h4atClient=nullptr; _inflight = false;});
    }
    if(_inflight) {
        ARMA_PRINT4("REJECTED: BUSY - %s %s\n",verb.data(),url.data());
        _error(ARMA_ERROR_BUSY);
    }
    else {
        _inflight=true;
        _phaseVerb[ARMA_PHASE_EXECUTE]=verb;
        _userfn=f;
        //
        if(fields.size()){
           if(requestHeaders.count(contentTypeTag())){
                std::string type=requestHeaders[contentTypeTag()];
                    if(type=="application/json") _bodydata=nvp2json(fields);
//                    else ARMA_PRINT1("unknown c-type %s\n",type.data());
            } 
            else {
                addRequestHeader(contentTypeTag(),"application/x-www-form-urlencoded");
                _bodydata=flattenMap(fields,"=","&",urlencode);
            }
        }
        //     
        _h4atClient->connect(url);
    }
}

void ArmadilloHTTP::_chunkItUp(uint8_t* pMsg,const uint8_t* d,size_t s){
    size_t              chunk=0;
    do {
        size_t n=0;
        for(uint8_t* i=pMsg;i<(pMsg+6);i++) if(*i=='\r' || *i=='\n') n+=*i;
        ARMA_PRINT4("stray fragment metric=%d\n",n);
        // if n != 23 , invalid chunk count
        if(n<23){
            ARMA_PRINT4("SF addchunk length %d total now %d in %d chunks\n",s,_sigmaChunx,_chunks.size());
            uint8_t* frag=2+((_chunks.back().data+_chunks.back().len)-s);
            memcpy(frag,pMsg,s);
        }
        else {
            chunk=hex2uint(pMsg);
            ARMA_PRINT4("Looks like a valid chunk of length %d\n",chunk);
            if(chunk){
                _sigmaChunx+=chunk;
                while((*pMsg++)!='\r');
                _chunks.emplace_back(++pMsg,chunk,true);
                ARMA_PRINT4("NC addchunk length %d total now %d in %d chunks\n",chunk,_sigmaChunx,_chunks.size());
                pMsg+=chunk+2;
                if(!(pMsg < d+s)) return;
            } 
            else {
                // rebuild block from frags
                ARMA_PRINT4("reassemble length %d from %d chunks\n",_sigmaChunx,_chunks.size());
                uint8_t* reassembled=mbx::getMemory(_sigmaChunx);
                if(reassembled){
                    uint8_t* r=reassembled;
                    for(auto &c:_chunks){
                        ARMA_PRINT4("UNCHUNKING\n");
                        dumphex(c.data,c.len);
                        memcpy(r,c.data,c.len);
                        c.clear();
                    }
                    _chunks.clear();
                    _chunks.shrink_to_fit();
                    _execute(reassembled,_sigmaChunx);
                    mbx::clear(reassembled);
                    _sigmaChunx=0;
                    return;
                }
                else {
                    _error(H4AT_INPUT_TOO_BIG, _sigmaChunx);
                    _destroyClient(true);
                    return;
                }
            }
        }
    } while(chunk);
}

void ArmadilloHTTP::_rx(const uint8_t* d,size_t s){
    ARMA_PRINT1("RX 0x%08x len=%d FH=%u\n",d,s,_HAL_freeHeap());
    if(_sigmaChunx) {
        uint8_t* pMsg=(uint8_t*) d;
        _chunkItUp(pMsg,d,s);
    }
    else {
        auto i=strstr((const char*) d,"\r\n\r\n");
        ptrdiff_t szHdrs=(const uint8_t*) i-d;
        if(szHdrs > s) return;

        uint8_t* pMsg=(uint8_t*) (d+szHdrs+4);
        const size_t   msgLen=s-(szHdrs+4);
        ARMA_PRINT4("Looks like hdrs n=%d msgLen=%d @ 0x%08x\n",szHdrs,msgLen,pMsg);

        std::string rawheaders;
        rawheaders.assign((const char*) d,szHdrs);

        std::vector<std::string> hdrs=split(rawheaders,"\r\n");
        std::vector<std::string> status=split(hdrs[0]," ");
        _response.httpResponseCode=atoi(status[1].c_str());
        ARMA_PRINT4("_response.httpResponseCode=%d\n",_response.httpResponseCode);
            
        for(auto const h:std::vector<std::string>(++hdrs.begin(),hdrs.end())){
            std::vector<std::string> deco2=split(h,": ");
            _response.responseHeaders[uppercase(deco2[0])]=deco2.size() > 1 ? deco2[1]:"";
        }

        rawheaders.clear();
        rawheaders.shrink_to_fit();
        hdrs.clear();
//        for(auto const h:_response.responseHeaders) ARMA_PRINT1("RH %s=%s\n",h.first.c_str(),h.second.c_str());
        if(_compareHeader("TRANSFER-ENCODING","CHUNKED")) _chunkItUp(pMsg,d,s);
        else {
            switch(_phase){
                case ARMA_PHASE_PREFLIGHT:
                    _preflight(pMsg,msgLen);
                    break;
                case ARMA_PHASE_MEASURE:
                    _measure(pMsg,msgLen);
                    break;
                case ARMA_PHASE_EXECUTE:
                    _execute(pMsg,msgLen);
                    break;
            }
        }
    }
}

void ArmadilloHTTP::_scavenge(){
    ARMA_PRINT4("_scavenge() IN FH=%u\n",_HAL_freeHeap());
    _bodydata.clear();
    requestHeaders.clear();
    _response.responseHeaders.clear();
    _response.allowedMethods.clear();
    _response.httpResponseCode=0;
    _phase=ARMA_PHASE_PREFLIGHT;
    for(auto &c:_chunks) c.clear();
    _sigmaChunx=0;
    _inflight=false;
    ARMA_PRINT4("_scavenge() UT FH=%u\n",_HAL_freeHeap());
}

void ArmadilloHTTP::_sendRequest(uint32_t phase){
   _phase=phase;
    std::string req=_phaseVerb[_phase]+" ";
    auto & _URL = _h4atClient->_URL;
    req.append(_URL.path).append(_URL.query.size() ? std::string("?")+_URL.query:"").append(" HTTP/1.1\r\nHost: ").append(_URL.host).append("\r\n");
    req.append("User-Agent: ArmadilloHTTP/").append(ARDUINO_BOARD).append("/").append(ARMADILLO_VERSION).append("\r\n");
    switch(phase){
        case ARMA_PHASE_PREFLIGHT:
            addRequestHeader("Access-Control-Request-Method",_phaseVerb[ARMA_PHASE_EXECUTE]);
            _appendHeaders(&req);
            break;
        case ARMA_PHASE_EXECUTE:
            addRequestHeader(contentLengthTag(),stringFromInt(_bodydata.size()));
            addRequestHeader("Connection","close");
            _appendHeaders(&req);
            req+=_bodydata;
            break;
        default:
            _appendHeaders(&req);
            break;
    }
    if (_h4atClient)
        _h4atClient->TX((const uint8_t*) req.c_str(),req.size()); // hang on to the string :)
}