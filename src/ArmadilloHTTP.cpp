#include<H4Tools.h>
#include<ArmadilloHTTP.h>

#if H4AT_TLS_SESSION
#include "lwip/apps/altcp_tls_mbedtls_opts.h"
#endif

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
    ARMA_PRINT1("_prepare h4at %p _inflight %d\n", _h4atClient, _inflight);
    if (_h4atClient == nullptr)
    {
        _h4atClient = new H4AsyncClient();
        _h4atClient->onDisconnect([this](){ ARMA_PRINT1("onDisconnect\n"); _destroyClient(); });
        _h4atClient->onRX([this](const uint8_t* d,size_t s){ _rx(d,s); });
        _h4atClient->onError([this](int e, int i){ _error(e,i); if (e) _destroyClient(); return true; });
        _h4atClient->onConnect([phase, this](){_sendRequest(phase); });
        _h4atClient->onConnectFail([this](){ ARMA_PRINT1("onConnectFail\n"); _destroyClient(); });
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
#if H4AT_TLS_SESSION
         // [ ] Parse base URL / Host and use it in comparison.
        static void* _tlsSession;
        static uint32_t _lastSessionMs;
        static std::string lastURL;
        _h4atClient->enableTLSSession();
        _h4atClient->onSession(
            [=](void *tls_session)
            {
                ARMA_PRINT1("onSession(%p)\n", tls_session);
                _tlsSession = const_cast<void *>(tls_session);
                _lastSessionMs = millis();
                ARMA_PRINT3("_tlsSession %p _lastSessionMs %u\n", _tlsSession, _lastSessionMs);
            });


        // ARMA_PRINT4("url %s lastURL %s millis() %u _lastSessionMs %u diff=%u\n url==lastURL=%d\tdiff<timeout=%d\n", url.c_str(), lastURL.c_str(), millis(), _lastSessionMs, millis() - _lastSessionMs, 
        // url == lastURL, (millis() - _lastSessionMs < ALTCP_MBEDTLS_SESSION_CACHE_TIMEOUT_SECONDS * 1000));
        if (_tlsSession && url == lastURL && (millis() - _lastSessionMs < ALTCP_MBEDTLS_SESSION_CACHE_TIMEOUT_SECONDS * 1000)) {
            _h4atClient->setTLSSession(_tlsSession);
        }
        else {
            if (_tlsSession) {
                _h4atClient->freeTLSSession(_tlsSession);
                _tlsSession = nullptr;
            }
        }
        lastURL = url;
#endif

        auto cas = _caCert.size();
        auto pks = _privkey.size();
        auto pkps = _privkeyPass.size();
        auto cs = _clientCert.size();
        Serial.printf("cas %d\n", cas);
        if (cas) {
#if H4AT_TLS
            _h4atClient->secureTLS(_caCert.data(), _caCert.size(), 
                                        pks ? _privkey.data() : nullptr, pks, 
                                        pkps ? _privkeyPass.data() : nullptr, pkps, 
                                        cs ? _clientCert.data() : nullptr, cs);
#else 
            ARMA_PRINT1("Make sure TLS is enabled in H4AsyncTCP\n");
#endif 
        }

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

        uint8_t* pMsg=(uint8_t*) (d+szHdrs+4); //pMsg = i+4 ..?
        const size_t   msgLen=s-(szHdrs+4);
        ARMA_PRINT4("Looks like hdrs n=%d msgLen=%d @ 0x%08x\n",szHdrs,msgLen,pMsg);

        std::string rawheaders;
        rawheaders.assign((const char*) d,szHdrs);

        std::vector<std::string> hdrs=split(rawheaders,"\r\n");
        std::vector<std::string> status=split(hdrs[0]," ");
        if (status.size() < 3 || !stringIsNumeric(status[1])) { // Checks against 3 parts of the header to filter out the malformed HTTP responses, as well as encrypted ones...
            ARMA_PRINT1("ERROR: NO STATUS CODE\n");
            _error(ARMA_ERROR_HTTP);
            return;
        }
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
    _h4atClient=nullptr;
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

bool ArmadilloHTTP::secureTLS(const u8_t *ca, size_t ca_len, const u8_t *privkey, size_t privkey_len, const u8_t *privkey_pass, size_t privkey_pass_len, const u8_t *cert, size_t cert_len)
{
#if H4AT_TLS
    // Copy to internals 
    ARMA_PRINT1("secureTLS(%p,%d,%p,%d,%p,%d,%p,%d)\n",ca,ca_len,privkey,privkey_len,privkey_pass,privkey_pass_len,cert,cert_len);

    if (ca) {
        _caCert.reserve(ca_len);
        std::copy_n(ca, ca_len, std::back_inserter(_caCert));
    }
    if (privkey) {
        _privkey.reserve(privkey_len);
        std::copy_n(privkey, privkey_len, std::back_inserter(_privkey));
    }
    if (privkey_pass) {
        _privkeyPass.reserve(privkey_pass_len);
        std::copy_n(privkey_pass, privkey_pass_len, std::back_inserter(_privkeyPass));
    }
    if (cert) {
        _clientCert.reserve(cert_len);
        std::copy_n(cert, cert_len, std::back_inserter(_clientCert));
    }
    return true;
#else
    ARMA_PRINT1("TLS is not activated within H4AsyncTCP\n");
	return false;
#endif
}