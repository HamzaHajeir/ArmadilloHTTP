#include <Arduino.h>
#include <WiFi.h>
#include <ArmadilloHTTP.h>
#include <H4.h>

#define H4_QUEUE_SIZE 25
H4 h4(115200,H4_QUEUE_SIZE);
std::string ca_cert =  // For GTS ROOT R4, CA of ipify.org
	R"(-----BEGIN CERTIFICATE-----
MIICCTCCAY6gAwIBAgINAgPlwGjvYxqccpBQUjAKBggqhkjOPQQDAzBHMQswCQYD
VQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIG
A1UEAxMLR1RTIFJvb3QgUjQwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAw
WjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2Vz
IExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjQwdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AATzdHOnaItgrkO4NcWBMHtLSZ37wWHO5t5GvWvVYRg1rkDdc/eJkTBa6zzuhXyi
QHY7qca4R9gq55KRanPpsXI5nymfopjTX15YhmUPoYRlBtHci8nHc8iMai/lxKvR
HYqjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBSATNbrdP9JNqPV2Py1PsVq8JQdjDAKBggqhkjOPQQDAwNpADBmAjEA6ED/g94D
9J+uHXqnLrmvT/aDHQ4thQEd0dlq7A/Cr8deVl5c1RxYIigL9zC2L7F8AjEA8GE8
p/SgguMh1YQdc4acLa/KNJvxn7kjNuK8YAOdgLOaVsjh4rsUecrNIdSUtUlD
-----END CERTIFICATE-----
)";

struct HTTPClient : ArmadilloHTTP {
	static bool wifiConnected;
	void onError(int e, int i) { // Could react over these errors.
		if (e<0) {
			Serial.printf("LwIP ERROR e=%d i=%d\n", e,i);
		}
		else if (e<H4AT_MAX_ERROR) {
			Serial.printf("TCP ERROR e=%d i=%d\n", e,i);
		}
		else {
			Serial.printf("HTTP ERROR e=%d i=%d\n", e,i);
		}

		// Might use this callback to retry the HTTP request, but beware that after onResponse is called, the TCP connection gets closed and will emit ERR_CLSD (-15) here. Watch the events with care.
	}
	void onResponse(ArmadilloHTTPresponse r) {
		Serial.printf("onResponse CB code %d\n", r.httpResponseCode);
		std::string body(reinterpret_cast<const char*>(r.data), r.length);
		Serial.printf("Response body:\n%s\n", body.c_str());

		if (auto s=r.responseHeaders.size()) {
			Serial.printf("Headers (%d):\n", s);
		}
		for (auto& h : r.responseHeaders) {
			Serial.printf("\t%s:%s\n", h.first.c_str(), h.second.c_str());
		}
		
		/*  Might chain-up requests here: */
		// aClient.GET("theURL",[this](ArmadilloHTTPresponse r){ onResponse(r); },nullptr,ARMA_PHASE_EXECUTE);
		// Or by initiating a timer:
		// h4.once(5000, 
		// 		[this]{
		//			aClient.GET(...);
		//		}
		//)
	}

	void DELETE(const std::string& url,ARMA_FN_HTTP rx=nullptr,uint32_t phase=ARMA_PHASE_EXECUTE){ if(wifiConnected) ArmadilloHTTP::DELETE(url,rx ? rx : [this](ArmadilloHTTPresponse r){ onResponse(r); },nullptr,phase); }
	void GET(const std::string& url,ARMA_FN_HTTP rx=nullptr,uint32_t phase=ARMA_PHASE_EXECUTE){ if(wifiConnected) ArmadilloHTTP::GET(url,rx ? rx : [this](ArmadilloHTTPresponse r){ onResponse(r); },nullptr,phase); }
	void PATCH(const std::string& url,const H4AT_NVP_MAP& fields,ARMA_FN_HTTP rx=nullptr,uint32_t phase=ARMA_PHASE_EXECUTE){ if(wifiConnected) ArmadilloHTTP::PATCH(url,fields,rx ? rx : [this](ArmadilloHTTPresponse r){ onResponse(r); },nullptr,phase); }
	void POST(const std::string& url,const H4AT_NVP_MAP& fields,ARMA_FN_HTTP rx=nullptr,uint32_t phase=ARMA_PHASE_EXECUTE){ if(wifiConnected) ArmadilloHTTP::POST(url,fields,rx ? rx : [this](ArmadilloHTTPresponse r){ onResponse(r); },nullptr,phase); }
	void PUT(const std::string& url,const H4AT_NVP_MAP& fields,ARMA_FN_HTTP rx=nullptr,uint32_t phase=ARMA_PHASE_EXECUTE){ if(wifiConnected) ArmadilloHTTP::PUT(url,fields,rx ? rx : [this](ArmadilloHTTPresponse r){ onResponse(r); },nullptr,phase); }

	HTTPClient(){ ArmadilloHTTP::onHTTPerror([this](int e, int i){ onError(e, i); }); }
};

void onResponse(ArmadilloHTTPresponse r) {
	Serial.printf("Custom onResponse CB code %d\n", r.httpResponseCode);
	std::string body(reinterpret_cast<const char*>(r.data), r.length);
	Serial.printf("Response body:\n%s\n", body.c_str());

	if (auto s=r.responseHeaders.size()) {
		Serial.printf("Headers (%d):\n", s);
	}
	for (auto& h : r.responseHeaders) {
		Serial.printf("\t%s:%s\n", h.first.c_str(), h.second.c_str());
	}
}
bool HTTPClient::wifiConnected = false;
std::vector<HTTPClient*> httpclients;
void h4setup() {

	WiFi.begin("XXXXXXXX","XXXXXXXX"); 	// [ ] Replace with Wifi credentials.

	WiFi.waitForConnectResult();
	if(WiFi.status()!=WL_CONNECTED){
		Serial.printf("Failed to connect to WiFi!\n");
		ESP.restart();
	}
	HTTPClient::wifiConnected = true; // Might listen for WiFi Events, when WiFi gets disconnected check it to false, and vise-versa.

	Serial.printf("WIFI CONNECTED IP=%s\n",WiFi.localIP().toString().c_str());
	h4.every(5000, []{ Serial.printf("T=%u H=%u M=%u\n", millis(), _HAL_freeHeap(), _HAL_maxHeapBlock()); });

	auto testRootCA = reinterpret_cast<const uint8_t *>(const_cast<char *>(ca_cert.c_str()));
	Serial.printf("HTTP CERT Validation: %s\n", H4AsyncClient::isCertValid(testRootCA, ca_cert.length() + 1) ? "SUCCEEDED" : "FAILED");

	for (int i=0;i< CONFIG_LWIP_MAX_RAW_PCBS;i++) {
		Serial.printf("Setting HTTPClient No.%d heap %u maxbloc %u\n", i, _HAL_freeHeap(), _HAL_maxHeapBlock());
		httpclients.push_back(new HTTPClient{});
		auto client = httpclients.back();

		_HAL_feedWatchdog();
		
		auto testRootCA = reinterpret_cast<const uint8_t*>(const_cast<char*>(ca_cert.c_str()));
		client->secureTLS(testRootCA, ca_cert.length() + 1);

		client->GET("https://api.ipify.org/?format=json");
		// OR specify the custom callback function:
		// c.GET("https://api.ipify.org/?format=json", onResponse);
	}

	// One might re-run the whole requests again by iterating over httpclients pointers.
	h4.everyRandom(60000, 100000, 
		[]{ /* for(auto client : httpclients) { ... } */}
		);
	// Or by any other H4 timing strategy:
	// h4.once(60000, []{ ... });
	// h4.onceRandom(60000, 100000, []{ ... });
	// h4.every(60000, []{ ... });
	// h4.nTimes(5, 60000, []{ ... });
	// ...etc
}
