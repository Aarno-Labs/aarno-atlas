LOG_LEVEL?=-DDEBUG_LOG=1

SGX_COMMON_FLAGS += $(LOG_LEVEL) -std=c++17 -Winit-self -Wreturn-type -Wno-pointer-arith \
                    -Waddress -Wsequence-point -Wformat-security -Wformat\
                    -Wmissing-include-dirs -Wundef  -Wno-parentheses\
                    -Wcast-align -Wconversion -fno-omit-frame-pointer
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wunsuffixed-float-constants -g  -Wall
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++17 -Wno-write-strings -Wall

######## App Settings ########


App_Include_Paths := -Iutils -I/home/elahtinen/atlas/remote-attestation/modules/protocol -I/home/elahtinen/atlas/remote-attestation/servers/common -I/home/elahtinen/atlas/remote-attestation/apps/common -I/home/elahtinen/atlas/remote-attestation/apps/rpi
App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)



REMOTE_ATTEST_LIB?=/home/elahtinen/atlas/remote-attestation/build
REMOTE_ATTEST_PROTO_LIB?=/home/elahtinen/atlas/remote-attestation/build/modules/protocol
PAHO_CPP3_LIB?=/usr/local/lib
PAHO_C_LIB?=/usr/local/lib

App_Cpp_Flags := $(App_C_Flags)
App_Link_Flags := -fno-omit-frame-pointer -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -L${REMOTE_ATTEST_LIB} -lrpi -L${REMOTE_ATTEST_PROTO_LIB} -lprotocol -L${PAHO_CPP3_LIB} -lpaho-mqttpp3 -lmbedtls -lmbedcrypto -L${MBEDTLS_LIB} -lmbedx509  -L${PAHO_C_LIB} -lpaho-mqtt3as -lstdc++fs  -lpthread  -ldl -lm 

App_Name := app
#QJS_FLAGS = -Ofast -DCONFIG_VERSION=\"2020-09-06\"  -Wno-conversion -Wno-unused-result 
QJS_FLAGS = -g -DCONFIG_VERSION=\"2020-09-06\"  -Wno-conversion -Wno-unused-result -DCONFIG_BIGNUM -DPLATFORM_RPI
ifeq ($(PRINT_DEBUG), 1)
	QJS_FLAGS+=-DDEBUG -g 
	App_C_Flags += 			-DDEBUG -g 
	App_Cpp_Flags += 		-DDEBUG -g
	Enclave_C_Flags += 		-DDEBUG -g
	SGX_COMMON_CXX_FLAGS += 	-DDEBUG -g
endif

######## Enclave Settings ########

Enclave_C_Flags := -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)  -DXD -DAARNO_SIMPLE
Enclave_Cpp_Flags := $(Enclave_C_Flags) $(OpenSSL_INCLUDES) $(OpenSSL_Wrappers) -lm -Wno-sign-compare -g -DDUMP_MODULE_RESOLVE

#App_C_Flags +=			-Ofast 			
App_Cpp_Flags += 		$(QJS_FLAGS)
Enclave_C_Flags += 		$(QJS_FLAGS)
SGX_COMMON_CXXFLAGS += 	$(QJS_FLAGS)
App_Link_Flags +=		 $(QJS_FLAGS)
Enclave_Cpp_Flags +=	$(QJS_FLAGS)
Enclave_Link_Flags +=	$(QJS_FLAGS) -Wno-incompatible-pointer-types
App_C_Flags += 
App_Cpp_Flags += -fpermissive


.PHONY: all run target
all: simple-server


QJS_C_FILES := $(wildcard Enclave/isolated/*.c)
QJS_O_FILES := $(QJS_C_FILES:.c=.o)


Enclave/isolated/%.o: Enclave/isolated/%.c
	$(CC) $(Enclave_Cpp_Flags) -g -c -o $@ -c $<  -D_GNU_SOURCE --std=c99 -lpthread $(QJS_FLAGS) -Wno-implicit-function-declaration
simple/%.o: simple/%.cpp 
	$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

simple-server: simple/simple.o $(QJS_O_FILES)
	$(CXX) $^ -o $@  -g $(App_Link_Flags) -lssl -lcrypto -ldl -lpthread 
	@echo "LINK =>  $@"

.PHONY: clean

clean:
	@rm -f simple/*.o
	@rm -f simple-server
	@rm -f Enclave/isolated/*.o
