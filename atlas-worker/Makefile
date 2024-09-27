SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
SGX_SHARED ?= 0
PRINT_DEBUG ?= 0

LOG_LEVEL?=-DDEBUG_LOG=1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += 
else
        SGX_COMMON_FLAGS += 
endif



SGX_COMMON_FLAGS += $(LOG_LEVEL) -Winit-self -Wreturn-type -Wno-pointer-arith \
                    -Waddress -Wsequence-point -Wformat-security -Wformat\
                    -Wmissing-include-dirs -Wundef  -Wno-parentheses\
                    -Wcast-align -Wconversion 
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wunsuffixed-float-constants -g  -Wall
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11 -Wno-write-strings -Wall

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := App/App.cpp App/ocalls.cpp App/nw.cpp App/funcs.cpp
App_Include_Paths := -IApp -I$(SGX_SDK)/include -Iutils

App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)  


# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags +=  -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags)
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -ldl -lm

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif



App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o) 

App_Name := app
#QJS_FLAGS = -Ofast -DCONFIG_VERSION=\"2020-09-06\"  -Wno-conversion -Wno-unused-result 
QJS_FLAGS = -DCONFIG_BIGNUM=1 -DCONFIG_VERSION=\"2020-09-06\"  -Wno-conversion -Wno-unused-result 
ifeq ($(PRINT_DEBUG), 1)
	QJS_FLAGS+=-DDEBUG -g
	App_C_Flags += 			-DDEBUG -g 
	App_Cpp_Flags += 		-DDEBUG -g
	Enclave_C_Flags += 		-DDEBUG -g
	SGX_COMMON_CXX_FLAGS += 	-DDEBUG -g
endif

######## Enclave Settings ########

Enclave_Version_Script := Enclave/Enclave_debug.lds
ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
	# Choose to use 'Enclave.lds' for HW release mode
	Enclave_Version_Script = Enclave/Enclave.lds 
endif
endif
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto


#############################################################3
# SGX-OpenSSL
OpenSSL_PATH=SGX-OpenSSL
OpenSSL_INCLUDES=-I$(OpenSSL_PATH)/OpenSSL_SGX/include
OpenSSL_Wrappers=-I$(OpenSSL_PATH)/Wrappers/Enclave
OpenSSL_Lib_ssl=$(OpenSSL_PATH)/OpenSSL_SGX/libssl.a
OpenSSL_Lib_crypto=$(OpenSSL_PATH)/OpenSSL_SGX/libcrypto.a

# Two individual files that are required
OpenSSL_ocall_wrappers_o=$(OpenSSL_PATH)/Wrappers/Enclave/Ocall_wrappers.o
OpenSSL_ocall_implement_o=$(OpenSSL_PATH)/Wrappers/App/Ocall_implements.o
#############################################################

Enclave_Cpp_Files := $(wildcard Enclave/*.cpp)  $(wildcard Enclave/dh/*.cpp) simple/ProcessClient.cpp
Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/tlibc $(OpenSSL_INCLUDES) -Iutils

Enclave_C_Flags := -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)  
Enclave_Cpp_Flags := $(Enclave_C_Flags) $(OpenSSL_INCLUDES) $(OpenSSL_Wrappers) -lm -Wno-sign-compare -g

#App_C_Flags +=			-Ofast 			
App_Cpp_Flags += 		$(QJS_FLAGS)
Enclave_C_Flags += 		$(QJS_FLAGS)
SGX_COMMON_CXXFLAGS += 	$(QJS_FLAGS)
App_Link_Flags +=		$(QJS_FLAGS)
Enclave_Cpp_Flags +=	$(QJS_FLAGS)
Enclave_Link_Flags +=	$(QJS_FLAGS) -Wno-incompatible-pointer-types
App_C_Flags += 
App_Cpp_Flags += -fpermissive

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	$(OpenSSL_Lib_ssl) $(OpenSSL_Lib_crypto) \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx  -lsgx_tcrypto -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--allow-multiple-definition \
	-Wl,--version-script=$(Enclave_Version_Script)

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else

ifeq ($(PRINT_DEBUG), 1)
	Build_Mode = SIM_DEBUG
	App_Link_Flags += 
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all run target
all: .config_$(Build_Mode)_$(SGX_ARCH)

	@$(MAKE) target


#############################################################3
# SGX-OpenSSL
$(OpenSSL_PATH)/OpenSSL_SGX/Makefile: $(OpenSSL_PATH)/OpenSSL_SGX/sgx_openssl_setup.sh
	cd $(OpenSSL_PATH)/OpenSSL_SGX && ./sgx_openssl_setup.sh
        # ssl_enclave_types.h defines some types in our edl
	cp patches/ssl_enclave_types.h $(OpenSSL_PATH)/Wrappers/Enclave/ssl_enclave_types.h

$(OpenSSL_Lib_crypto) : $(OpenSSL_PATH)/OpenSSL_SGX/Makefile
	cd $(OpenSSL_PATH)/OpenSSL_SGX && make 

$(OpenSSL_Lib_ssl) : $(OpenSSL_Lib_crypto)
	cd $(OpenSSL_PATH)/OpenSSL_SGX && make 


$(OpenSSL_ocall_wrappers_o) : $(OpenSSL_ocall_wrappers_o:o=cpp) Enclave/Enclave_t.h
	$(CXX) -m64  -O0 -g -fPIC -std=c++11  -IInclude  -DCONFIG_VERSION=\"2020-09-06\"  -IApp -fvisibility=hidden  -fstack-protector -IEnclave -I/home/elahtinen/install/sgxsdk/include  -I/home/elahtinen/install/sgxsdk/include/tlibc    -lm  -DCONFIG_VERSION=\"2020-09-06\" $(App_Cpp_Flags) -I/home/elahtinen/install/sgxsdk/include/tlibc -IEnclave -std=c++11 -c $< -o $@
	@echo "CXX  <=  $<"

$(OpenSSL_ocall_implement_o) :$(OpenSSL_ocall_implement_o:o=cpp) Enclave/Enclave_t.h
	$(CXX)  $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"
#############################################################3




ifeq ($(Build_Mode), HW_RELEASE)
target: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
target: $(App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)

	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## App Objects ########

App/Enclave_u.h:  $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"
App/Enclave_u.c: App/Enclave_u.h

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp App/Enclave_u.h App/wqueue.h
	$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/Enclave_u.o $(App_Cpp_Objects) $(OpenSSL_ocall_implement_o) 
	$(CXX) $^ -o $@ -L/home/elahtinen/install/sgxsdk/lib64 $(App_Link_Flags)  -L/usr/local/ssl -lssl -lcrypto -ldl -lsgx_urts -lpthread   -lsgx_uae_service 
	@echo "LINK =>  $@"


######## Enclave Objects ########

Enclave/Enclave_t.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.c: Enclave/Enclave_t.h

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp Enclave/isolated/*.c
	$(CXX)  $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -g -c $< -o $@
	@echo "CXX  <=  $<"

simple/process-client.o: simple/process-client.cpp
	$(CXX)  $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -g -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Cpp_Objects): Enclave/Enclave_t.h utils/log/sgx_log.h 

#Enclave/isolated/quickjs.o:
Enclave/isolated/*.o: Enclave/isolated/*.c
	$(CC) $(Enclave_Cpp_Flags) -g -c -o Enclave/isolated/quickjs.o -c Enclave/isolated/quickjs.c  -D_GNU_SOURCE --std=c99 -lpthread $(QJS_FLAGS) -Wno-implicit-function-declaration
	$(CC) $(Enclave_Cpp_Flags) -g -o Enclave/isolated/qjs.o  -c Enclave/isolated/qjs.c  -D_GNU_SOURCE --std=c99 -lpthread $(QJS_FLAGS) 	
	$(CC) $(Enclave_Cpp_Flags) -g -o Enclave/isolated/quickjs-libc.o -c Enclave/isolated/quickjs-libc.c  -D_GNU_SOURCE --std=c99 -lpthread $(QJS_FLAGS) -Wno-incompatible-pointer-types -Wno-implicit-function-declaration
	$(CC) $(Enclave_Cpp_Flags) -g -o Enclave/isolated/libunicode.o -c Enclave/isolated/libunicode.c  -D_GNU_SOURCE --std=c99 -lpthread $(QJS_FLAGS)
	$(CC) $(Enclave_Cpp_Flags) -g -o Enclave/isolated/cutils.o -c Enclave/isolated/cutils.c  -D_GNU_SOURCE --std=c99 -lpthread $(QJS_FLAGS)
	$(CC) $(Enclave_Cpp_Flags) -g -o Enclave/isolated/libregexp.o -c Enclave/isolated/libregexp.c  -D_GNU_SOURCE --std=c99 -lpthread $(QJS_FLAGS)
	$(CC) $(Enclave_Cpp_Flags) -g -o Enclave/isolated/repl.o -c Enclave/isolated/repl.c  -D_GNU_SOURCE --std=c99 -lpthread $(QJS_FLAGS)
	$(CC) $(Enclave_Cpp_Flags) -g -o Enclave/isolated/libbf.o -c Enclave/isolated/libbf.c  -D_GNU_SOURCE --std=c99 -lpthread $(QJS_FLAGS)


$(Enclave_Name): Enclave/isolated/*.o Enclave/Enclave_t.o $(Enclave_Cpp_Objects) $(OpenSSL_Lib_ssl) $(OpenSSL_Lib_crypto) $(OpenSSL_ocall_wrappers_o)
	$(CXX) -Wno-sign-compare -fpermissive Enclave/isolated/*.o Enclave/dh/*.o $^  -o $@ $(Enclave_Link_Flags)  -fpermissive  
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -ignore-init-sec-error -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"


.PHONY: clean

clean:
	rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*  tags Enclave/dh/*.o $(OpenSSL_ocall_wrappers_o) $(OpenSSL_ocall_implement_o)
	cd $(OpenSSL_PATH)/OpenSSL_SGX && make clean
	 @rm -f output *.json data*
	 @rm -f Enclave/isolated/*.o
